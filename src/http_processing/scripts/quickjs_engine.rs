//! Synchronous, invocation-local QuickJS-NG execution for HTTP rewrites.
use libquickjs_ng_sys as qjs;
use std::{
    cell::Cell,
    ffi::{CStr, CString, c_void},
    io,
    marker::PhantomData,
    mem::{ManuallyDrop, size_of},
    ptr::{self, NonNull},
    slice,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use super::{
    super::body_budget::{BridgePlan, BudgetedBytes, MAX_BODY, Reservation},
    CompiledSource,
};

const TICK_LIMIT: usize = 100_000;
const HEAP_LIMIT: usize = 16 * 1024 * 1024;
const STACK_LIMIT: usize = 256 * 1024;
const METADATA_LIMIT: usize = 1024 * 1024;

struct Execution<'a> {
    deadline: Instant,
    cancellation: &'a CancellationToken,
    ticks: Cell<usize>,
}

impl Execution<'_> {
    fn stopped(&self) -> Option<io::ErrorKind> {
        if self.cancellation.is_cancelled() {
            Some(io::ErrorKind::Interrupted)
        } else if Instant::now() >= self.deadline || self.ticks.get() > TICK_LIMIT {
            Some(io::ErrorKind::TimedOut)
        } else {
            None
        }
    }

    fn check(&self) -> io::Result<()> {
        self.stopped().map_or(Ok(()), |error| Err(error.into()))
    }
}

unsafe extern "C" fn interrupt(_: *mut qjs::JSContext, opaque: *mut c_void) -> i32 {
    // SAFETY: The registered execution state lives until the runtime is freed.
    let execution = unsafe { &*opaque.cast::<Execution<'_>>() };
    i32::from(execution.stopped().is_some())
}

unsafe extern "C" fn tick(
    context: *mut qjs::JSContext,
    _: qjs::JSValue,
    _: i32,
    _: *mut qjs::JSValue,
) -> qjs::JSValue {
    // SAFETY: The context opaque points to the execution borrowed by Engine
    // and QuickJS calls this hook on the owning thread.
    let execution = unsafe { &*qjs::JS_GetContextOpaque(context).cast::<Execution<'_>>() };
    execution.ticks.set(execution.ticks.get().saturating_add(1));
    if execution.stopped().is_some() {
        // QuickJS-NG internal errors terminate the JS evaluation.
        unsafe { qjs::JS_ThrowInternalError(context, c"script execution stopped".as_ptr()) }
    } else {
        undefined()
    }
}

unsafe extern "C" fn unavailable_hint(
    _: *mut qjs::JSContext,
    _: qjs::JSValue,
    _: i32,
    _: *mut qjs::JSValue,
) -> qjs::JSValue {
    // Use the trusted prelude's bounded fallbacks for the JSC-native hints.
    undefined()
}

fn undefined() -> qjs::JSValue {
    unsafe { qjs::JS_Ext_NewSpecialValue(qjs::JS_TAG_UNDEFINED, 0) }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Values, UTF-16 views and callbacks borrow this owner. Nothing that belongs to
// QuickJS can outlive its context, or move to another thread.
struct Engine<'a> {
    runtime: NonNull<qjs::JSRuntime>,
    context: NonNull<qjs::JSContext>,
    execution: &'a Execution<'a>,
}

impl<'a> Engine<'a> {
    fn new(execution: &'a Execution<'a>) -> io::Result<Self> {
        let runtime =
            NonNull::new(unsafe { qjs::JS_NewRuntime() }).ok_or(io::ErrorKind::OutOfMemory)?;
        let opaque = ptr::from_ref(execution).cast_mut().cast();
        // The core library has no standard-library modules installed by the
        // embedder, and this owner neither registers a loader nor drains jobs.
        let context = unsafe {
            qjs::JS_SetMemoryLimit(runtime.as_ptr(), HEAP_LIMIT);
            qjs::JS_SetMaxStackSize(runtime.as_ptr(), STACK_LIMIT);
            qjs::JS_SetCanBlock(runtime.as_ptr(), false);
            qjs::JS_SetInterruptHandler(runtime.as_ptr(), Some(interrupt), opaque);
            NonNull::new(qjs::JS_NewContext(runtime.as_ptr()))
        };
        let Some(context) = context else {
            unsafe { qjs::JS_FreeRuntime(runtime.as_ptr()) };
            execution.check()?;
            return Err(io::ErrorKind::OutOfMemory.into());
        };
        unsafe { qjs::JS_SetContextOpaque(context.as_ptr(), opaque) };
        Ok(Self {
            runtime,
            context,
            execution,
        })
    }

    fn ctx(&self) -> *mut qjs::JSContext {
        self.context.as_ptr()
    }

    fn owned(&self, raw: qjs::JSValue) -> Value<'_> {
        Value {
            ctx: self.ctx(),
            raw,
            owner: PhantomData,
        }
    }

    fn value(&self, raw: qjs::JSValue) -> io::Result<Value<'_>> {
        if unsafe { qjs::JS_Ext_IsException(raw) } {
            Err(self.error())
        } else {
            Ok(self.owned(raw))
        }
    }

    fn error(&self) -> io::Error {
        // Consume the exception regardless of whether timeout or cancellation
        // takes precedence. Avoid stringifying arbitrary exception objects.
        let exception = self.owned(unsafe { qjs::JS_GetException(self.ctx()) });
        self.execution.check().err().unwrap_or_else(|| {
            if unsafe { qjs::JS_Ext_IsNull(exception.raw) } {
                // The engine throws null when an error object cannot be allocated.
                io::ErrorKind::OutOfMemory.into()
            } else {
                invalid("JavaScript evaluation failed")
            }
        })
    }

    fn run(&self, code: &str) -> io::Result<()> {
        let source = CString::new(code).map_err(|_| invalid("invalid JavaScript source text"))?;
        self.value(unsafe {
            qjs::JS_Eval(
                self.ctx(),
                source.as_ptr(),
                source.as_bytes().len(),
                c"vole-http.js".as_ptr(),
                qjs::JS_EVAL_TYPE_GLOBAL as i32,
            )
        })?;
        Ok(())
    }

    fn get(&self, object: &Value<'_>, key: &CStr) -> io::Result<Value<'_>> {
        self.value(unsafe { qjs::JS_GetPropertyStr(self.ctx(), object.raw, key.as_ptr()) })
    }

    fn set(&self, object: &Value<'_>, key: &CStr, value: Value<'_>) -> io::Result<()> {
        // SetPropertyStr consumes the value even when the assignment fails.
        let result = unsafe {
            qjs::JS_SetPropertyStr(self.ctx(), object.raw, key.as_ptr(), value.into_raw())
        };
        if result < 0 {
            Err(self.error())
        } else if result == 0 {
            Err(invalid("script property assignment failed"))
        } else {
            Ok(())
        }
    }

    fn delete(&self, object: &Value<'_>, key: &CStr) -> io::Result<()> {
        let atom = unsafe { qjs::JS_NewAtom(self.ctx(), key.as_ptr()) };
        if atom == qjs::JS_ATOM_NULL {
            return Err(self.error());
        }
        let result = unsafe {
            qjs::JS_DeleteProperty(self.ctx(), object.raw, atom, qjs::JS_PROP_THROW as i32)
        };
        unsafe { qjs::JS_FreeAtom(self.ctx(), atom) };
        if result == 1 {
            Ok(())
        } else {
            Err(self.error())
        }
    }

    fn call(&self, global: &Value<'_>, key: &CStr, input: &Value<'_>) -> io::Result<Value<'_>> {
        let function = self.get(global, key)?;
        let mut argument = input.raw;
        self.value(unsafe { qjs::JS_Call(self.ctx(), function.raw, global.raw, 1, &mut argument) })
    }

    fn text(&self, value: &Value<'_>) -> io::Result<TextView<'_>> {
        if !unsafe { qjs::JS_Ext_IsString(value.raw) } {
            return Err(invalid("script string required"));
        }
        let mut len = 0;
        let ptr = unsafe { qjs::JS_ToCStringLenUTF16(self.ctx(), &mut len, value.raw) };
        if ptr.is_null() {
            return Err(self.error());
        }
        // The API either retains the original UTF-16 buffer or returns an
        // owned copy. This view holds that reference independently of value.
        Ok(TextView {
            ctx: self.ctx(),
            ptr,
            len,
            owner: PhantomData,
        })
    }

    fn install_hook(
        &self,
        global: &Value<'_>,
        name: &CStr,
        function: qjs::JSCFunction,
        arguments: i32,
    ) -> io::Result<()> {
        let hook = self.value(unsafe {
            qjs::JS_Ext_NewCFunction(self.ctx(), function, name.as_ptr(), arguments)
        })?;
        self.set(global, name, hook)
    }
}

impl Drop for Engine<'_> {
    fn drop(&mut self) {
        unsafe {
            qjs::JS_FreeContext(self.ctx());
            qjs::JS_FreeRuntime(self.runtime.as_ptr());
        }
    }
}

struct Value<'a> {
    ctx: *mut qjs::JSContext,
    raw: qjs::JSValue,
    owner: PhantomData<&'a qjs::JSContext>,
}

impl Value<'_> {
    fn into_raw(self) -> qjs::JSValue {
        ManuallyDrop::new(self).raw
    }
}

impl Drop for Value<'_> {
    fn drop(&mut self) {
        unsafe { qjs::JS_FreeValue(self.ctx, self.raw) };
    }
}

struct TextView<'a> {
    ctx: *mut qjs::JSContext,
    ptr: *const u16,
    len: usize,
    owner: PhantomData<&'a qjs::JSContext>,
}

impl TextView<'_> {
    fn units(&self) -> &[u16] {
        // SAFETY: The view owns a live QuickJS string reference.
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for TextView<'_> {
    fn drop(&mut self) {
        unsafe { qjs::JS_FreeCStringUTF16(self.ctx, self.ptr) };
    }
}

struct BodyExport {
    bound: usize,
    available_view: usize,
    extra_view: Option<Reservation>,
}

impl BodyExport {
    fn reserve_text_view(
        &mut self,
        output: &BudgetedBytes,
        units: usize,
        rope: bool,
    ) -> io::Result<()> {
        // JS_ToCStringLenUTF16 can linearize a rope into a narrow string
        // before widening a copy. The narrow allocation has a terminator.
        let flattening = if rope { units + 1 } else { 0 };
        let peak = units * size_of::<u16>() + flattening;
        let needed = peak.saturating_sub(self.available_view);
        if needed != 0 {
            self.extra_view = Some(
                output
                    .reserve_temporary(needed)
                    .ok_or(io::ErrorKind::OutOfMemory)?,
            );
        }
        Ok(())
    }
}

pub(super) fn evaluate(
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input: Option<&[u8]>,
    output: &mut BudgetedBytes,
    bridge_workspace: Option<&Reservation>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> io::Result<serde_json::Value> {
    super::super::diagnostics::increment(super::super::diagnostics::Counter::QuickjsEngineEntered);
    let execution = Execution {
        deadline,
        cancellation,
        ticks: Cell::new(0),
    };
    execution.check()?;
    let size = input.map_or(0, <[u8]>::len);
    let bound = program.maximum_output_bytes(size);
    let text = metadata["body"]["kind"] == "text";
    let bridge_cost = if input.is_some() {
        BridgePlan::new(size, text, bound)
            .and_then(BridgePlan::cost)
            .ok_or_else(|| invalid("invalid JavaScript body bridge"))?
    } else {
        0
    };
    let _local_bridge = match bridge_workspace {
        Some(permit) if !permit.covers(output, bridge_cost) => {
            return Err(invalid("invalid JavaScript bridge reservation"));
        }
        None if bridge_cost != 0 => Some(
            output
                .reserve_temporary(bridge_cost)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        ),
        _ => None,
    };
    // An input body stays live in QuickJS through output extraction. The
    // quoted JSON metadata is charged separately by the bounded VM.
    let retained_input = match input {
        Some(_) if text => size * 2,
        Some(_) => size.max(1),
        None => 0,
    };
    // The engine can cache the flattened string inside the original rope, so
    // the additional reservation stays alive through runtime teardown.
    let mut export = BodyExport {
        bound,
        available_view: bridge_cost.saturating_sub(retained_input),
        extra_view: None,
    };
    let result = {
        let engine = Engine::new(&execution)?;
        invoke(&engine, program, metadata, input, output, &mut export)
    };
    execution.check()?;
    result
}

fn invoke(
    engine: &Engine<'_>,
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input: Option<&[u8]>,
    output: &mut BudgetedBytes,
    export: &mut BodyExport,
) -> io::Result<serde_json::Value> {
    let ctx = engine.ctx();
    let global = engine.value(unsafe { qjs::JS_GetGlobalObject(ctx) })?;
    engine.install_hook(&global, c"__voleTick", Some(tick), 0)?;
    engine.install_hook(&global, c"__voleIsASCII", Some(unavailable_hint), 2)?;
    engine.install_hook(&global, c"__voleReplaceASCIIAll", Some(unavailable_hint), 4)?;
    engine.run(include_str!("runtime.js"))?;
    engine.run(&program.code)?;

    let mut encoded =
        serde_json::to_vec(metadata).map_err(|_| invalid("invalid script metadata"))?;
    let len = encoded.len();
    if len > METADATA_LIMIT {
        return Err(invalid("script metadata limit"));
    }
    encoded
        .try_reserve_exact(1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    encoded.push(0);
    let argument = engine.value(unsafe {
        qjs::JS_ParseJSON(
            ctx,
            encoded.as_ptr().cast(),
            len,
            c"vole-http-input.json".as_ptr(),
        )
    })?;
    drop(encoded);
    if let Some(bytes) = input {
        let body = engine.get(&argument, c"body")?;
        let data = if metadata["body"]["kind"] == "text" {
            std::str::from_utf8(bytes).map_err(|_| invalid("script body is not UTF-8"))?;
            unsafe { qjs::JS_NewStringLen(ctx, bytes.as_ptr().cast(), bytes.len()) }
        } else {
            unsafe { qjs::JS_NewUint8ArrayCopy(ctx, bytes.as_ptr(), bytes.len()) }
        };
        engine.set(&body, c"data", engine.value(data)?)?;
    }

    let result = engine.call(&global, c"rewrite", &argument)?;
    let result = engine.call(&global, c"__voleFinish", &result)?;
    let body = engine.get(&result, c"body")?;
    if !unsafe { qjs::JS_Ext_IsUndefined(body.raw) } {
        let data = engine.get(&body, c"data")?;
        export_body(engine, &global, &data, output, export)?;
        engine.delete(&body, c"data")?;
    }

    let json = engine
        .value(unsafe { qjs::JS_JSONStringify(ctx, result.raw, undefined(), undefined()) })?;
    let view = engine.text(&json)?;
    let units = view.units();
    let bytes = utf8_size(units, MAX_BODY)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(bytes)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    encoded.resize(bytes, 0);
    encode_utf8(units, &mut encoded)?;
    serde_json::from_slice(&encoded).map_err(|_| invalid("invalid script result encoding"))
}

fn export_body(
    engine: &Engine<'_>,
    global: &Value<'_>,
    data: &Value<'_>,
    output: &mut BudgetedBytes,
    export: &mut BodyExport,
) -> io::Result<()> {
    let bound = export.bound;
    if unsafe { qjs::JS_Ext_IsString(data.raw) } {
        let size = engine.call(global, c"__voleExportTextUnits", data)?;
        let mut units = 0;
        if unsafe { qjs::JS_ToInt32(engine.ctx(), &mut units, size.raw) } != 0 {
            return Err(engine.error());
        }
        let units = usize::try_from(units)
            .ok()
            .filter(|n| *n <= bound)
            .ok_or_else(|| invalid("text exceeded proven output bound"))?;
        let rope = unsafe { qjs::JS_Ext_ValueGetTag(data.raw) } == qjs::JS_TAG_STRING_ROPE;
        export.reserve_text_view(output, units, rope)?;
        let view = engine.text(data)?;
        if view.len != units {
            return Err(invalid("script text length changed before export"));
        }
        let bytes = utf8_size(view.units(), bound)?;
        output.prepare_output(bytes)?;
        return output.write_initialized_output(bytes, |dst| encode_utf8(view.units(), dst));
    }

    // Finish already validated the non-detached kind and disallows SharedArrayBuffer.
    let mut len = 0;
    let bytes = unsafe {
        if qjs::JS_IsArrayBuffer(data.raw) {
            qjs::JS_GetArrayBuffer(engine.ctx(), &mut len, data.raw)
        } else {
            // The public API includes the typed-array view's offset.
            qjs::JS_GetUint8Array(engine.ctx(), &mut len, data.raw)
        }
    };
    if bytes.is_null() && (len != 0 || unsafe { qjs::JS_HasException(engine.ctx()) }) {
        return Err(engine.error());
    }
    if len > bound {
        return Err(invalid("script exceeded proven output bound"));
    }
    // SAFETY: data roots the backing, and this code makes no JS call before
    // the copy. Empty views need no dereference, even with a null backing.
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(bytes, len) }
    };
    output.prepare_output(len)?;
    output.write_initialized_output(len, |dst| {
        dst.copy_from_slice(bytes);
        Ok(len)
    })
}

fn utf8_size(units: &[u16], bound: usize) -> io::Result<usize> {
    if units.len() > bound {
        return Err(invalid("script exceeded proven output bound"));
    }
    let mut bytes = 0;
    for unit in char::decode_utf16(units.iter().copied()) {
        bytes += unit
            .map_err(|_| invalid("invalid script UTF-16 export"))?
            .len_utf8();
        if bytes > bound {
            return Err(invalid("script exceeded proven output bound"));
        }
    }
    Ok(bytes)
}

fn encode_utf8(units: &[u16], dst: &mut [u8]) -> io::Result<usize> {
    let mut offset = 0;
    for unit in char::decode_utf16(units.iter().copied()) {
        let character = unit.map_err(|_| invalid("invalid script UTF-16 export"))?;
        let end = offset + character.len_utf8();
        let target = dst
            .get_mut(offset..end)
            .ok_or_else(|| invalid("invalid script UTF-8 size"))?;
        character.encode_utf8(target);
        offset = end;
    }
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_processing::{body_budget::Budget, scripts::validate_source};
    use serde_json::json;
    use std::time::Duration;

    fn execute(
        script: &CompiledSource,
        metadata: serde_json::Value,
        input: Option<&[u8]>,
        cancellation: &CancellationToken,
        timeout: Duration,
    ) -> (io::Result<serde_json::Value>, BudgetedBytes) {
        let mut output = BudgetedBytes::empty(&Budget::default());
        let result = evaluate(
            script,
            &metadata,
            input,
            &mut output,
            None,
            cancellation,
            Instant::now() + timeout,
        );
        (result, output)
    }

    #[test]
    fn preserves_binary_view_offsets_and_unicode_local_outputs() {
        let binary = validate_source(
            "function rewrite(input) {
                return {type:'modify',body:{kind:'bytes',data:input.body.data.subarray(1,3)}};
            }",
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let (result, output) = execute(
            &binary,
            json!({"body":{"kind":"bytes"}}),
            Some(&[128, 0, 255, 33]),
            &cancellation,
            Duration::from_secs(3),
        );
        assert_eq!(
            result.unwrap(),
            json!({"type":"modify","body":{"kind":"bytes"}})
        );
        assert_eq!(output.as_ref(), &[0, 255]);

        let text = validate_source(
            r#"function rewrite(input) {
                return {type:'respond',status:200,body:{kind:'text',data:'🦕\u0000é'}};
            }"#,
        )
        .unwrap();
        let (result, output) = execute(
            &text,
            json!({"body":{"kind":"not-requested"}}),
            None,
            &cancellation,
            Duration::from_secs(3),
        );
        assert_eq!(
            result.unwrap(),
            json!({"type":"respond","status":200,"body":{"kind":"text"}})
        );
        assert_eq!(output.as_ref(), "🦕\0é".as_bytes());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn closed_text_plan_matches_quickjs_guards_and_unicode_output() {
        use crate::http_processing::scripts::Backend;

        let script = validate_source(
            r#"function rewrite(input) {
                let found = false;
                for (let i = 0; i < input.response.headers.length; i++) {
                    if (input.response.headers[i].name === "x-native" &&
                        input.response.headers[i].value === "native-v1") { found = true; }
                }
                if (!found) { return {type: "abort"}; }
                if (!input.body || input.body.kind !== "text" ||
                    typeof input.body.data !== "string" || input.body.data.length !== 6) {
                    return {type: "abort"};
                }
                let data = input.body.data;
                data = data.replaceAll("b", "c");
                return {type: "modify", headers: [{op: "set", name: "x-js",
                    values: ["native-v1>js-v1"]}], body: {kind: "text", data: data}};
            }"#,
        )
        .unwrap();
        let fallback = validate_source(
            r#"function rewrite(input) {
                return {type: "modify", body: {kind: "text", data: input.body.data.toUpperCase()}};
            }"#,
        )
        .unwrap();
        let cancellation = CancellationToken::new();

        for (header, text, action, expected) in [
            ("native-v1", "b🦕é\0b", "modify", "c🦕é\0c"),
            ("other", "b🦕é\0b", "abort", ""),
            ("native-v1", "b🦕é\0", "abort", ""),
        ] {
            let metadata = json!({
                "body": {"kind": "text"},
                "response": {"headers": [{"name": "x-native", "value": header}]}
            });
            let budget = Budget::default();
            let input = BudgetedBytes::copy(&budget, text.as_bytes()).unwrap();
            let witness = Some(input.borrowed_body());
            let Backend::Plan(plan) = script.backend(&metadata, witness) else {
                panic!("closed guarded script must select the static plan");
            };
            assert!(matches!(
                fallback.backend(&metadata, witness),
                Backend::Engine(_)
            ));

            let bound = plan.maximum_output_bytes(text.len()).unwrap();
            let mut output = BudgetedBytes::new_fixed_output(&budget, bound).unwrap();
            let plan_result = plan
                .try_execute(
                    &metadata,
                    witness,
                    &mut output,
                    &cancellation,
                    Instant::now() + Duration::from_secs(3),
                )
                .unwrap()
                .result
                .unwrap();
            let mut vm_output = BudgetedBytes::empty(&budget);
            let vm_result = evaluate(
                &script,
                &metadata,
                Some(input.as_ref()),
                &mut vm_output,
                None,
                &cancellation,
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            assert_eq!(plan_result["type"], action);
            assert_eq!(plan_result, vm_result);
            assert_eq!(output.as_ref(), expected.as_bytes());
            assert_eq!(output.as_ref(), vm_output.as_ref());
            drop((input, output, vm_output));
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn admits_rope_conversion_before_allocating_the_export_view() {
        use crate::http_processing::body_budget::WORKSPACE;

        let execution = Execution {
            deadline: Instant::now() + Duration::from_secs(3),
            cancellation: &CancellationToken::new(),
            ticks: Cell::new(0),
        };
        let engine = Engine::new(&execution).unwrap();
        engine.run(include_str!("runtime.js")).unwrap();
        // Bypass the Finish walk so the native converter sees a rope that
        // has not already been flattened by the trusted string predicates.
        engine
            .run("function rope() { return 'a'.repeat(600) + 'b'.repeat(600); }")
            .unwrap();
        let global = engine
            .value(unsafe { qjs::JS_GetGlobalObject(engine.ctx()) })
            .unwrap();
        let argument = engine.owned(undefined());
        let data = engine.call(&global, c"rope", &argument).unwrap();
        assert_eq!(
            unsafe { qjs::JS_Ext_ValueGetTag(data.raw) },
            qjs::JS_TAG_STRING_ROPE
        );

        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        let used = WORKSPACE - 3_600;
        // This would admit the 2,400-byte UTF-16 copy and 1,200-byte output,
        // but cannot admit the still-live flattened copy and terminator.
        let _other_body_owner = budget.reserve(used).unwrap();
        let mut export = BodyExport {
            bound: MAX_BODY,
            available_view: 0,
            extra_view: None,
        };
        let error = export_body(&engine, &global, &data, &mut output, &mut export).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert!(output.as_ref().is_empty());
        assert_eq!(budget.used(), used);
    }

    #[test]
    fn interrupts_uninstrumented_work_and_recovers_on_the_next_call() {
        let hanging = CompiledSource {
            code: "function rewrite(input) { while (true) {} }".into(),
            ..CompiledSource::default()
        };
        let metadata = json!({"body":{"kind":"not-requested"}});
        let (result, output) = execute(
            &hanging,
            metadata.clone(),
            None,
            &CancellationToken::new(),
            Duration::from_millis(150),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(output.as_ref().is_empty());
        assert_eq!(output.budget().used(), 0);

        // The backend must report cancellation while executing, and the real
        // owner must return before a new invocation can proceed.
        let cancellation = CancellationToken::new();
        let (result, output) = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(25));
                cancellation.cancel();
            });
            execute(
                &hanging,
                metadata.clone(),
                None,
                &cancellation,
                Duration::from_secs(3),
            )
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(output.as_ref().is_empty());
        assert_eq!(output.budget().used(), 0);

        let success = validate_source("function rewrite(input) { return {type:'pass'}; }").unwrap();
        let (result, _) = execute(
            &success,
            metadata,
            None,
            &CancellationToken::new(),
            Duration::from_secs(3),
        );
        assert_eq!(result.unwrap(), json!({"type":"pass"}));
    }
}
