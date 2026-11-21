//! In-process engine for Linux and Windows. Every evaluation owns its isolate
//! and joins the watchdog before releasing the isolate and its body permit.
use std::{
    cell::Cell,
    ffi::c_void,
    io,
    sync::{OnceLock, mpsc},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

use super::{
    super::body_budget::{BridgePlan, BudgetedBytes, MAX_BODY, Reservation},
    CompiledSource,
};

const TICK_LIMIT: usize = 100_000;
const HEAP_LIMIT: usize = 16 * 1024 * 1024;
const HEAP_UNWIND_MARGIN: usize = 2 * 1024 * 1024;
const METADATA_LIMIT: usize = 1024 * 1024;

pub(super) fn initialize_platform() -> io::Result<()> {
    static INITIALIZED: OnceLock<()> = OnceLock::new();
    INITIALIZED.get_or_init(|| {
        // No unattached engine jobs survive the caller's execution owner.
        v8::V8::set_flags_from_string("--single-threaded");
        v8::V8::initialize_platform(v8::new_single_threaded_default_platform(false).make_shared());
        v8::V8::initialize();
    });
    Ok(())
}

struct Execution<'a> {
    deadline: Instant,
    cancellation: &'a CancellationToken,
}

impl Execution<'_> {
    fn check(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    fn watch(&self, isolate: v8::IsolateHandle, done: mpsc::Receiver<()>) {
        loop {
            if self.check().is_err() {
                isolate.terminate_execution();
                break;
            }
            let interval = self
                .deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(2));
            if !matches!(
                done.recv_timeout(interval),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                break;
            }
        }
    }
}

struct HeapPressure {
    isolate: Option<v8::IsolateHandle>,
    reached: Cell<bool>,
}

unsafe extern "C" fn heap_pressure(
    data: *mut c_void,
    current_limit: usize,
    initial_limit: usize,
) -> usize {
    // SAFETY: The owner registers its stable local state after creating the
    // isolate. The isolate is released before the state leaves scope.
    let state = unsafe { &*data.cast::<HeapPressure>() };
    state.reached.set(true);
    if let Some(isolate) = &state.isolate {
        isolate.terminate_execution();
    }
    // V8 needs room to observe termination and unwind the active allocation.
    current_limit.max(initial_limit.saturating_add(HEAP_UNWIND_MARGIN))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Ticks(usize);

fn tick(
    scope: &mut v8::PinScope<'_, '_>,
    _: v8::FunctionCallbackArguments<'_>,
    _: v8::ReturnValue<'_, v8::Value>,
) {
    if let Some(ticks) = scope.get_slot_mut::<Ticks>() {
        ticks.0 += 1;
        if ticks.0 <= TICK_LIMIT {
            return;
        }
    }
    scope.terminate_execution();
}

fn native_hint_unavailable(
    _: &mut v8::PinScope<'_, '_>,
    _: v8::FunctionCallbackArguments<'_>,
    _: v8::ReturnValue<'_, v8::Value>,
) {
    // Undefined keeps the runtime's bounded JS fallback for JSC fast paths.
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
    let execution = Execution {
        deadline,
        cancellation,
    };
    execution.check()?;
    let bound = program.maximum_output_bytes(input.map_or(0, <[u8]>::len));
    let required = match input {
        Some(bytes) => BridgePlan::new(bytes.len(), metadata["body"]["kind"] == "text", bound)
            .and_then(BridgePlan::cost)
            .ok_or_else(|| invalid("invalid JavaScript body bridge"))?,
        None => 0,
    };
    let _local_bridge = match bridge_workspace {
        Some(permit) if !permit.covers(output, required) => {
            return Err(invalid("invalid JavaScript bridge reservation"));
        }
        None if required != 0 => Some(
            output
                .reserve_temporary(required)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        ),
        _ => None,
    };

    initialize_platform()?;
    execution.check()?;
    let mut pressure = HeapPressure {
        isolate: None,
        reached: Cell::new(false),
    };
    let mut isolate = v8::Isolate::new(v8::CreateParams::default().heap_limits(0, HEAP_LIMIT));
    isolate.set_microtasks_policy(v8::MicrotasksPolicy::Explicit);
    isolate.set_slot(Ticks(0));
    let handle = isolate.thread_safe_handle();
    pressure.isolate = Some(handle.clone());
    isolate.add_near_heap_limit_callback(
        heap_pressure,
        std::ptr::from_ref(&pressure).cast_mut().cast(),
    );

    let result = {
        v8::scope!(let scope, &mut isolate);
        let context = v8::Context::new(scope, Default::default());
        context.set_allow_generation_from_strings(false);
        let scope = &mut v8::ContextScope::new(scope, context);
        v8::tc_scope!(let scope, scope);
        execution.check()?;
        std::thread::scope(|owner| {
            let (done, watch) = mpsc::channel();
            let execution = &execution;
            std::thread::Builder::new()
                .name("vole-js-v8-watchdog".into())
                .spawn_scoped(owner, move || execution.watch(handle, watch))?;
            let result = invoke(scope, program, metadata, input, output, bound);
            drop(done);
            result
        })
    };

    execution.check()?;
    if isolate
        .get_slot::<Ticks>()
        .is_some_and(|ticks| ticks.0 > TICK_LIMIT)
    {
        return Err(io::ErrorKind::TimedOut.into());
    }
    if pressure.reached.get() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    result
}

fn invoke(
    scope: &mut v8::PinScope<'_, '_>,
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input_body: Option<&[u8]>,
    output: &mut BudgetedBytes,
    bound: usize,
) -> io::Result<serde_json::Value> {
    let global = scope.get_current_context().global(scope);
    let tick = v8::Function::new(scope, tick).ok_or_else(js_error)?;
    let hint = v8::Function::new(scope, native_hint_unavailable).ok_or_else(js_error)?;
    set(scope, global, "__voleTick", tick.into())?;
    set(scope, global, "__voleIsASCII", hint.into())?;
    set(scope, global, "__voleReplaceASCIIAll", hint.into())?;
    run_script(scope, include_str!("runtime.js"))?;
    run_script(scope, &program.code)?;

    let encoded =
        serde_json::to_string(metadata).map_err(|_| invalid("invalid script metadata"))?;
    if encoded.len() > METADATA_LIMIT {
        return Err(invalid("script metadata limit"));
    }
    let encoded = new_string(scope, &encoded)?;
    let input = v8::json::parse(scope, encoded).ok_or_else(js_error)?;
    if let Some(bytes) = input_body {
        let record = v8::Local::<v8::Object>::try_from(input).map_err(|_| js_error())?;
        let body = get_object(scope, record, "body")?;
        let data = if metadata["body"]["kind"] == "text" {
            let text =
                std::str::from_utf8(bytes).map_err(|_| invalid("script body is not UTF-8"))?;
            new_string(scope, text)?.into()
        } else {
            let mut copy = Vec::new();
            copy.try_reserve_exact(bytes.len())
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            copy.extend_from_slice(bytes);
            let backing = v8::ArrayBuffer::new_backing_store_from_vec(copy).make_shared();
            let buffer = v8::ArrayBuffer::with_backing_store(scope, &backing);
            v8::Uint8Array::new(scope, buffer, 0, bytes.len())
                .ok_or_else(js_error)?
                .into()
        };
        set(scope, body, "data", data)?;
    }

    let result = call(scope, global, "rewrite", input)?;
    let result = call(scope, global, "__voleFinish", result)?;
    let record = v8::Local::<v8::Object>::try_from(result).map_err(|_| js_error())?;
    let body = get(scope, record, "body")?;
    if !body.is_undefined() {
        let body = v8::Local::<v8::Object>::try_from(body).map_err(|_| js_error())?;
        let key = new_string(scope, "data")?;
        let data = body.get(scope, key.into()).ok_or_else(js_error)?;
        export_body(scope, data, output, bound)?;
        if body.delete(scope, key.into()) != Some(true) {
            return Err(js_error());
        }
    }
    let result = v8::json::stringify(scope, result).ok_or_else(js_error)?;
    let bytes = result.utf8_length(scope);
    if bytes > MAX_BODY {
        return Err(invalid("script result metadata limit"));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(bytes)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    buffer.resize(bytes, 0);
    write_utf8(scope, result, &mut buffer)?;
    serde_json::from_slice(&buffer).map_err(|_| invalid("invalid script result encoding"))
}

fn export_body(
    scope: &mut v8::PinScope<'_, '_>,
    data: v8::Local<v8::Value>,
    output: &mut BudgetedBytes,
    bound: usize,
) -> io::Result<()> {
    // Finish has already validated body.kind, primitive UTF-16 and byte type.
    if let Ok(text) = v8::Local::<v8::String>::try_from(data) {
        let length = text.utf8_length(scope);
        admit(output, length, bound)?;
        output.write_initialized_output(length, |destination| write_utf8(scope, text, destination))
    } else if let Ok(array) = v8::Local::<v8::Uint8Array>::try_from(data) {
        let length = array.byte_length();
        admit(output, length, bound)?;
        output.write_initialized_output(length, |destination| {
            let copied = array.copy_contents(destination);
            if copied != length {
                return Err(invalid("incomplete script body export"));
            }
            Ok(copied)
        })
    } else if let Ok(buffer) = v8::Local::<v8::ArrayBuffer>::try_from(data) {
        let length = buffer.byte_length();
        admit(output, length, bound)?;
        let backing = buffer.get_backing_store();
        output.write_initialized_output(length, |destination| {
            if backing.len() != length {
                return Err(invalid("invalid script output backing"));
            }
            for (out, byte) in destination.iter_mut().zip(backing.iter()) {
                *out = byte.get();
            }
            Ok(length)
        })
    } else {
        Err(invalid("invalid script output body"))
    }
}

fn admit(output: &mut BudgetedBytes, length: usize, bound: usize) -> io::Result<()> {
    if length > bound {
        return Err(invalid("script exceeded proven output bound"));
    }
    output.prepare_output(length)
}

fn write_utf8(
    scope: &v8::PinScope<'_, '_>,
    text: v8::Local<v8::String>,
    destination: &mut [u8],
) -> io::Result<usize> {
    let written = text.write_utf8_v2(scope, destination, v8::WriteFlags::empty(), None);
    if written != destination.len() || std::str::from_utf8(destination).is_err() {
        return Err(invalid("invalid script UTF-8 export"));
    }
    Ok(written)
}

fn js_error() -> io::Error {
    invalid("JavaScript evaluation failed")
}

fn new_string<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    value: &str,
) -> io::Result<v8::Local<'s, v8::String>> {
    v8::String::new(scope, value).ok_or_else(js_error)
}

fn run_script(scope: &mut v8::PinScope<'_, '_>, source: &str) -> io::Result<()> {
    let source = new_string(scope, source)?;
    let script = v8::Script::compile(scope, source, None).ok_or_else(js_error)?;
    script.run(scope).ok_or_else(js_error)?;
    Ok(())
}

fn set(
    scope: &mut v8::PinScope<'_, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    value: v8::Local<v8::Value>,
) -> io::Result<()> {
    let key = new_string(scope, name)?;
    if object.set(scope, key.into(), value) != Some(true) {
        return Err(js_error());
    }
    Ok(())
}

fn get<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> io::Result<v8::Local<'s, v8::Value>> {
    let key = new_string(scope, name)?;
    object.get(scope, key.into()).ok_or_else(js_error)
}

fn get_object<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
) -> io::Result<v8::Local<'s, v8::Object>> {
    v8::Local::<v8::Object>::try_from(get(scope, object, name)?).map_err(|_| js_error())
}

fn call<'s>(
    scope: &mut v8::PinScope<'s, '_>,
    object: v8::Local<v8::Object>,
    name: &str,
    input: v8::Local<v8::Value>,
) -> io::Result<v8::Local<'s, v8::Value>> {
    let function =
        v8::Local::<v8::Function>::try_from(get(scope, object, name)?).map_err(|_| js_error())?;
    function
        .call(scope, object.into(), &[input])
        .ok_or_else(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_processing::{body_budget::Budget, scripts::validate_source};
    use serde_json::json;

    fn execute(
        script: &CompiledSource,
        metadata: serde_json::Value,
        input: Option<&[u8]>,
        deadline: Duration,
    ) -> (io::Result<serde_json::Value>, BudgetedBytes) {
        let budget = Budget::default();
        let mut output = BudgetedBytes::empty(&budget);
        let result = evaluate(
            script,
            &metadata,
            input,
            &mut output,
            None,
            &CancellationToken::new(),
            Instant::now() + deadline,
        );
        (result, output)
    }

    #[test]
    fn v8_preserves_binary_view_offsets_and_unicode_local_outputs() {
        let binary = validate_source(
            "function rewrite(input) {
                return {type:'modify',body:{kind:'bytes',data:input.body.data.subarray(1,3)}};
            }",
        )
        .unwrap();
        let (result, output) = execute(
            &binary,
            json!({"body":{"kind":"bytes"}}),
            Some(&[128, 0, 255, 33]),
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
            Duration::from_secs(3),
        );
        assert_eq!(
            result.unwrap(),
            json!({"type":"respond","status":200,"body":{"kind":"text"}})
        );
        assert_eq!(output.as_ref(), "🦕\0é".as_bytes());
    }

    #[test]
    fn v8_stops_uninstrumented_work_and_recovers_on_the_next_call() {
        initialize_platform().unwrap();
        // This adapter-level fixture omits the frontend's instrumented ticks
        // to ensure the independent watchdog owns the termination here.
        let hanging = CompiledSource {
            code: "function rewrite(input) { while (true) {} }".into(),
            ..CompiledSource::default()
        };
        let metadata = json!({"body":{"kind":"not-requested"}});
        let (result, output) =
            execute(&hanging, metadata.clone(), None, Duration::from_millis(300));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(output.as_ref().is_empty());
        assert_eq!(output.budget().used(), 0);

        let success = validate_source("function rewrite(input) { return {type:'pass'}; }").unwrap();
        let (result, _) = execute(&success, metadata, None, Duration::from_secs(3));
        assert_eq!(result.unwrap(), json!({"type":"pass"}));
    }
}
