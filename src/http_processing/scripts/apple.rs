//! System JavaScriptCore C API. No private execution-time or heap APIs.
use super::CompiledSource;
use crate::http_processing::{
    body_budget::{API_TEXT_VIEW, BridgePlan, Budget, BudgetedBytes, Reservation},
    diagnostics::{self, Counter},
};
use std::{
    cell::RefCell,
    ffi::{CString, c_char, c_void},
    io, ptr, slice,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

type Context = *const c_void;
type Object = *mut c_void;
type Value = *const c_void;
type JsString = *mut c_void;
type Callback =
    unsafe extern "C" fn(Context, Object, Object, usize, *const Value, *mut Value) -> Value;

#[link(name = "JavaScriptCore", kind = "framework")]
unsafe extern "C" {
    fn JSGlobalContextCreate(class: *const c_void) -> Context;
    fn JSGlobalContextRelease(ctx: Context);
    fn JSContextGetGlobalObject(ctx: Context) -> Object;
    fn JSStringCreateWithUTF8CString(text: *const c_char) -> JsString;
    fn JSStringCreateWithCharacters(text: *const u16, length: usize) -> JsString;
    fn JSStringRelease(string: JsString);
    fn JSStringGetLength(string: JsString) -> usize;
    fn JSStringGetCharactersPtr(string: JsString) -> *const u16;
    fn JSStringGetUTF8CString(string: JsString, buffer: *mut c_char, size: usize) -> usize;
    fn JSValueMakeUndefined(ctx: Context) -> Value;
    fn JSValueMakeBoolean(ctx: Context, value: bool) -> Value;
    fn JSValueMakeString(ctx: Context, value: JsString) -> Value;
    fn JSValueMakeFromJSONString(ctx: Context, value: JsString) -> Value;
    fn JSValueCreateJSONString(
        ctx: Context,
        value: Value,
        indent: u32,
        exception: *mut Value,
    ) -> JsString;
    fn JSValueToStringCopy(ctx: Context, value: Value, exception: *mut Value) -> JsString;
    fn JSValueToObject(ctx: Context, value: Value, exception: *mut Value) -> Object;
    fn JSValueIsString(ctx: Context, value: Value) -> bool;
    fn JSValueIsNumber(ctx: Context, value: Value) -> bool;
    fn JSValueToNumber(ctx: Context, value: Value, exception: *mut Value) -> f64;
    fn JSValueIsUndefined(ctx: Context, value: Value) -> bool;
    fn JSValueProtect(ctx: Context, value: Value);
    fn JSValueUnprotect(ctx: Context, value: Value);
    fn JSObjectMakeFunctionWithCallback(
        ctx: Context,
        name: JsString,
        callback: Option<Callback>,
    ) -> Object;
    fn JSObjectGetProperty(
        ctx: Context,
        object: Object,
        name: JsString,
        exception: *mut Value,
    ) -> Value;
    fn JSObjectSetProperty(
        ctx: Context,
        object: Object,
        name: JsString,
        value: Value,
        attributes: u32,
        exception: *mut Value,
    );
    fn JSObjectDeleteProperty(
        ctx: Context,
        object: Object,
        name: JsString,
        exception: *mut Value,
    ) -> bool;
    fn JSObjectCallAsFunction(
        ctx: Context,
        object: Object,
        receiver: Object,
        count: usize,
        args: *const Value,
        exception: *mut Value,
    ) -> Value;
    fn JSEvaluateScript(
        ctx: Context,
        source: JsString,
        this: Object,
        url: JsString,
        line: i32,
        exception: *mut Value,
    ) -> Value;
    fn JSObjectMakeTypedArray(
        ctx: Context,
        kind: u32,
        length: usize,
        exception: *mut Value,
    ) -> Object;
    fn JSObjectGetTypedArrayByteLength(
        ctx: Context,
        object: Object,
        exception: *mut Value,
    ) -> usize;
    fn JSObjectGetTypedArrayByteOffset(
        ctx: Context,
        object: Object,
        exception: *mut Value,
    ) -> usize;
    fn JSObjectGetTypedArrayBuffer(ctx: Context, object: Object, exception: *mut Value) -> Object;
    fn JSObjectGetArrayBufferByteLength(
        ctx: Context,
        object: Object,
        exception: *mut Value,
    ) -> usize;
    fn JSObjectGetArrayBufferBytesPtr(
        ctx: Context,
        object: Object,
        exception: *mut Value,
    ) -> *mut c_void;
    fn JSValueGetTypedArrayType(ctx: Context, value: Value, exception: *mut Value) -> u32;
}

struct StringRef(JsString);
impl StringRef {
    fn new(value: &str) -> io::Result<Self> {
        let bytes = CString::new(value).map_err(|_| invalid("embedded NUL in control string"))?;
        let value = unsafe { JSStringCreateWithUTF8CString(bytes.as_ptr()) };
        if value.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(Self(value))
    }
    fn text(value: &str, allow_utf8: bool) -> io::Result<Self> {
        #[cfg(test)]
        if FORCE_UTF16_INPUT_FOR_TEST.with(std::cell::Cell::get) {
            return Self::text_utf16(value);
        }
        if allow_utf8 && !value.is_empty() && value.bytes().all(|byte| byte.is_ascii() && byte != 0)
        {
            // Keep the original fallible, exact-capacity body allocation rule.
            // Admission separately pays retained API2I and Vec bookkeeping;
            // this branch requires view >= 3I+1 for CString+possible decoder.
            #[cfg(test)]
            bridge_event(BridgeEvent::InputUtf8Start);
            let length = value
                .len()
                .checked_add(1)
                .ok_or(io::ErrorKind::OutOfMemory)?;
            let mut utf8 = Vec::new();
            utf8.try_reserve_exact(length)
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            if utf8.capacity() > length {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            utf8.extend_from_slice(value.as_bytes());
            utf8.push(0);
            let value = unsafe { JSStringCreateWithUTF8CString(utf8.as_ptr().cast()) };
            if value.is_null() {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            return Ok(Self(value));
        }
        Self::text_utf16(value)
    }
    fn text_utf16(value: &str) -> io::Result<Self> {
        #[cfg(test)]
        bridge_event(BridgeEvent::InputUtf16Start);
        let length = value.encode_utf16().count();
        let mut utf16 = Vec::new();
        utf16
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        if utf16.capacity() > length {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        utf16.extend(value.encode_utf16());
        let value = unsafe { JSStringCreateWithCharacters(utf16.as_ptr(), utf16.len()) };
        if value.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(Self(value))
    }
    fn units(&self) -> &[u16] {
        let length = unsafe { JSStringGetLength(self.0) };
        if length == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(JSStringGetCharactersPtr(self.0), length) }
    }
    fn to_string_checked(&self, limit: usize) -> io::Result<String> {
        let length = utf8_length(self.units(), limit)?;
        let mut result = String::new();
        result
            .try_reserve_exact(length)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        for ch in char::decode_utf16(self.units().iter().copied()) {
            result.push(ch.map_err(|_| invalid("invalid UTF-16"))?);
        }
        Ok(result)
    }
}
impl Drop for StringRef {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { JSStringRelease(self.0) };
        }
    }
}
/// Initialize trusted platform/prelude state on a joined owner thread. No user
/// source is evaluated. No prelude, callback, execution TLS, body view or VM
/// survives this function; the process only retains the joined Ready marker.
pub(super) fn initialize_platform() -> io::Result<()> {
    struct PlatformContext(Context);
    impl Drop for PlatformContext {
        fn drop(&mut self) {
            unsafe { JSGlobalContextRelease(self.0) };
            diagnostics::increment(Counter::PlatformWarmupContextReleased);
        }
    }
    let raw = unsafe { JSGlobalContextCreate(ptr::null()) };
    if raw.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    diagnostics::increment(Counter::PlatformWarmupContextCreated);
    let context = PlatformContext(raw);
    let global = unsafe { JSContextGetGlobalObject(context.0) };
    if global.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    // These callbacks exist only in this disposable, trusted context. They do
    // not inspect args, touch EXECUTION, acquire body credit or count business
    // ticks. Known small constants bound every prelude path exercised below.
    for name in ["__voleTick", "__voleIsASCII", "__voleReplaceASCIIAll"] {
        let key = StringRef::new(name)?;
        let function = unsafe {
            JSObjectMakeFunctionWithCallback(context.0, key.0, Some(platform_warmup_noop))
        };
        if function.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        set(context.0, global, name, function.cast_const())?;
    }
    if script(context.0, include_str!("runtime.js"))?.is_null()
        || script(context.0, PLATFORM_TRUSTED_WARMUP)?.is_null()
    {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    drop(context);
    Ok(())
}

unsafe extern "C" fn platform_warmup_noop(
    ctx: Context,
    _: Object,
    _: Object,
    _: usize,
    _: *const Value,
    _: *mut Value,
) -> Value {
    unsafe { JSValueMakeUndefined(ctx) }
}

// Fixed trusted code, not generated from configuration or passed user source.
// No source enumeration, callback arguments, network, metadata/body input or
// rewrite() invocation is available here. Each helper receives only the small
// constants below, and both synthetic results die with PlatformContext.
const PLATFORM_TRUSTED_WARMUP: &str = r#"
(function () {
    const input = {body: {data: "warmup:text:text"}};
    const text = __voleGet(__voleGet(input, "body"), "data");
    const changed = __voleCall(text, "replaceAll", [":", "_"]);
    if (changed !== "warmup_text_text") throw new Error("trusted warmup mismatch");
    __voleFinish(__voleValue({
        type: "modify",
        headers: __voleValue([__voleValue({
            op: "set", name: "x-vole-warmup", values: __voleValue(["ready"])
        })]),
        body: __voleValue({kind: "text", data: changed})
    }));
    __voleExportTextUnits(changed);
    const bytes = __voleCall(Uint8Array, "from", [[0, 1, 127, 255]]);
    __voleFinish(__voleValue({
        type: "modify", body: __voleValue({kind: "bytes", data: bytes})
    }));
})();
"#;

struct ContextRef(Context);
impl Drop for ContextRef {
    fn drop(&mut self) {
        #[cfg(feature = "http-diagnostics")]
        execution_phase("context-release");
        #[cfg(feature = "http-diagnostics")]
        let started = Instant::now();
        unsafe { JSGlobalContextRelease(self.0) };
        #[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
        VALIDATION_TRACE.with(|slot| {
            if let Some(trace) = slot.borrow_mut().as_mut() {
                trace.context_released = true;
            }
        });
        #[cfg(test)]
        CONTEXT_RELEASE_FOR_TEST.with(|slot| {
            if let Some(observer) = slot.borrow_mut().take() {
                observer();
            }
        });
        #[cfg(feature = "http-diagnostics")]
        super::super::diagnostics::timing(
            super::super::diagnostics::Timing::ContextRelease,
            started.elapsed().as_micros(),
        );
        if !self.0.is_null() {
            super::super::diagnostics::context_released();
        }
    }
}
struct Rooted {
    ctx: Context,
    value: Value,
}
impl Rooted {
    fn new(ctx: Context, value: Value) -> io::Result<Self> {
        if value.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        unsafe { JSValueProtect(ctx, value) };
        Ok(Self { ctx, value })
    }
}
impl Drop for Rooted {
    fn drop(&mut self) {
        unsafe { JSValueUnprotect(self.ctx, self.value) };
    }
}

struct Execution {
    deadline: Instant,
    cancellation: CancellationToken,
    ascii_view_budget: Budget,
    prepaid_view_capacity: usize,
    // Final body egress3O can never be consumed by retained outputs.
    prepaid_export_floor: usize,
    // Disjoint portions of that slot retained by native API output strings.
    // Never includes the separately paid 2I input backing or Rust output Vec.
    retained_borrowed: usize,
    // Extra native-output backing outside borrowed prepaid slices. The
    // complete prepaid bridge owner and this cumulative extra owner both
    // outlive the actual JSGlobalContextRelease, even after JS overwrites it.
    literal_output_backing: Option<Reservation>,
    ticks: usize,
    exception: Value,
    started: Instant,
    entry_remaining_us: u128,
    phase: &'static str,
    phase_start_us: u128,
    stage_us: [u128; 6],
    #[cfg(feature = "http-diagnostics")]
    stages_seen: u8,
    first_stop: Option<StopEvidence>,
}
#[derive(Clone, Copy)]
struct StopEvidence {
    cause: &'static str,
    phase: &'static str,
    ticks: usize,
    elapsed_us: u128,
    phase_elapsed_us: u128,
}
thread_local! { static EXECUTION: RefCell<Option<Execution>> = const { RefCell::new(None) }; }
#[cfg(test)]
thread_local! {
    static LAST_TICKS_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
thread_local! {
    static FORCE_UTF16_INPUT_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(super) struct InputConstructorControl(bool);
#[cfg(test)]
impl Drop for InputConstructorControl {
    fn drop(&mut self) {
        FORCE_UTF16_INPUT_FOR_TEST.with(|slot| slot.set(self.0));
    }
}
#[cfg(test)]
pub(super) fn force_utf16_input_for_test() -> InputConstructorControl {
    // These differential tests deliberately execute on the test's current
    // thread, where the same real adapter reads this test-only override.
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread
    );
    InputConstructorControl(FORCE_UTF16_INPUT_FOR_TEST.with(|slot| slot.replace(true)))
}
#[cfg(test)]
pub(super) fn last_ticks_for_test() -> Option<usize> {
    LAST_TICKS_FOR_TEST.with(std::cell::Cell::get)
}
#[cfg(test)]
thread_local! {
    static FIRST_TICK_FOR_TEST: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn on_first_tick_for_test(hook: impl FnOnce() + 'static) {
    FIRST_TICK_FOR_TEST.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}
#[cfg(test)]
thread_local! {
    static CONTEXT_RELEASE_FOR_TEST: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}
#[cfg(test)]
pub(super) fn on_context_release_for_test(observer: impl FnOnce() + 'static) {
    CONTEXT_RELEASE_FOR_TEST.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(observer));
    });
}
struct ExecutionGuard {
    #[cfg(feature = "http-diagnostics")]
    succeeded: bool,
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        EXECUTION.with(|s| {
            #[cfg(feature = "http-diagnostics")]
            if let Some(state) = s.borrow_mut().as_mut() {
                let elapsed = state.started.elapsed().as_micros();
                let mut stages = state.stage_us;
                if let Some(slot) = stage_slot(state.phase) {
                    stages[slot] =
                        stages[slot].saturating_add(elapsed.saturating_sub(state.phase_start_us));
                }
                super::super::diagnostics::evaluation_finished(
                    stages,
                    state.stages_seen,
                    elapsed,
                    state.ticks,
                    self.succeeded,
                );
            }
            #[cfg(test)]
            LAST_TICKS_FOR_TEST.with(|ticks| {
                ticks.set(s.borrow().as_ref().map(|state| state.ticks));
            });
            #[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
            VALIDATION_TRACE.with(|slot| {
                if let (Some(trace), Some(state)) =
                    (slot.borrow_mut().as_mut(), s.borrow().as_ref())
                {
                    trace.ticks = Some(state.ticks);
                }
            });
            s.replace(None);
        });
    }
}

unsafe extern "C" fn tick(
    ctx: Context,
    _: Object,
    _: Object,
    _: usize,
    _: *const Value,
    exception: *mut Value,
) -> Value {
    #[cfg(test)]
    FIRST_TICK_FOR_TEST.with(|slot| {
        let hook = slot.borrow_mut().take();
        if let Some(hook) = hook {
            hook();
        }
    });
    let error = EXECUTION.with(|cell| {
        let mut state = cell.borrow_mut();
        let state = state.as_mut()?;
        state.ticks += 1;
        // Preserve the existing short-circuit order and one clock read on
        // a healthy tick. Evidence and its clock read exist only on failure.
        let cause = if state.cancellation.is_cancelled() {
            Some("cancel")
        } else if state.ticks > 100_000 {
            Some("ticks")
        } else if Instant::now() >= state.deadline {
            Some("deadline")
        } else {
            None
        };
        if let Some(cause) = cause {
            if state.first_stop.is_none() {
                let elapsed_us = state.started.elapsed().as_micros();
                state.first_stop = Some(StopEvidence {
                    cause,
                    phase: state.phase,
                    ticks: state.ticks,
                    elapsed_us,
                    phase_elapsed_us: elapsed_us.saturating_sub(state.phase_start_us),
                });
            }
            Some(state.exception)
        } else {
            None
        }
    });
    if let Some(error) = error {
        // The exception is allocated and rooted before running user code, so
        // cancellation itself cannot fail because a new string needs memory.
        unsafe { *exception = error };
    }
    unsafe { JSValueMakeUndefined(ctx) }
}

// Private trusted-prelude ABI: (primitive string, that same string's length).
// The frontend cannot name this helper and strings cannot change between the
// two argument evaluations. Return undefined to retain the original regex
// predicate whenever additional bridge payload cannot be admitted or viewed.
unsafe extern "C" fn is_ascii(
    ctx: Context,
    _: Object,
    _: Object,
    count: usize,
    args: *const Value,
    _: *mut Value,
) -> Value {
    let unavailable = || unsafe { JSValueMakeUndefined(ctx) };
    if count != 2 || args.is_null() {
        return unavailable();
    }
    let value = unsafe { *args };
    let declared_length = unsafe { *args.add(1) };
    if value.is_null()
        || declared_length.is_null()
        || !unsafe { JSValueIsString(ctx, value) }
        || !unsafe { JSValueIsNumber(ctx, declared_length) }
    {
        return unavailable();
    }
    let mut conversion_exception = ptr::null();
    let declared_length =
        unsafe { JSValueToNumber(ctx, declared_length, &mut conversion_exception) };
    if !conversion_exception.is_null()
        || !declared_length.is_finite()
        || declared_length < 0.0
        || declared_length.fract() != 0.0
        || declared_length > super::super::body_budget::MAX_BODY as f64
    {
        return unavailable();
    }
    let length = declared_length as usize;
    let Some(payload) = length.checked_mul(3) else {
        return unavailable();
    };
    let reservation = EXECUTION.with(|cell| {
        let state = cell.borrow();
        let state = state.as_ref()?;
        use super::super::diagnostics::{Counter, increment};
        increment(Counter::AsciiViewRequested);
        let extra = payload.saturating_sub(state.available_view());
        if extra == 0 {
            increment(Counter::AsciiViewAdmitted);
            return Some(None);
        }
        match state.ascii_view_budget.reserve(extra) {
            Some(reservation) => {
                increment(Counter::AsciiViewAdmitted);
                Some(Some(reservation))
            }
            None => {
                increment(Counter::AsciiViewBudgetFallback);
                None
            }
        }
    });
    // Any extra guard is declared before StringRef: release the API copy
    // and expansion first. The prepaid slot remains held by the caller and
    // is reused sequentially by export, never by retained input backing.
    let Some(_reservation) = reservation else {
        return unavailable();
    };
    #[cfg(test)]
    let _owner_observer = AsciiOwnerObserver;
    #[cfg(test)]
    bridge_event(BridgeEvent::AsciiCopyStart);
    let text = StringRef(unsafe { JSValueToStringCopy(ctx, value, &mut conversion_exception) });
    if !conversion_exception.is_null() || text.0.is_null() {
        return unavailable();
    }
    if unsafe { JSStringGetLength(text.0) } != length {
        return unavailable();
    }
    if length == 0 {
        return unsafe { JSValueMakeBoolean(ctx, true) };
    }
    let units = unsafe { JSStringGetCharactersPtr(text.0) };
    if units.is_null() {
        return unavailable();
    }
    // Public JSC can copy N bytes and expand 2N more for an 8-bit source.
    // The separate view slot or extra reservation covers character payload,
    // not VM heap/metadata. The retained 2I input allocation is never reused.
    let ascii = unsafe { slice::from_raw_parts(units, length) }
        .iter()
        .all(|unit| *unit <= 0x7f);
    unsafe { JSValueMakeBoolean(ctx, ascii) }
}

// Private trusted-prelude ABI: (primitive string, that string's length,
// ASCII search code unit, ASCII replacement code unit). No value conversion
// can invoke user code. Return undefined to keep the original JS operation.
unsafe extern "C" fn replace_ascii_literal_all(
    ctx: Context,
    _: Object,
    _: Object,
    count: usize,
    args: *const Value,
    _: *mut Value,
) -> Value {
    let unavailable = || unsafe { JSValueMakeUndefined(ctx) };
    if count != 4 || args.is_null() {
        return unavailable();
    }
    let value = unsafe { *args };
    if value.is_null() || !unsafe { JSValueIsString(ctx, value) } {
        return unavailable();
    }
    let mut numbers = [0usize; 3];
    for (index, maximum) in [super::super::body_budget::MAX_BODY, 127, 127]
        .into_iter()
        .enumerate()
    {
        let argument = unsafe { *args.add(index + 1) };
        if argument.is_null() || !unsafe { JSValueIsNumber(ctx, argument) } {
            return unavailable();
        }
        let mut exception = ptr::null();
        let number = unsafe { JSValueToNumber(ctx, argument, &mut exception) };
        if !exception.is_null()
            || !number.is_finite()
            || number < 0.0
            || number.fract() != 0.0
            || number > maximum as f64
        {
            return unavailable();
        }
        numbers[index] = number as usize;
    }
    let [length, search, replacement] = numbers;
    if length < 4096 || replacement == usize::from(b'$') {
        return unavailable();
    }
    diagnostics::increment(Counter::LiteralReplaceRequested);
    let Some(temporary_payload) = length
        .checked_mul(5)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u16>>()))
    else {
        return unavailable();
    };
    let Some(retained_payload) = length.checked_mul(2) else {
        return unavailable();
    };
    let admission = EXECUTION.with(|cell| {
        let state = cell.borrow();
        let state = state.as_ref()?;
        // Retained and temporary slices must fit simultaneously. Reservation
        // failures occur before any API copy. No primitive API here reenters JS.
        let borrowed_retained = retained_payload.min(state.available_retained_view());
        let temporary_extra =
            temporary_payload.saturating_sub(state.available_view() - borrowed_retained);
        let retained_extra = retained_payload - borrowed_retained;
        let temporary = if temporary_extra == 0 {
            None
        } else {
            Some(state.ascii_view_budget.reserve(temporary_extra)?)
        };
        let retained = if retained_extra == 0 {
            None
        } else {
            Some(state.ascii_view_budget.reserve(retained_extra)?)
        };
        Some((temporary, retained, borrowed_retained))
    });
    // Both guards precede every API copy and the host UTF-16 Vec. Any API
    // owner and Vec are dropped before the temporary guard on every exit.
    let Some((_temporary, retained, borrowed_retained)) = admission else {
        diagnostics::increment(Counter::LiteralReplaceBudgetFallback);
        return unavailable();
    };
    #[cfg(test)]
    let _temporary_owner_observer = NativeOwnerObserver;
    #[cfg(test)]
    bridge_event(BridgeEvent::NativeCopyStart);
    let mut conversion_exception = ptr::null();
    let text = StringRef(unsafe { JSValueToStringCopy(ctx, value, &mut conversion_exception) });
    if !conversion_exception.is_null()
        || text.0.is_null()
        || unsafe { JSStringGetLength(text.0) } != length
    {
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    let units = unsafe { JSStringGetCharactersPtr(text.0) };
    if units.is_null() {
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    // The slice is used only while its StringRef owner remains in this scope.
    // All input is checked before allocating or exposing a replacement value.
    let units = unsafe { slice::from_raw_parts(units, length) };
    let mut matches = 0usize;
    for unit in units {
        if *unit > 0x7f {
            diagnostics::increment(Counter::LiteralReplaceSemanticFallback);
            return unavailable();
        }
        matches += usize::from(usize::from(*unit) == search);
    }
    // Sparse/no-match input keeps JSC's very cheap native string intrinsic.
    // This is an eligibility threshold, not a measured crossover claim.
    if matches < length.div_ceil(16) {
        diagnostics::increment(Counter::LiteralReplaceSemanticFallback);
        return unavailable();
    }
    let mut output_units = Vec::new();
    if output_units.try_reserve_exact(length).is_err() || output_units.capacity() != length {
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    output_units.extend(units.iter().map(|unit| {
        if usize::from(*unit) == search {
            replacement as u16
        } else {
            *unit
        }
    }));
    // The last units read has completed. End the 3N input API view before
    // creating output API2N and any JSValueMakeString VM isolated copy2N.
    // Peak is then max(3N+Vec2N, Vec2N+API2N+VM2N) <= T5N+R2N.
    drop(text);
    #[cfg(test)]
    bridge_event(BridgeEvent::NativeInputOwnerDropped);
    // Commit only at the actual output API allocation boundary. Earlier
    // semantic/copy fallbacks refund this unused retained plan. From here on,
    // even allocation failure keeps borrowed and extra payload until ctx drop.
    let committed = EXECUTION.with(|cell| {
        let mut state = cell.borrow_mut();
        let Some(state) = state.as_mut() else {
            return false;
        };
        if borrowed_retained > state.available_retained_view() {
            return false;
        }
        if let Some(retained) = retained {
            if let Some(previous) = state.literal_output_backing.as_mut() {
                if previous.merge(retained).is_err() {
                    return false;
                }
            } else {
                state.literal_output_backing = Some(retained);
            }
        }
        state.retained_borrowed += borrowed_retained;
        true
    });
    if !committed {
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    #[cfg(test)]
    bridge_event(BridgeEvent::NativeRetainedCommitted);
    let output = StringRef(unsafe {
        JSStringCreateWithCharacters(output_units.as_ptr(), output_units.len())
    });
    if output.0.is_null() {
        // The conservative retained reservation still expires at context
        // release, including this allocation-failure path.
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    let result = unsafe { JSValueMakeString(ctx, output.0) };
    if result.is_null() {
        diagnostics::increment(Counter::LiteralReplaceApiFallback);
        return unavailable();
    }
    diagnostics::increment(Counter::LiteralReplaceAdmitted);
    result
}

// Successful evaluations emit no diagnostics. A check-based classification
// is kept distinct from the first native callback that requested a stop.
fn execution_error(
    state: &Execution,
    kind: io::ErrorKind,
    origin: &'static str,
    classification: &'static str,
) -> io::Error {
    let elapsed_us = state.started.elapsed().as_micros();
    let first = state.first_stop.unwrap_or(StopEvidence {
        cause: classification,
        phase: state.phase,
        ticks: state.ticks,
        elapsed_us,
        phase_elapsed_us: elapsed_us.saturating_sub(state.phase_start_us),
    });
    let first_trigger = if state.first_stop.is_some() {
        "callback"
    } else {
        origin
    };
    let stages = state.stage_us.map(diagnostic_us);
    io::Error::new(
        kind,
        format!(
            "js f={first_trigger} c={} p={} t={} e={} pe={} o={origin} k={classification} a={} r={} stage_us={},{},{},{},{},{}",
            first.cause,
            first.phase,
            first.ticks,
            diagnostic_us(first.elapsed_us),
            diagnostic_us(first.phase_elapsed_us),
            diagnostic_us(elapsed_us),
            diagnostic_us(state.entry_remaining_us),
            stages[0],
            stages[1],
            stages[2],
            stages[3],
            stages[4],
            stages[5],
        ),
    )
}
// Presentation-only saturation keeps every diagnostic below the host's
// 256-byte UTF-8 message cap. Execution clocks and limits remain unchanged.
fn diagnostic_us(value: u128) -> u32 {
    value.min(u128::from(u32::MAX)) as u32
}
fn stage_slot(phase: &str) -> Option<usize> {
    match phase {
        "context" => Some(0),
        "prelude" => Some(1),
        "program" => Some(2),
        "input" => Some(3),
        "invoke" => Some(4),
        "export" => Some(5),
        _ => None,
    }
}
fn execution_phase(phase: &'static str) {
    EXECUTION.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            // Reuse the phase transition's existing clock reading. The fixed
            // array holds completed context/prelude/program/input/invoke/export.
            let elapsed_us = state.started.elapsed().as_micros();
            let slot = stage_slot(state.phase);
            if let Some(slot) = slot {
                state.stage_us[slot] = state.stage_us[slot]
                    .saturating_add(elapsed_us.saturating_sub(state.phase_start_us));
            }
            state.phase = phase;
            state.phase_start_us = elapsed_us;
            #[cfg(feature = "http-diagnostics")]
            if let Some(slot) = stage_slot(phase) {
                state.stages_seen |= 1 << slot;
            }
        }
    });
}
fn stopped(kind: io::ErrorKind, origin: &'static str, cause: &'static str) -> io::Error {
    EXECUTION.with(|cell| {
        let state = cell.borrow();
        state.as_ref().map_or_else(
            || io::Error::from(kind),
            |s| execution_error(s, kind, origin, cause),
        )
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn utf8_length(units: &[u16], limit: usize) -> io::Result<usize> {
    let mut length = 0usize;
    for ch in char::decode_utf16(units.iter().copied()) {
        length = length
            .checked_add(ch.map_err(|_| invalid("invalid UTF-16"))?.len_utf8())
            .filter(|v| *v <= limit)
            .ok_or_else(|| invalid("script result is too large"))?;
    }
    Ok(length)
}
fn check(exception: Value) -> io::Result<()> {
    if exception.is_null() {
        return Ok(());
    }
    EXECUTION.with(|cell| {
        let state = cell.borrow();
        let Some(state) = state.as_ref() else {
            return Err(invalid("JavaScript evaluation failed"));
        };
        if state.cancellation.is_cancelled() {
            Err(execution_error(
                state,
                io::ErrorKind::Interrupted,
                "exception-check",
                "cancel",
            ))
        } else if state.ticks > 100_000 {
            Err(execution_error(
                state,
                io::ErrorKind::TimedOut,
                "exception-check",
                "ticks",
            ))
        } else if Instant::now() >= state.deadline {
            // This says when the exception was classified, not that the
            // exception itself was necessarily thrown by the tick callback.
            Err(execution_error(
                state,
                io::ErrorKind::TimedOut,
                "exception-check",
                "deadline",
            ))
        } else {
            Err(invalid("JavaScript evaluation failed"))
        }
    })
}
fn property(ctx: Context, object: Object, name: &str) -> io::Result<Value> {
    let key = StringRef::new(name)?;
    let mut exception = ptr::null();
    let value = unsafe { JSObjectGetProperty(ctx, object, key.0, &mut exception) };
    check(exception)?;
    Ok(value)
}
fn object(ctx: Context, value: Value) -> io::Result<Object> {
    let mut exception = ptr::null();
    let value = unsafe { JSValueToObject(ctx, value, &mut exception) };
    check(exception)?;
    if value.is_null() {
        return Err(invalid("object required"));
    }
    Ok(value)
}
fn set(ctx: Context, object: Object, name: &str, value: Value) -> io::Result<()> {
    let _value = Rooted::new(ctx, value)?;
    let key = StringRef::new(name)?;
    let mut exception = ptr::null();
    unsafe { JSObjectSetProperty(ctx, object, key.0, value, 0, &mut exception) };
    check(exception)
}
fn script(ctx: Context, source: &str) -> io::Result<Value> {
    let source = StringRef::new(source)?;
    let mut exception = ptr::null();
    let result = unsafe {
        JSEvaluateScript(
            ctx,
            source.0,
            ptr::null_mut(),
            ptr::null_mut(),
            1,
            &mut exception,
        )
    };
    check(exception)?;
    Ok(result)
}
fn call(ctx: Context, global: Object, name: &str, input: Value) -> io::Result<Rooted> {
    let _input = Rooted::new(ctx, input)?;
    let function = object(ctx, property(ctx, global, name)?)?;
    let mut exception = ptr::null();
    let result = unsafe {
        JSObjectCallAsFunction(ctx, function, ptr::null_mut(), 1, &input, &mut exception)
    };
    check(exception)?;
    Rooted::new(ctx, result)
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
    if cancellation.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "js f=entry-check c=cancel p=context t=0 e=0 pe=0 o=entry-check k=cancel a=0 r=0 stage_us=0,0,0,0,0,0",
        ));
    }
    // This guard is declared before the context and therefore remains held
    // through JSGlobalContextRelease. Direct adapter tests use the same ledger
    // as production CallBuffers; they cannot omit bridge admission.
    let output_bound = program.maximum_output_bytes(input.map_or(0, <[u8]>::len));
    let plan = input
        .map(|bytes| {
            BridgePlan::new(
                bytes.len(),
                metadata["body"]["kind"] == "text",
                output_bound,
            )
            .ok_or_else(|| invalid("invalid bridge input"))
        })
        .transpose()?;
    let required = plan.and_then(BridgePlan::cost);
    let local_bridge = if let Some(prepaid) = bridge_workspace {
        if !prepaid.covers(output, required.unwrap_or(0)) {
            diagnostics::increment(Counter::BridgeGuardInvalid);
            return Err(invalid("invalid bridge reservation"));
        }
        None
    } else if let Some(required) = required {
        Some(output.reserve_temporary(required).ok_or_else(|| {
            diagnostics::increment(Counter::BridgeInputRejected);
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "HTTP script bridge workspace exceeded",
            )
        })?)
    } else {
        None
    };
    // This owner remains declared before ExecutionGuard and ContextRef. Its
    // complete slot (including borrowed retained slices) outlives actual ctx.
    let _bridge_workspace = bridge_workspace.or(local_bridge.as_ref());
    let started = Instant::now();
    EXECUTION.with(|s| {
        s.replace(Some(Execution {
            deadline,
            cancellation: cancellation.clone(),
            ascii_view_budget: output.budget().clone(),
            prepaid_view_capacity: plan.map_or(0, |plan| plan.view_capacity),
            prepaid_export_floor: plan.map_or(0, |_| 3 * output_bound),
            retained_borrowed: 0,
            literal_output_backing: None,
            ticks: 0,
            exception: ptr::null(),
            started,
            entry_remaining_us: deadline.saturating_duration_since(started).as_micros(),
            phase: "context",
            phase_start_us: 0,
            stage_us: [0; 6],
            #[cfg(feature = "http-diagnostics")]
            stages_seen: 1,
            first_stop: None,
        }));
    });
    #[cfg(feature = "http-diagnostics")]
    let mut _execution = ExecutionGuard { succeeded: false };
    #[cfg(not(feature = "http-diagnostics"))]
    let _execution = ExecutionGuard {};
    let ctx = ContextRef(unsafe { JSGlobalContextCreate(ptr::null()) });
    if ctx.0.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    super::super::diagnostics::context_created();
    #[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
    let _validation_context = ValidationContextProbe(ctx.0);
    #[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
    VALIDATION_TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.context_created = true;
        }
    });
    let failure = StringRef::new("script execution cancelled or budget exceeded")?;
    let failure = Rooted::new(ctx.0, unsafe { JSValueMakeString(ctx.0, failure.0) })?;
    EXECUTION.with(|s| {
        if let Some(state) = s.borrow_mut().as_mut() {
            state.exception = failure.value;
        }
    });
    let global = unsafe { JSContextGetGlobalObject(ctx.0) };
    let name = StringRef::new("__voleTick")?;
    let function = unsafe { JSObjectMakeFunctionWithCallback(ctx.0, name.0, Some(tick)) };
    set(ctx.0, global, "__voleTick", function.cast_const())?;
    let name = StringRef::new("__voleIsASCII")?;
    let function = unsafe { JSObjectMakeFunctionWithCallback(ctx.0, name.0, Some(is_ascii)) };
    if function.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    set(ctx.0, global, "__voleIsASCII", function.cast_const())?;
    let name = StringRef::new("__voleReplaceASCIIAll")?;
    let function =
        unsafe { JSObjectMakeFunctionWithCallback(ctx.0, name.0, Some(replace_ascii_literal_all)) };
    if function.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    set(
        ctx.0,
        global,
        "__voleReplaceASCIIAll",
        function.cast_const(),
    )?;
    execution_phase("prelude");
    script(ctx.0, include_str!("runtime.js"))?;
    #[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
    VALIDATION_TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.prelude_loaded = true;
        }
    });
    execution_phase("program");
    script(ctx.0, &program.code)?;
    execution_phase("input");
    let json = serde_json::to_string(metadata).map_err(|_| invalid("invalid script metadata"))?;
    if json.len() > 1024 * 1024 {
        return Err(invalid("script metadata limit"));
    }
    let json = StringRef::new(&json)?;
    let input_value = unsafe { JSValueMakeFromJSONString(ctx.0, json.0) };
    if input_value.is_null() {
        return Err(invalid("invalid script input"));
    }
    let input_root = Rooted::new(ctx.0, input_value)?;
    let input_object = object(ctx.0, input_value)?;
    if let Some(input) = input {
        let body = object(ctx.0, property(ctx.0, input_object, "body")?)?;
        let value = if metadata["body"]["kind"] == "text" {
            let text = std::str::from_utf8(input).map_err(|_| invalid("body is not UTF-8"))?;
            let plan = plan.ok_or_else(|| invalid("missing input bridge plan"))?;
            // UTF8 worst-case extra is CString(I+1)+decoder Vec(2I).
            // MAX uses UTF16 rather than borrowing the separately paid input2I.
            let text = StringRef::text(text, plan.allows_utf8_input(input.len()))?;
            unsafe { JSValueMakeString(ctx.0, text.0) }
        } else {
            let mut exception = ptr::null();
            // JSTypedArrayType Uint8Array = 3 in the public SDK enum.
            let array = unsafe { JSObjectMakeTypedArray(ctx.0, 3, input.len(), &mut exception) };
            check(exception)?;
            if array.is_null() {
                return Err(io::ErrorKind::OutOfMemory.into());
            }
            let array_root = Rooted::new(ctx.0, array.cast_const())?;
            let buffer = unsafe { JSObjectGetTypedArrayBuffer(ctx.0, array, &mut exception) };
            check(exception)?;
            let data = unsafe { JSObjectGetArrayBufferBytesPtr(ctx.0, buffer, &mut exception) };
            check(exception)?;
            if !input.is_empty() {
                if data.is_null() {
                    return Err(invalid("invalid typed array allocation"));
                }
                unsafe { ptr::copy_nonoverlapping(input.as_ptr(), data.cast::<u8>(), input.len()) };
            }
            set(ctx.0, body, "data", array.cast_const())?;
            drop(array_root);
            array.cast_const()
        };
        set(ctx.0, body, "data", value)?;
    }
    execution_phase("invoke");
    let rewritten = call(ctx.0, global, "rewrite", input_value)?;
    let result_root = call(ctx.0, global, "__voleFinish", rewritten.value)?;
    execution_phase("export");
    drop(rewritten);
    drop(input_root);
    let result = result_root.value;
    let record = object(ctx.0, result)?;
    if let Some(kind) = output_kind(ctx.0, record)? {
        let body = object(ctx.0, property(ctx.0, record, "body")?)?;
        let data = property(ctx.0, body, "data")?;
        export_body(ctx.0, kind.as_str(), data, output, output_bound)?;
        let key = StringRef::new("data")?;
        let mut exception = ptr::null();
        if !unsafe { JSObjectDeleteProperty(ctx.0, body, key.0, &mut exception) } {
            return Err(invalid("body data is not exportable"));
        }
        check(exception)?;
    }
    let mut exception = ptr::null();
    let encoded = StringRef(unsafe { JSValueCreateJSONString(ctx.0, result, 0, &mut exception) });
    check(exception)?;
    if encoded.0.is_null() {
        return Err(invalid("invalid result encoding"));
    }
    let encoded = encoded.to_string_checked(256 * 1024)?;
    execution_phase("final-check");
    if cancellation.is_cancelled() {
        return Err(stopped(io::ErrorKind::Interrupted, "final-check", "cancel"));
    }
    if Instant::now() >= deadline {
        return Err(stopped(io::ErrorKind::TimedOut, "final-check", "deadline"));
    }
    #[cfg(feature = "http-diagnostics")]
    let parse_started = Instant::now();
    let result = serde_json::from_str(&encoded).map_err(|_| invalid("invalid result encoding"));
    #[cfg(feature = "http-diagnostics")]
    {
        super::super::diagnostics::timing(
            super::super::diagnostics::Timing::FinalParse,
            parse_started.elapsed().as_micros(),
        );
        _execution.succeeded = result.is_ok();
    }
    result
}

fn output_kind(ctx: Context, record: Object) -> io::Result<Option<String>> {
    let value = property(ctx, record, "body")?;
    if unsafe { JSValueIsUndefined(ctx, value) } {
        return Ok(None);
    }
    let mut exception = ptr::null();
    let body = object(ctx, value)?;
    let kind = property(ctx, body, "kind")?;
    if !unsafe { JSValueIsString(ctx, kind) } {
        return Err(invalid("invalid body kind"));
    }
    let kind = StringRef(unsafe { JSValueToStringCopy(ctx, kind, &mut exception) });
    check(exception)?;
    if kind.0.is_null() {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    let kind = kind.to_string_checked(16)?;
    if kind != "text" && kind != "bytes" {
        return Err(invalid("invalid body kind"));
    }
    Ok(Some(kind))
}

impl Execution {
    fn available_view(&self) -> usize {
        self.prepaid_view_capacity - self.retained_borrowed
    }
    fn available_retained_view(&self) -> usize {
        self.available_view()
            .saturating_sub(self.prepaid_export_floor)
    }
}
// Primitive-string APIs do not call user code; no borrowed temporary view can
// overlap another callback. Retained slices are deducted permanently below.
fn reserve_view(payload: usize) -> Option<Option<Reservation>> {
    EXECUTION.with(|cell| {
        let state = cell.borrow();
        let state = state.as_ref()?;
        let extra = payload.saturating_sub(state.available_view());
        if extra == 0 {
            Some(None)
        } else {
            state.ascii_view_budget.reserve(extra).map(Some)
        }
    })
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BridgeEvent {
    InputUtf8Start,
    InputUtf16Start,
    AsciiCopyStart,
    AsciiOwnerDropped,
    NativeCopyStart,
    NativeInputOwnerDropped,
    NativeRetainedCommitted,
    NativeOwnersDropped,
    ExportCopyStart,
    ExportOwnerDropped,
}
#[cfg(test)]
thread_local! { static BRIDGE_EVENT: RefCell<Option<Box<dyn FnMut(BridgeEvent)>>> = const { RefCell::new(None) }; }
#[cfg(test)]
pub(super) fn observe_bridge_for_test(observer: impl FnMut(BridgeEvent) + 'static) {
    BRIDGE_EVENT.with(|slot| *slot.borrow_mut() = Some(Box::new(observer)));
}
#[cfg(test)]
fn bridge_event(event: BridgeEvent) {
    BRIDGE_EVENT.with(|slot| {
        if let Some(observer) = slot.borrow_mut().as_mut() {
            observer(event);
        }
    });
}
#[cfg(test)]
pub(super) fn bridge_view_for_test() -> (usize, usize) {
    EXECUTION.with(|cell| {
        let state = cell.borrow();
        let state = state.as_ref().unwrap();
        (state.prepaid_view_capacity, state.retained_borrowed)
    })
}
#[cfg(test)]
struct AsciiOwnerObserver;
#[cfg(test)]
impl Drop for AsciiOwnerObserver {
    fn drop(&mut self) {
        bridge_event(BridgeEvent::AsciiOwnerDropped);
    }
}
#[cfg(test)]
struct NativeOwnerObserver;
#[cfg(test)]
impl Drop for NativeOwnerObserver {
    fn drop(&mut self) {
        bridge_event(BridgeEvent::NativeOwnersDropped);
    }
}
#[cfg(test)]
struct ExportOwnerObserver;
#[cfg(test)]
impl Drop for ExportOwnerObserver {
    fn drop(&mut self) {
        bridge_event(BridgeEvent::ExportOwnerDropped);
    }
}
// Called only after trusted Finish. Native rechecks the primitive types;
// no String object/ToPrimitive conversion or API character copy precedes 3N.
fn export_text_units(ctx: Context, data: Value) -> io::Result<usize> {
    if !unsafe { JSValueIsString(ctx, data) } {
        return Err(invalid("text body required"));
    }
    let global = unsafe { JSContextGetGlobalObject(ctx) };
    let length = call(ctx, global, "__voleExportTextUnits", data)?;
    if !unsafe { JSValueIsNumber(ctx, length.value) } {
        return Err(invalid("invalid text unit count"));
    }
    let mut exception = ptr::null();
    let length = unsafe { JSValueToNumber(ctx, length.value, &mut exception) };
    check(exception)?;
    if !length.is_finite()
        || length < 0.0
        || length.fract() != 0.0
        || length > super::super::body_budget::MAX_BODY as f64
    {
        return Err(invalid("invalid text unit count"));
    }
    Ok(length as usize)
}

fn export_body(
    ctx: Context,
    kind: &str,
    data: Value,
    output: &mut BudgetedBytes,
    output_bound: usize,
) -> io::Result<()> {
    let mut exception = ptr::null();
    if kind == "text" {
        let expected_units = export_text_units(ctx, data)?;
        if expected_units > output_bound {
            return Err(invalid("text exceeded proven output bound"));
        }
        if expected_units == 0 {
            output.prepare_output(0)?;
            return Ok(());
        }
        let payload = expected_units
            .checked_mul(3)
            .filter(|n| *n <= API_TEXT_VIEW)
            .ok_or_else(|| invalid("invalid text view payload"))?;
        let _view_reservation = reserve_view(payload).ok_or_else(|| {
            diagnostics::increment(Counter::BridgeExportRejected);
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "HTTP script bridge workspace exceeded",
            )
        })?;
        #[cfg(test)]
        let _owner_observer = ExportOwnerObserver;
        #[cfg(test)]
        bridge_event(BridgeEvent::ExportCopyStart);
        // Declared after the permit: all exits release the API owner first.
        let text = StringRef(unsafe { JSValueToStringCopy(ctx, data, &mut exception) });
        check(exception)?;
        if text.0.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        if unsafe { JSStringGetLength(text.0) } != expected_units {
            return Err(invalid("text unit count changed before export"));
        }
        let units = text.units();
        let length = units.len();
        if length < super::super::body_budget::MAX_BODY
            && output.as_ref().is_empty()
            && output.remaining() > length
            && units.iter().all(|unit| (1..=0x7f).contains(unit))
        {
            // ASCII excludes every surrogate. Reserve no extra storage: the
            // public API's trailing NUL fits in already admitted capacity.
            // Embedded NUL and MAX_BODY stay on the strict original path.
            output.write_initialized_output(length + 1, |buffer| {
                let written = unsafe {
                    JSStringGetUTF8CString(text.0, buffer.as_mut_ptr().cast(), buffer.len())
                };
                if written != buffer.len() || buffer[length] != 0 {
                    return Err(invalid("incomplete ASCII body export"));
                }
                Ok(length)
            })?;
            return Ok(());
        }
        let length = utf8_length(units, output_bound)?;
        output.prepare_output(length)?;
        for ch in char::decode_utf16(units.iter().copied()) {
            let mut bytes = [0u8; 4];
            output.extend(
                ch.map_err(|_| invalid("invalid body text"))?
                    .encode_utf8(&mut bytes)
                    .as_bytes(),
            )?;
        }
    } else {
        let kind = unsafe { JSValueGetTypedArrayType(ctx, data, &mut exception) };
        check(exception)?;
        // The public SDK has Uint8Array=3 and ArrayBuffer=9.
        if kind != 3 && kind != 9 {
            return Err(invalid("Uint8Array or ArrayBuffer required"));
        }
        let array = object(ctx, data)?;
        let (buffer, offset, length) = if kind == 3 {
            let length = unsafe { JSObjectGetTypedArrayByteLength(ctx, array, &mut exception) };
            check(exception)?;
            let offset = unsafe { JSObjectGetTypedArrayByteOffset(ctx, array, &mut exception) };
            check(exception)?;
            let buffer = unsafe { JSObjectGetTypedArrayBuffer(ctx, array, &mut exception) };
            check(exception)?;
            (buffer, offset, length)
        } else {
            let length = unsafe { JSObjectGetArrayBufferByteLength(ctx, array, &mut exception) };
            check(exception)?;
            (array, 0, length)
        };
        if length > output_bound {
            return Err(invalid("bytes exceeded proven output bound"));
        }
        output.prepare_output(length)?;
        let capacity = unsafe { JSObjectGetArrayBufferByteLength(ctx, buffer, &mut exception) };
        check(exception)?;
        if offset.checked_add(length).is_none_or(|end| end > capacity) {
            return Err(invalid("invalid bytes view"));
        }
        let bytes = unsafe { JSObjectGetArrayBufferBytesPtr(ctx, buffer, &mut exception) };
        check(exception)?;
        if length != 0 {
            if bytes.is_null() {
                return Err(invalid("invalid bytes backing"));
            }
            output
                .extend(unsafe { slice::from_raw_parts(bytes.cast::<u8>().add(offset), length) })?;
        }
    }
    Ok(())
}

// Explicit Apple diagnostic only. Normal evaluations never evaluate this probe.
#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ValidationTrace {
    pub(super) ticks: Option<usize>,
    pub(super) allocation_work: Option<usize>,
    pub(super) context_created: bool,
    pub(super) prelude_loaded: bool,
    pub(super) context_released: bool,
}
#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
thread_local! {
    static VALIDATION_TRACE: RefCell<Option<ValidationTrace>> = const { RefCell::new(None) };
}
#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
struct ValidationContextProbe(Context);
#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
impl Drop for ValidationContextProbe {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let enabled = VALIDATION_TRACE.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|trace| trace.prelude_loaded)
        });
        if !enabled {
            return;
        }
        // __voleAllocated is a trusted global lexical, not a global-object
        // property. No tick/Charge/user source runs; probe errors never replace
        // the original result. Missing/failed reads remain explicitly None.
        let work = (|| -> Option<usize> {
            let value = script(self.0, "__voleAllocated").ok()?;
            if !unsafe { JSValueIsNumber(self.0, value) } {
                return None;
            }
            let mut exception = ptr::null();
            let number = unsafe { JSValueToNumber(self.0, value, &mut exception) };
            if !exception.is_null()
                || !number.is_finite()
                || number.fract() != 0.0
                || !(0.0..=2097152.0).contains(&number)
            {
                return None;
            }
            Some(number as usize)
        })();
        VALIDATION_TRACE.with(|slot| {
            if let Some(trace) = slot.borrow_mut().as_mut() {
                trace.allocation_work = work;
            }
        });
    }
}
#[cfg(all(feature = "http-diagnostics", target_vendor = "apple"))]
pub(super) fn evaluate_for_validation(
    program: &CompiledSource,
    metadata: &serde_json::Value,
    input: Option<&[u8]>,
    output: &mut BudgetedBytes,
    bridge: Option<&Reservation>,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> (io::Result<serde_json::Value>, ValidationTrace) {
    struct Capture;
    impl Drop for Capture {
        fn drop(&mut self) {
            VALIDATION_TRACE.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    let occupied = VALIDATION_TRACE.with(|slot| {
        let occupied = slot.borrow().is_some();
        if !occupied {
            slot.replace(Some(ValidationTrace::default()));
        }
        occupied
    });
    if occupied {
        return (
            Err(io::ErrorKind::WouldBlock.into()),
            ValidationTrace::default(),
        );
    }
    let _capture = Capture;
    let result = evaluate(
        program,
        metadata,
        input,
        output,
        bridge,
        cancellation,
        deadline,
    );
    let trace = VALIDATION_TRACE
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    (result, trace)
}
