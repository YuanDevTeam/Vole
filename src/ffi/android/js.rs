//! AndroidX owns the sandbox. This JNI boundary owns the host reference and
//! admits at most one binary result for the current call.

use super::{
    JAVA_VM, JBoolean, JByteArray, JInt, JLong, JMethodId, JNI_FALSE, JNI_TRUE, JObject, JValue,
    JavaVm, JniEnv, call_boolean_method, clear_pending_exception, copy_byte_array_bounded,
    current_env, delete_global_ref, delete_local_ref, detach_current_thread, env_function,
    get_method_id, get_object_class, is_runtime_thread, new_byte_array, new_global_ref,
};
use std::{
    ffi::CStr,
    io,
    mem::transmute,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const JNI_CALL_INT_METHOD_A: usize = 51;
const JNI_CALL_VOID_METHOD_A: usize = 63;
pub(crate) const MAX_RESULT_METADATA: usize = 256 * 1024;

static OWNER: Mutex<()> = Mutex::new(());
static BRIDGE: Mutex<Bridge> = Mutex::new(Bridge {
    controller: None,
    pending: None,
    next_id: 1,
});

struct Bridge {
    controller: Option<Arc<Controller>>,
    pending: Option<Arc<Pending>>,
    next_id: JLong,
}

struct Controller {
    vm: usize,
    object: usize,
    prepare: usize,
    start: usize,
    cancel: usize,
    stop: usize,
}

// JNI global references and method IDs remain usable while the controller
// owns them, including on native workers attached by AttachedEnv.
struct AttachedEnv {
    vm: JavaVm,
    env: JniEnv,
    attached: bool,
}

impl AttachedEnv {
    fn new(vm: usize) -> io::Result<Self> {
        let vm = vm as JavaVm;
        let (env, attached) = unsafe { current_env(vm) }.ok_or_else(transport)?;
        Ok(Self { vm, env, attached })
    }
}

impl Drop for AttachedEnv {
    fn drop(&mut self) {
        if self.attached {
            let _ = unsafe { detach_current_thread(self.vm) };
        }
    }
}

struct LocalRef {
    env: JniEnv,
    object: JObject,
}

impl Drop for LocalRef {
    fn drop(&mut self) {
        unsafe { delete_local_ref(self.env, self.object) };
    }
}

impl Controller {
    fn prepare(&self) -> io::Result<()> {
        let attachment = AttachedEnv::new(self.vm)?;
        let env = attachment.env;
        let method = unsafe { env_function(env, JNI_CALL_INT_METHOD_A) }.ok_or_else(transport)?;
        // SAFETY: JNI CallIntMethodA and the registered ()I method.
        let call: unsafe extern "system" fn(JniEnv, JObject, JMethodId, *const JValue) -> JInt =
            unsafe { transmute(method) };
        let result = unsafe {
            call(
                env,
                self.object as JObject,
                self.prepare as JMethodId,
                ptr::null(),
            )
        };
        if unsafe { clear_pending_exception(env) } {
            return Err(transport());
        }
        match result {
            0 => Ok(()),
            1 => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android WebView does not provide the required JavaScript sandbox features",
            )),
            _ => Err(transport()),
        }
    }

    fn start(
        &self,
        id: JLong,
        script: &[u8],
        input: &[u8],
        output_bound: usize,
        cancellation: &CancellationToken,
        deadline: Instant,
    ) -> io::Result<()> {
        let attachment = AttachedEnv::new(self.vm)?;
        let env = attachment.env;
        let array = |bytes: &[u8]| {
            let object = unsafe { new_byte_array(env, bytes) };
            if unsafe { clear_pending_exception(env) } {
                return Err(transport());
            }
            Ok(LocalRef {
                env,
                object: object.ok_or_else(transport)?,
            })
        };
        let script = array(script)?;
        let input = array(input)?;
        let arguments = [
            JValue { j: id },
            JValue { l: script.object },
            JValue { l: input.object },
            JValue {
                i: JInt::try_from(output_bound).map_err(|_| bad_result())?,
            },
        ];
        check(cancellation, deadline)?;
        let accepted = unsafe {
            call_boolean_method(
                env,
                self.object as JObject,
                self.start as JMethodId,
                arguments.as_ptr(),
            )
        };
        if unsafe { clear_pending_exception(env) } || accepted != JNI_TRUE {
            return Err(transport());
        }
        Ok(())
    }

    fn call_void(&self, method: usize, arguments: *const JValue) -> io::Result<()> {
        let attachment = AttachedEnv::new(self.vm)?;
        let env = attachment.env;
        let method_pointer =
            unsafe { env_function(env, JNI_CALL_VOID_METHOD_A) }.ok_or_else(transport)?;
        // SAFETY: JNI CallVoidMethodA and a registered void method.
        let call: unsafe extern "system" fn(JniEnv, JObject, JMethodId, *const JValue) =
            unsafe { transmute(method_pointer) };
        unsafe { call(env, self.object as JObject, method as JMethodId, arguments) };
        if unsafe { clear_pending_exception(env) } {
            return Err(transport());
        }
        Ok(())
    }

    fn cancel(&self, id: JLong) -> io::Result<()> {
        let argument = JValue { j: id };
        self.call_void(self.cancel, &raw const argument)
    }

    fn stop(&self) -> io::Result<()> {
        self.call_void(self.stop, ptr::null())
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        if let Ok(attachment) = AttachedEnv::new(self.vm) {
            unsafe { delete_global_ref(attachment.env, self.object as JObject) };
        }
    }
}

pub(crate) struct Evaluation {
    pub(crate) metadata: Vec<u8>,
    pub(crate) body: Vec<u8>,
}

struct Pending {
    id: JLong,
    output_bound: usize,
    deadline: Instant,
    completed: Condvar,
    state: Mutex<State>,
}

enum State {
    Waiting,
    Finished(io::Result<Evaluation>),
    Closed,
}

struct Active<'a> {
    pending: Arc<Pending>,
    controller: &'a Controller,
    needs_cancel: bool,
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        *lock(&self.pending.state) = State::Closed;
        lock(&BRIDGE).pending = None;
        if self.needs_cancel
            && self.controller.cancel(self.pending.id).is_err()
            && self.controller.stop().is_err()
        {
            // A JNI controller violating the cancellation contract cannot
            // accept a later call. Unregister it before the lane is released.
            lock(&BRIDGE).controller = None;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn transport() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "Android JavaScript sandbox bridge failed",
    )
}

fn bad_result() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Android JavaScript result",
    )
}

fn controller() -> io::Result<Arc<Controller>> {
    lock(&BRIDGE).controller.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Android JavaScript sandbox controller is not registered",
        )
    })
}

pub(crate) fn ensure_available() -> io::Result<()> {
    controller().map(|_| ())
}

pub(crate) fn prepare() -> io::Result<()> {
    let _owner = lock(&OWNER);
    controller()?.prepare()
}

pub(crate) fn shutdown() -> io::Result<()> {
    let _owner = lock(&OWNER);
    let controller = lock(&BRIDGE).controller.clone();
    controller.map_or(Ok(()), |controller| controller.stop())
}

fn check(cancellation: &CancellationToken, deadline: Instant) -> io::Result<()> {
    if cancellation.is_cancelled() {
        Err(io::ErrorKind::Interrupted.into())
    } else if Instant::now() >= deadline {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate(
    script: &[u8],
    input: &[u8],
    output_bound: usize,
    cancellation: &CancellationToken,
    deadline: Instant,
) -> io::Result<Evaluation> {
    check(cancellation, deadline)?;
    let _owner = OWNER.try_lock().map_err(|_| io::ErrorKind::WouldBlock)?;
    let controller = controller()?;
    let pending = {
        let mut bridge = lock(&BRIDGE);
        let id = bridge.next_id;
        bridge.next_id = id.checked_add(1).ok_or_else(transport)?;
        let pending = Arc::new(Pending {
            id,
            output_bound,
            deadline,
            completed: Condvar::new(),
            state: Mutex::new(State::Waiting),
        });
        bridge.pending = Some(pending.clone());
        pending
    };
    let mut active = Active {
        pending,
        controller: &controller,
        needs_cancel: true,
    };
    controller.start(
        active.pending.id,
        script,
        input,
        output_bound,
        cancellation,
        deadline,
    )?;
    let mut state = lock(&active.pending.state);
    let result = loop {
        check(cancellation, deadline)?;
        if matches!(*state, State::Finished(_)) {
            let State::Finished(result) = std::mem::replace(&mut *state, State::Closed) else {
                unreachable!()
            };
            break result;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        (state, _) = active
            .pending
            .completed
            .wait_timeout(state, remaining.min(Duration::from_millis(2)))
            .unwrap_or_else(|error| error.into_inner());
    };
    drop(state);
    active.needs_cancel = false;
    result
}

unsafe fn register(env: JniEnv, object: JObject) -> io::Result<()> {
    let _owner = OWNER.try_lock().map_err(|_| io::ErrorKind::WouldBlock)?;
    if object.is_null() || lock(&BRIDGE).controller.is_some() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let vm = *JAVA_VM.get().ok_or_else(transport)?;
    let class = unsafe { get_object_class(env, object) };
    if unsafe { clear_pending_exception(env) } {
        return Err(transport());
    }
    let class = LocalRef {
        env,
        object: class.ok_or_else(transport)?,
    };
    let find = |name: &CStr, signature: &CStr| {
        let method = unsafe { get_method_id(env, class.object, name.as_ptr(), signature.as_ptr()) };
        if unsafe { clear_pending_exception(env) } {
            return Err(transport());
        }
        method.map(|method| method as usize).ok_or_else(transport)
    };
    let prepare = find(c"prepare", c"()I")?;
    let start = find(c"start", c"(J[B[BI)Z")?;
    let cancel = find(c"cancel", c"(J)V")?;
    let stop = find(c"stop", c"()V")?;
    let global = unsafe { new_global_ref(env, object) };
    if unsafe { clear_pending_exception(env) } {
        if let Some(global) = global {
            unsafe { delete_global_ref(env, global) };
        }
        return Err(transport());
    }
    lock(&BRIDGE).controller = Some(Arc::new(Controller {
        vm,
        object: global.ok_or_else(transport)? as usize,
        prepare,
        start,
        cancel,
        stop,
    }));
    Ok(())
}

fn unregister() -> io::Result<()> {
    let _owner = OWNER.try_lock().map_err(|_| io::ErrorKind::WouldBlock)?;
    let controller = lock(&BRIDGE).controller.clone();
    if let Some(controller) = controller {
        controller.stop()?;
        lock(&BRIDGE).controller = None;
    }
    Ok(())
}

pub(super) fn release_on_unload() {
    // Normal hosts stop and unregister explicitly. JVM teardown cannot call
    // arbitrary Java lifecycle methods.
    if let Ok(_owner) = OWNER.try_lock() {
        let controller = lock(&BRIDGE).controller.take();
        drop(controller);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeRegisterJsController(
    env: JniEnv,
    _receiver: JObject,
    controller: JObject,
) -> JBoolean {
    if is_runtime_thread() {
        return JNI_FALSE;
    }
    match catch_unwind(AssertUnwindSafe(|| unsafe { register(env, controller) })) {
        Ok(Ok(())) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeUnregisterJsController(
    _env: JniEnv,
    _receiver: JObject,
) -> JBoolean {
    if is_runtime_thread() {
        return JNI_FALSE;
    }
    match catch_unwind(unregister) {
        Ok(Ok(())) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeCompleteJs(
    env: JniEnv,
    _receiver: JObject,
    id: JLong,
    status: JInt,
    metadata: JByteArray,
    body: JByteArray,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let pending = lock(&BRIDGE).pending.clone();
        let Some(pending) =
            pending.filter(|pending| pending.id == id && Instant::now() < pending.deadline)
        else {
            return;
        };
        let mut state = lock(&pending.state);
        if !matches!(*state, State::Waiting) || Instant::now() >= pending.deadline {
            return;
        }
        let result = match status {
            0 => (|| {
                let metadata =
                    unsafe { copy_byte_array_bounded(env, metadata, MAX_RESULT_METADATA) }
                        .ok_or_else(bad_result)?;
                let body = unsafe { copy_byte_array_bounded(env, body, pending.output_bound) }
                    .ok_or_else(bad_result)?;
                Ok(Evaluation { metadata, body })
            })(),
            1 => Err(bad_result()),
            2 => Err(io::ErrorKind::TimedOut.into()),
            _ => Err(transport()),
        };
        *state = State::Finished(result);
        pending.completed.notify_one();
    }));
}
