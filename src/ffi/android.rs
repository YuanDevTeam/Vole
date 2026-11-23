//! Android-only JNI adapter for registering `VpnService.protect`.
//!
//! The JSON Invoke API remains the only business interface. Android needs one
//! additional out-of-band capability because a callback cannot be represented
//! in JSON: a runtime-local controller that protects TUN-instance outbound
//! socket file descriptors before they connect.

use std::{
    ffi::{c_char, c_void},
    io,
    mem::transmute,
    ptr,
    sync::{Arc, OnceLock},
};

use crate::dialer::SocketProtector;

use crate::invoke::{
    MAX_INVOKE_BYTES, invoke_bytes_admitted, is_runtime_thread, replace_android_socket_protector,
    runtime_thread_response,
};

type JniEnv = *mut c_void;
type JavaVm = *mut c_void;
type JObject = *mut c_void;
type JByteArray = JObject;
type JMethodId = *mut c_void;
type JInt = i32;
type JLong = i64;
type JSize = i32;
type JBoolean = u8;

const JNI_VERSION_1_6: JInt = 0x0001_0006;
const JNI_OK: JInt = 0;
const JNI_EDETACHED: JInt = -2;
const JNI_ERR: JInt = -1;
const JNI_FALSE: JBoolean = 0;
const JNI_TRUE: JBoolean = 1;

// JNINativeInterface function-table indices from the JNI specification.
const JNI_EXCEPTION_OCCURRED: usize = 15;
const JNI_EXCEPTION_CLEAR: usize = 17;
const JNI_NEW_GLOBAL_REF: usize = 21;
const JNI_DELETE_GLOBAL_REF: usize = 22;
const JNI_DELETE_LOCAL_REF: usize = 23;
const JNI_GET_OBJECT_CLASS: usize = 31;
const JNI_GET_METHOD_ID: usize = 33;
const JNI_CALL_BOOLEAN_METHOD_A: usize = 39;
const JNI_GET_ARRAY_LENGTH: usize = 171;
const JNI_NEW_BYTE_ARRAY: usize = 176;
const JNI_GET_BYTE_ARRAY_REGION: usize = 200;
const JNI_SET_BYTE_ARRAY_REGION: usize = 208;

// JNIInvokeInterface indices.
const JVM_ATTACH_CURRENT_THREAD: usize = 4;
const JVM_DETACH_CURRENT_THREAD: usize = 5;
const JVM_GET_ENV: usize = 6;

static JAVA_VM: OnceLock<usize> = OnceLock::new();

#[repr(C)]
union JValue {
    z: JBoolean,
    b: i8,
    c: u16,
    s: i16,
    i: JInt,
    j: JLong,
    f: f32,
    d: f64,
    l: JObject,
}

/// Owns the Java controller global reference.
///
/// All stored values are opaque JNI handles represented as integers, so the
/// object can be shared with the runtime's outbound dialing tasks. Calls attach
/// the current Rust thread before touching the Java object.
struct JniSocketProtector {
    vm: usize,
    controller: usize,
    protect_method: usize,
}

impl SocketProtector for JniSocketProtector {
    fn protect(&self, socket_fd: i32) -> io::Result<()> {
        let vm = self.vm as JavaVm;
        let Some((env, attached)) = (unsafe { current_env(vm) }) else {
            return Err(protect_error(
                "unable to attach the outbound thread to the JVM",
            ));
        };

        let argument = JValue { i: socket_fd };
        let accepted = unsafe {
            call_boolean_method(
                env,
                self.controller as JObject,
                self.protect_method as JMethodId,
                &raw const argument,
            )
        };
        // An exception must never be mistaken for a successful protect call,
        // even if a broken Java implementation returned true before throwing.
        let had_exception = unsafe { clear_pending_exception(env) };
        if attached {
            let _ = unsafe { detach_current_thread(vm) };
        }

        if accepted == JNI_TRUE && !had_exception {
            Ok(())
        } else if had_exception {
            Err(protect_error(
                "Android protect controller threw an exception",
            ))
        } else {
            Err(protect_error(
                "Android protect controller rejected the socket",
            ))
        }
    }
}

impl Drop for JniSocketProtector {
    fn drop(&mut self) {
        let vm = self.vm as JavaVm;
        let Some((env, attached)) = (unsafe { current_env(vm) }) else {
            // A global reference cannot safely be touched without a live
            // JNIEnv. This can only happen during JVM teardown; leaking the
            // reference is safer than dereferencing an invalid VM table.
            return;
        };
        unsafe { delete_global_ref(env, self.controller as JObject) };
        if attached {
            let _ = unsafe { detach_current_thread(vm) };
        }
    }
}

fn protect_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn JNI_OnLoad(vm: JavaVm, _reserved: *mut c_void) -> JInt {
    if vm.is_null() {
        return JNI_ERR;
    }
    match JAVA_VM.set(vm as usize) {
        Ok(()) => JNI_VERSION_1_6,
        Err(_) if JAVA_VM.get().copied() == Some(vm as usize) => JNI_VERSION_1_6,
        Err(_) => JNI_ERR,
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn JNI_OnUnload(_vm: JavaVm, _reserved: *mut c_void) {
    // Normal hosts stop the TUN instance before unloading the library. The
    // registry rejects controller removal while a TUN lease is held, so no
    // TUN runtime can observe a freed Java global reference.
    let _ = std::panic::catch_unwind(|| replace_android_socket_protector(None));
}

/// Invokes the runtime registry using unmodified UTF-8 bytes.
///
/// A byte array is deliberate: JNI strings use Modified UTF-8 and therefore
/// are not a safe transport for arbitrary JSON containing non-ASCII text or
/// supplementary Unicode characters such as emoji.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeInvoke(
    env: JniEnv,
    _receiver: JObject,
    request: JByteArray,
) -> JByteArray {
    if is_runtime_thread() {
        return unsafe { new_byte_array(env, &runtime_thread_response()) }
            .unwrap_or(ptr::null_mut());
    }
    // A null or unreadable array is dispatched as an empty request so callers
    // still receive the standard failure envelope whenever JNI can allocate
    // the response array.
    let request = unsafe { copy_byte_array(env, request) }.unwrap_or_default();
    let response = match std::panic::catch_unwind(|| invoke_bytes_admitted(&request)) {
        Ok(response) => response,
        Err(_) => {
            br#"{"success":false,"data":null,"error":"panic caught at the Android JNI boundary"}"#
                .to_vec()
        }
    };
    unsafe { new_byte_array(env, &response) }.unwrap_or(ptr::null_mut())
}

/// Registers a runtime-local controller with method `boolean protect(int fd)`.
///
/// `io.github.yuandevteam.vole` is Vole's stable Android namespace. The dispatcher
/// accepts replacement whenever no instance currently holds the Android TUN lease.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeRegisterProtectController(
    env: JniEnv,
    _receiver: JObject,
    controller: JObject,
) -> JBoolean {
    if is_runtime_thread() {
        return JNI_FALSE;
    }
    let result = std::panic::catch_unwind(|| unsafe { register_controller(env, controller) });
    match result {
        Ok(Ok(())) => JNI_TRUE,
        Ok(Err(())) | Err(_) => JNI_FALSE,
    }
}

/// Unregisters the Android controller while no TUN lease is held.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn Java_io_github_yuandevteam_vole_NativeVole_nativeUnregisterProtectController(
    _env: JniEnv,
    _receiver: JObject,
) -> JBoolean {
    if is_runtime_thread() {
        return JNI_FALSE;
    }
    let result = std::panic::catch_unwind(|| replace_android_socket_protector(None));
    match result {
        Ok(Ok(())) => JNI_TRUE,
        Ok(Err(_)) | Err(_) => JNI_FALSE,
    }
}

unsafe fn register_controller(env: JniEnv, controller: JObject) -> Result<(), ()> {
    if env.is_null() || controller.is_null() {
        return Err(());
    }
    let Some(vm) = JAVA_VM.get().copied() else {
        return Err(());
    };
    let Some(protect_method) = (unsafe { find_protect_method(env, controller) }) else {
        let _ = unsafe { clear_pending_exception(env) };
        return Err(());
    };
    if unsafe { clear_pending_exception(env) } {
        return Err(());
    }
    let Some(global_controller) = (unsafe { new_global_ref(env, controller) }) else {
        let _ = unsafe { clear_pending_exception(env) };
        return Err(());
    };
    if unsafe { clear_pending_exception(env) } {
        unsafe { delete_global_ref(env, global_controller) };
        return Err(());
    }

    let protector = Arc::new(JniSocketProtector {
        vm,
        controller: global_controller as usize,
        protect_method: protect_method as usize,
    });
    replace_android_socket_protector(Some(protector)).map_err(|_| ())
}

unsafe fn find_protect_method(env: JniEnv, controller: JObject) -> Option<JMethodId> {
    let class = unsafe { get_object_class(env, controller) }?;
    let name = c"protect";
    let signature = c"(I)Z";
    let method = unsafe { get_method_id(env, class, name.as_ptr(), signature.as_ptr()) };
    unsafe { delete_local_ref(env, class) };
    method
}

unsafe fn current_env(vm: JavaVm) -> Option<(JniEnv, bool)> {
    if vm.is_null() {
        return None;
    }
    let get_env_pointer = unsafe { vm_function(vm, JVM_GET_ENV) }?;
    // SAFETY: function-table slot is specified by JNIInvokeInterface.
    let get_env: unsafe extern "system" fn(JavaVm, *mut JniEnv, JInt) -> JInt =
        unsafe { transmute(get_env_pointer) };
    let mut env = ptr::null_mut();
    let result = unsafe { get_env(vm, &mut env, JNI_VERSION_1_6) };
    if result == JNI_OK && !env.is_null() {
        return Some((env, false));
    }
    if result != JNI_EDETACHED {
        return None;
    }
    let attach_pointer = unsafe { vm_function(vm, JVM_ATTACH_CURRENT_THREAD) }?;
    // SAFETY: function-table slot is specified by JNIInvokeInterface.
    let attach: unsafe extern "system" fn(JavaVm, *mut JniEnv, *mut c_void) -> JInt =
        unsafe { transmute(attach_pointer) };
    if unsafe { attach(vm, &mut env, ptr::null_mut()) } == JNI_OK && !env.is_null() {
        Some((env, true))
    } else {
        None
    }
}

unsafe fn detach_current_thread(vm: JavaVm) -> JInt {
    let Some(pointer) = (unsafe { vm_function(vm, JVM_DETACH_CURRENT_THREAD) }) else {
        return JNI_ERR;
    };
    // SAFETY: function-table slot is specified by JNIInvokeInterface.
    let detach: unsafe extern "system" fn(JavaVm) -> JInt = unsafe { transmute(pointer) };
    unsafe { detach(vm) }
}

unsafe fn copy_byte_array(env: JniEnv, array: JByteArray) -> Option<Vec<u8>> {
    unsafe { copy_byte_array_bounded(env, array, MAX_INVOKE_BYTES) }
}

unsafe fn copy_byte_array_bounded(env: JniEnv, array: JByteArray, limit: usize) -> Option<Vec<u8>> {
    if env.is_null() || array.is_null() {
        return None;
    }
    let length_pointer = unsafe { env_function(env, JNI_GET_ARRAY_LENGTH) }?;
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let get_length: unsafe extern "system" fn(JniEnv, JByteArray) -> JSize =
        unsafe { transmute(length_pointer) };
    let length = usize::try_from(unsafe { get_length(env, array) }).ok()?;
    // Enforce the caller's bound before allocating or copying Java input.
    if length > limit || unsafe { clear_pending_exception(env) } {
        return None;
    }
    let mut output = Vec::new();
    output.try_reserve_exact(length).ok()?;
    output.resize(length, 0);
    if length != 0 {
        let region_pointer = unsafe { env_function(env, JNI_GET_BYTE_ARRAY_REGION) }?;
        // SAFETY: function-table slot is specified by JNINativeInterface.
        let get_region: unsafe extern "system" fn(JniEnv, JByteArray, JSize, JSize, *mut i8) =
            unsafe { transmute(region_pointer) };
        let jni_length = JSize::try_from(length).ok()?;
        unsafe { get_region(env, array, 0, jni_length, output.as_mut_ptr().cast()) };
    }
    (!unsafe { clear_pending_exception(env) }).then_some(output)
}

unsafe fn new_byte_array(env: JniEnv, value: &[u8]) -> Option<JByteArray> {
    if env.is_null() {
        return None;
    }
    let length = JSize::try_from(value.len()).ok()?;
    let new_array_pointer = unsafe { env_function(env, JNI_NEW_BYTE_ARRAY) }?;
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let new_array: unsafe extern "system" fn(JniEnv, JSize) -> JByteArray =
        unsafe { transmute(new_array_pointer) };
    let array = unsafe { new_array(env, length) };
    if array.is_null() || unsafe { clear_pending_exception(env) } {
        return None;
    }
    if length != 0 {
        let set_region_pointer = unsafe { env_function(env, JNI_SET_BYTE_ARRAY_REGION) }?;
        // SAFETY: function-table slot is specified by JNINativeInterface.
        let set_region: unsafe extern "system" fn(JniEnv, JByteArray, JSize, JSize, *const i8) =
            unsafe { transmute(set_region_pointer) };
        unsafe { set_region(env, array, 0, length, value.as_ptr().cast()) };
        if unsafe { clear_pending_exception(env) } {
            unsafe { delete_local_ref(env, array) };
            return None;
        }
    }
    Some(array)
}

unsafe fn new_global_ref(env: JniEnv, object: JObject) -> Option<JObject> {
    let pointer = unsafe { env_function(env, JNI_NEW_GLOBAL_REF) }?;
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let function: unsafe extern "system" fn(JniEnv, JObject) -> JObject =
        unsafe { transmute(pointer) };
    let reference = unsafe { function(env, object) };
    (!reference.is_null()).then_some(reference)
}

unsafe fn delete_global_ref(env: JniEnv, object: JObject) {
    if object.is_null() {
        return;
    }
    if let Some(pointer) = unsafe { env_function(env, JNI_DELETE_GLOBAL_REF) } {
        // SAFETY: function-table slot is specified by JNINativeInterface.
        let function: unsafe extern "system" fn(JniEnv, JObject) = unsafe { transmute(pointer) };
        unsafe { function(env, object) };
    }
}

unsafe fn delete_local_ref(env: JniEnv, object: JObject) {
    if object.is_null() {
        return;
    }
    if let Some(pointer) = unsafe { env_function(env, JNI_DELETE_LOCAL_REF) } {
        // SAFETY: function-table slot is specified by JNINativeInterface.
        let function: unsafe extern "system" fn(JniEnv, JObject) = unsafe { transmute(pointer) };
        unsafe { function(env, object) };
    }
}

unsafe fn get_object_class(env: JniEnv, object: JObject) -> Option<JObject> {
    let pointer = unsafe { env_function(env, JNI_GET_OBJECT_CLASS) }?;
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let function: unsafe extern "system" fn(JniEnv, JObject) -> JObject =
        unsafe { transmute(pointer) };
    let class = unsafe { function(env, object) };
    (!class.is_null()).then_some(class)
}

unsafe fn get_method_id(
    env: JniEnv,
    class: JObject,
    name: *const c_char,
    signature: *const c_char,
) -> Option<JMethodId> {
    let pointer = unsafe { env_function(env, JNI_GET_METHOD_ID) }?;
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let function: unsafe extern "system" fn(
        JniEnv,
        JObject,
        *const c_char,
        *const c_char,
    ) -> JMethodId = unsafe { transmute(pointer) };
    let method = unsafe { function(env, class, name, signature) };
    (!method.is_null()).then_some(method)
}

unsafe fn call_boolean_method(
    env: JniEnv,
    object: JObject,
    method: JMethodId,
    arguments: *const JValue,
) -> JBoolean {
    let Some(pointer) = (unsafe { env_function(env, JNI_CALL_BOOLEAN_METHOD_A) }) else {
        return JNI_FALSE;
    };
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let function: unsafe extern "system" fn(JniEnv, JObject, JMethodId, *const JValue) -> JBoolean =
        unsafe { transmute(pointer) };
    unsafe { function(env, object, method, arguments) }
}

/// Returns true for an exception or for an unusable exception API.
unsafe fn clear_pending_exception(env: JniEnv) -> bool {
    let Some(occurred_pointer) = (unsafe { env_function(env, JNI_EXCEPTION_OCCURRED) }) else {
        return true;
    };
    // SAFETY: function-table slot is specified by JNINativeInterface.
    let occurred: unsafe extern "system" fn(JniEnv) -> JObject =
        unsafe { transmute(occurred_pointer) };
    let exception = unsafe { occurred(env) };
    if exception.is_null() {
        return false;
    }
    if let Some(clear_pointer) = unsafe { env_function(env, JNI_EXCEPTION_CLEAR) } {
        // SAFETY: function-table slot is specified by JNINativeInterface.
        let clear: unsafe extern "system" fn(JniEnv) = unsafe { transmute(clear_pointer) };
        unsafe { clear(env) };
    }
    unsafe { delete_local_ref(env, exception) };
    true
}

unsafe fn env_function(env: JniEnv, index: usize) -> Option<*const c_void> {
    if env.is_null() {
        return None;
    }
    // `_JNIEnv` contains the JNINativeInterface pointer as its first field.
    let table = unsafe { *env.cast::<*const *const c_void>() };
    if table.is_null() {
        return None;
    }
    let function = unsafe { *table.add(index) };
    (!function.is_null()).then_some(function)
}

unsafe fn vm_function(vm: JavaVm, index: usize) -> Option<*const c_void> {
    if vm.is_null() {
        return None;
    }
    // `_JavaVM` contains the JNIInvokeInterface pointer as its first field.
    let table = unsafe { *vm.cast::<*const *const c_void>() };
    if table.is_null() {
        return None;
    }
    let function = unsafe { *table.add(index) };
    (!function.is_null()).then_some(function)
}
