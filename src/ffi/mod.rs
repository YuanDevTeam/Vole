//! Thin C ABI and Android JNI transports for the shared Invoke API.
use crate::invoke::{
    InvokeFailure, InvokeResponse, MAX_INVOKE_BYTES, invoke_bytes, is_runtime_thread,
    runtime_thread_response, serialize_response,
};
use std::{
    ffi::{CString, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};
#[cfg(target_os = "android")]
pub(crate) mod android;
/// Executes one Vole request and returns an independently allocated UTF-8 JSON
/// response. The caller must release the returned pointer with `VoleFree`.
///
/// # Safety
/// `request_json` must be either null or point to readable storage containing a
/// NUL terminator within `MAX_INVOKE_BYTES + 1` bytes.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn VoleInvoke(request_json: *const c_char) -> *mut c_char {
    if is_runtime_thread() {
        return allocate_response(runtime_thread_response());
    }
    let response = match catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller contract is documented above; this function adds
        // a bounded scan before constructing the byte slice.
        unsafe { read_request(request_json) }
    })) {
        Ok(Ok(request)) => invoke_bytes(request),
        Ok(Err(error)) => serialize_response(InvokeResponse::failure(error.message)),
        Err(_) => serialize_response(InvokeResponse::failure(
            "internal error: panic caught at the Vole Invoke boundary",
        )),
    };
    allocate_response(response)
}

/// Releases a response returned by `VoleInvoke` or `VoleWindowsVpnInvoke`.
/// A null pointer is ignored.
///
/// # Safety
/// A non-null pointer must have been returned by one of those functions, must not have
/// been freed already, and must not be used after this call.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn VoleFree(response: *mut c_char) {
    if !response.is_null() {
        // SAFETY: ownership is returned by the caller under the contract above.
        drop(unsafe { CString::from_raw(response) });
    }
}

unsafe fn read_request<'a>(request_json: *const c_char) -> Result<&'a [u8], InvokeFailure> {
    if request_json.is_null() {
        return Err(InvokeFailure::invalid_request("request_json is null"));
    }
    // SAFETY: the caller promises readable storage through the first NUL or
    // MAX_INVOKE_BYTES + 1 bytes, whichever comes first.
    let len = unsafe { libc::strnlen(request_json, MAX_INVOKE_BYTES + 1) };
    if len > MAX_INVOKE_BYTES {
        return Err(InvokeFailure::invalid_request(format!(
            "Invoke envelope exceeds the {MAX_INVOKE_BYTES}-byte limit or is not NUL-terminated"
        )));
    }
    // SAFETY: strnlen established that these bytes are readable and precede a
    // NUL terminator within the documented bound.
    Ok(unsafe { slice::from_raw_parts(request_json.cast::<u8>(), len) })
}

fn allocate_response(json: Vec<u8>) -> *mut c_char {
    // JSON escapes control characters, so serialization cannot introduce an
    // interior NUL. Keep a defensive fallback to preserve the C contract.
    CString::new(json).unwrap_or_else(|_| {
        CString::new(
            "{\"success\":false,\"data\":null,\"error\":\"internal error: invalid response string\"}",
        )
        .expect("static response has no NUL")
    })
    .into_raw()
}
