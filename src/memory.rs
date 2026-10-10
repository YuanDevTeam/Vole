//! Current-process memory only, sampled on an explicit Controller request.

/// Resident bytes, or unavailable. No process enumeration or retained history.
pub(crate) fn resident_bytes() -> Option<u64> {
    platform_resident_bytes()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_resident_bytes() -> Option<u64> {
    use std::io::Read;
    let mut data = String::new();
    std::fs::File::open("/proc/self/status")
        .ok()?
        .take(16 * 1024)
        .read_to_string(&mut data)
        .ok()?;
    let line = data.lines().find_map(|line| line.strip_prefix("VmRSS:"))?;
    let mut fields = line.split_whitespace();
    let bytes = fields.next()?.parse::<u64>().ok()?.checked_mul(1024)?;
    (fields.next()? == "kB").then_some(bytes)
}

#[cfg(target_vendor = "apple")]
fn platform_resident_bytes() -> Option<u64> {
    // MACH_TASK_BASIC_INFO is the public 64-bit ABI on all Apple targets.
    #[repr(C)]
    struct BasicInfo {
        virtual_size: u64,
        resident_size: u64,
        resident_size_max: u64,
        user_time: [i32; 2],
        system_time: [i32; 2],
        policy: i32,
        suspend_count: i32,
    }
    unsafe extern "C" {
        static mach_task_self_: libc::mach_port_t;
    }
    let mut info = std::mem::MaybeUninit::<BasicInfo>::zeroed();
    let expected = (std::mem::size_of::<BasicInfo>() / std::mem::size_of::<u32>()) as u32;
    let mut count = expected;
    // SAFETY: our own task port, correctly sized/aligned writable ABI storage.
    let result =
        unsafe { libc::task_info(mach_task_self_, 20, info.as_mut_ptr().cast(), &mut count) };
    if result != 0 || count != expected {
        return None;
    }
    // SAFETY: successful task_info initialized the full verified ABI structure.
    Some(unsafe { info.assume_init() }.resident_size)
}

#[cfg(windows)]
fn platform_resident_bytes() -> Option<u64> {
    use std::ffi::c_void;
    #[repr(C)]
    struct Counters {
        size: u32,
        page_fault_count: u32,
        peak_working_set: usize,
        working_set: usize,
        quota_peak_paged_pool: usize,
        quota_paged_pool: usize,
        quota_peak_non_paged_pool: usize,
        quota_non_paged_pool: usize,
        pagefile: usize,
        peak_pagefile: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, size: u32)
        -> i32;
    }
    let mut counters = std::mem::MaybeUninit::<Counters>::zeroed();
    let size = std::mem::size_of::<Counters>() as u32;
    // SAFETY: own pseudo-handle; the API writes to the supplied sized structure.
    unsafe { (*counters.as_mut_ptr()).size = size };
    // SAFETY: no external PID or handle lifetime; valid initialized ABI storage.
    let result =
        unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), counters.as_mut_ptr(), size) };
    if result == 0 {
        return None;
    }
    // SAFETY: the successful API call populated this structure.
    u64::try_from(unsafe { counters.assume_init() }.working_set).ok()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
fn platform_resident_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    fn current_process_has_resident_memory() {
        assert!(super::resident_bytes().is_some_and(|bytes| bytes > 0));
    }
}
