# Native Windows ARM64, MSVC ABI. Clang's integrated assembler handles BoringSSL
# preprocessed .S files; Ninja preserves their directory-qualified object names.
# Never disable assembly or change the bundled third-party source.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(CMAKE_C_COMPILER "$ENV{CC_aarch64_pc_windows_msvc}")
set(CMAKE_CXX_COMPILER "$ENV{CXX_aarch64_pc_windows_msvc}")
# cmake-rs supplies MSVC-style ASM flags as well as C/C++ flags. Use the CL
# driver for all three languages so the integrated assembler accepts them.
set(CMAKE_ASM_COMPILER "$ENV{CC_aarch64_pc_windows_msvc}")
set(CMAKE_C_COMPILER_TARGET aarch64-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET aarch64-pc-windows-msvc)
set(CMAKE_ASM_COMPILER_TARGET aarch64-pc-windows-msvc)
# Match Cargo's selected CRT, including UWP's dynamic CRT. An explicit setting
# from a native build script takes precedence over this toolchain default.
if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
  if("$ENV{CARGO_CFG_TARGET_FEATURE}" MATCHES "(^|,)crt-static(,|$)")
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
  endif()
endif()
