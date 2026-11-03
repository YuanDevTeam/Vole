# vcpkg recognizes tvOS but has no dedicated chainload toolchain. Reuse its
# Apple compiler/flag setup after selecting CMake's tvOS platform explicitly.
set(CMAKE_SYSTEM_NAME tvOS CACHE STRING "")
# The main toolchain propagates Z_VCPKG_ROOT_DIR to nested try_compile checks.
# Initial port configuration supplies _VCPKG_ROOT_DIR before that cache exists.
if(DEFINED Z_VCPKG_ROOT_DIR)
  set(_vole_vcpkg_root "${Z_VCPKG_ROOT_DIR}")
else()
  set(_vole_vcpkg_root "${_VCPKG_ROOT_DIR}")
endif()
include("${_vole_vcpkg_root}/scripts/toolchains/ios.cmake")
