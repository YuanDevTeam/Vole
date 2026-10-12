# Vole-owned package configuration. The official source and port stay intact.
# Only the blake3 package receives compile-time namespaces; dependency tools do not.
if(PORT STREQUAL "blake3")
  set(_vole_blake3_symbols
    blake3_version
    blake3_hasher_init
    blake3_hasher_init_keyed
    blake3_hasher_init_derive_key
    blake3_hasher_init_derive_key_raw
    blake3_hasher_update
    blake3_hasher_finalize
    blake3_hasher_finalize_seek
    blake3_hasher_reset
    blake3_compress_subtree_wide
    blake3_compress_in_place
    blake3_compress_xof
    blake3_xof_many
    blake3_hash_many
    blake3_simd_degree
    blake3_compress_in_place_portable
    blake3_compress_xof_portable
    blake3_hash_many_portable
    blake3_compress_in_place_sse2
    blake3_compress_xof_sse2
    blake3_hash_many_sse2
    blake3_compress_in_place_sse41
    blake3_compress_xof_sse41
    blake3_hash_many_sse41
    blake3_hash_many_avx2
    blake3_compress_in_place_avx512
    blake3_compress_xof_avx512
    blake3_hash_many_avx512
    blake3_xof_many_avx512
    blake3_hash_many_neon
    blake3_hash4_sse2
    blake3_hash4_sse41
    blake3_hash8_avx2
    blake3_hash4_avx512
    blake3_hash8_avx512
    blake3_hash16_avx512
    blake3_xof4_avx512
    blake3_xof8_avx512
    blake3_xof16_avx512
  )
  foreach(_vole_symbol IN LISTS _vole_blake3_symbols)
    string(APPEND VCPKG_C_FLAGS " -D${_vole_symbol}=vole_c_${_vole_symbol}")
    string(APPEND VCPKG_CXX_FLAGS " -D${_vole_symbol}=vole_c_${_vole_symbol}")
  endforeach()
  # Preprocessor namespaces apply to the official intrinsics C implementations.
  # The unpreprocessed MSVC assembly exports cannot follow those definitions.
  if(VCPKG_TARGET_ARCHITECTURE MATCHES "^(x64|x86)$")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "-DBLAKE3_SIMD_TYPE=x86-intrinsics")
  endif()
endif()
