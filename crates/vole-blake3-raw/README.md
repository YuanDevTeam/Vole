# Binary-context BLAKE3 DeriveKey

Private workspace crate for the byte-string DeriveKey used on the VLESS
Encryption wire. One public function accepts two byte slices and returns a
32-byte key. It performs no allocation, IO, runtime loading, or TLS operation.
Callers own input/output secrets and their erasure policy. The C adapter clears
its hasher with volatile stores; it cannot guarantee erasure of upstream
internal temporaries.

The official Rust 1.8.7 derive API takes `&str`. Arbitrary binary protocol
contexts may contain invalid UTF-8, so conversion to UTF-8, hex or base64 would
change the derivation. NUL itself is valid UTF-8 and can occur in a Rust string.
The official C `blake3_hasher_init_derive_key_raw` accepts a pointer and length.
Rust does not mirror the C hasher layout or implement a compression/KDF algorithm.

This reproduces an existing protocol. BLAKE3's authors recommend a fixed,
globally unique application-specific context; wire compatibility alone does
not establish the security of VLESS Encryption's protocol design.

## Dependency and build

The implementation is official [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3/tree/1.8.7/c),
installed as a static library through the official
[vcpkg port](https://github.com/microsoft/vcpkg/tree/e456309491fd875487bf02b8a0dca76c1b1b00cc/ports/blake3).
[The manifest](../../scripts/native/blake3/vcpkg.json) locks the registry commit
and exact port version. vcpkg manages release acquisition, checksum verification,
its official Windows ARM patch and upstream license texts in the dependency cache.
Vole-owned adapter/build/Rust code and package configuration are MIT.

There is no bundled BLAKE3 source. `build.rs` compiles only `src/derive.c` and
links the supplied static archive. It never downloads dependencies or searches
Cargo source caches. Platform build scripts prepare the dependency automatically;
see [build instructions](../../scripts/README.md).

The Vole-owned package triplet sets compile-time `vole_c_blake3_*` names for all
C symbols, keeping the official source and port unchanged. This prevents
collisions with the official Rust crate's native SIMD callbacks in the same
Core or test executable. ARM retains official NEON; x86 uses the official C
intrinsics mode so compiler macros also rename SIMD exports. Package upgrades
require reviewing the upstream symbol set and rerunning vectors and target builds.

For direct Cargo use, provide absolute public include and static library directories:

```sh
export VOLE_BLAKE3_INCLUDE_DIR=/absolute/native-package/include
export VOLE_BLAKE3_LIB_DIR=/absolute/native-package/lib
cargo test --locked -p vole-blake3-raw
```

Native builds accept those two variables. Cross builds require target-specific
pairs such as `VOLE_BLAKE3_INCLUDE_DIR_AARCH64_APPLE_IOS` and
`VOLE_BLAKE3_LIB_DIR_AARCH64_APPLE_IOS`; target-specific paths take precedence.
The archive must be the matching namespaced static package, built for the same
architecture, SDK/API and CRT; Unix shared-library consumers require PIC.
The public header must declare version 1.8.7. Missing paths, a wrong header
version or a missing archive fail closed. Cargo declares this native identity
with `links = "blake3"`.

## Check

The four memory-only tests verify the linked C library version, arbitrary binary
contexts, independent vectors and coexistence with the official Rust crate.
They check a primitive; Encryption handshake, ticket authentication, runtime
ownership and platform behavior need their own tests.

The fixture has 52 values generated with the independent
`github.com/metacubex/blake3 v0.1.0` implementation used by Mihomo, using Go 1.27.1.
Its SHA-256 is `16fa3198a0a6adad7de4df74010f1625b72a445991e8554842c0b12bd070b08d`.
The generator and Go module lock are in `tests/generator/`; `go run .` reproduces
the JSON on stdout and is not part of the Rust build. Inputs contain invalid
UTF-8 and NUL and cover 64/1024-byte boundaries and wire contexts up to 17005
bytes. UTF-8 cases also compare the official Rust derive interface in the same
test executable.
