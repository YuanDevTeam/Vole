use std::{env, fs, path::PathBuf};

const VERSION: &str = "1.8.7";

fn dependency_dir(name: &str, target: &str, host: &str) -> PathBuf {
    let scoped = format!("{name}_{}", target.to_uppercase().replace('-', "_"));
    println!("cargo:rerun-if-env-changed={scoped}");
    println!("cargo:rerun-if-env-changed={name}");
    let value = env::var_os(&scoped)
        .or_else(|| (target == host).then(|| env::var_os(name)).flatten())
        .unwrap_or_else(|| {
            panic!(
                "set {scoped} to the absolute directory of the target's installed official BLAKE3 {VERSION} static package; native builds also accept {name}"
            )
        });
    let path = PathBuf::from(value);
    assert!(path.is_absolute(), "{scoped} must be an absolute path");
    assert!(path.is_dir(), "{scoped} must name an existing directory");
    path.canonicalize()
        .expect("canonicalize dependency directory")
}

fn main() {
    let target = env::var("TARGET").expect("Cargo TARGET");
    let host = env::var("HOST").expect("Cargo HOST");
    let include = dependency_dir("VOLE_BLAKE3_INCLUDE_DIR", &target, &host);
    let lib = dependency_dir("VOLE_BLAKE3_LIB_DIR", &target, &host);
    let header = include.join("blake3.h");
    let header_text = fs::read_to_string(&header).expect("read installed public blake3.h");
    let expected_version = format!("\"{VERSION}\"");
    assert!(
        header_text.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some("#define")
                && fields.next() == Some("BLAKE3_VERSION_STRING")
                && fields.next() == Some(expected_version.as_str())
        }),
        "installed blake3.h must declare BLAKE3_VERSION_STRING {VERSION}"
    );
    let archive_name = if target.ends_with("-msvc") {
        "blake3.lib"
    } else {
        "libblake3.a"
    };
    let archive = lib.join(archive_name);
    assert!(
        archive.is_file(),
        "missing static BLAKE3 archive {archive_name}"
    );

    // Only this Vole-owned adapter is compiled here. Package management owns
    // the public header and archive; this build never discovers or downloads C.
    let mut adapter = cc::Build::new();
    adapter
        .include(&include)
        .file("src/derive.c")
        .std("c11")
        .flag_if_supported("-fvisibility=hidden");
    // Match the external package's compile-time namespace without changing
    // upstream's public header or implementation. This is required when the
    // official Rust crate also contributes its native SIMD callbacks.
    for symbol in [
        "blake3_hasher_init_derive_key_raw",
        "blake3_hasher_update",
        "blake3_hasher_finalize",
    ] {
        adapter.define(symbol, format!("vole_c_{symbol}").as_str());
    }
    adapter.compile("vole_blake3_raw");
    println!("cargo:rustc-link-search=native={}", lib.display());
    println!("cargo:rustc-link-lib=static=blake3");
    println!("cargo:rerun-if-changed=src/derive.c");
    println!("cargo:rerun-if-changed={}", header.display());
    println!("cargo:rerun-if-changed={}", archive.display());
}
