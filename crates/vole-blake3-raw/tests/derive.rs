use vole_blake3_raw::derive_key;

#[test]
fn links_the_required_official_c_library_version() {
    unsafe extern "C" {
        #[link_name = "vole_c_blake3_version"]
        fn blake3_version() -> *const std::ffi::c_char;
    }
    // SAFETY: the public API returns a static NUL-terminated version string.
    let version = unsafe { std::ffi::CStr::from_ptr(blake3_version()) };
    assert_eq!(version.to_bytes(), b"1.8.7");
}

#[test]
fn derives_binary_context_without_utf8_conversion() {
    // Independent github.com/metacubex/blake3 v0.1.0 DeriveKey result.
    let context: Vec<u8> = (0..16).map(|i| (i * 37 + 255) as u8).collect();
    let material: Vec<u8> = (0..32).map(|i| (i * 13 + 7) as u8).collect();
    let actual: String = derive_key(&context, &material)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        actual,
        "853b1d12dc08c5f34a282e668cc51fa4e34a5213ecd9d036773696493d6a19ba"
    );
}

#[test]
fn matches_independent_go_vectors_across_block_chunk_and_wire_context_lengths() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/blake3-binary-context-vectors.json")).unwrap();
    let vectors = fixtures["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 52);
    for vector in vectors {
        let context_len = vector["context_length"].as_u64().unwrap() as usize;
        let key_len = vector["key_length"].as_u64().unwrap() as usize;
        let context: Vec<u8> = (0..context_len).map(|i| (i * 37 + 255) as u8).collect();
        let material: Vec<u8> = (0..key_len).map(|i| (i * 13 + 7) as u8).collect();
        let actual: String = derive_key(&context, &material)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            actual,
            vector["output"].as_str().unwrap(),
            "context={context_len}, material={key_len}"
        );
    }
}

#[test]
fn coexists_with_official_rust_blake3_and_matches_its_utf8_interface() {
    for context in ["", "VLESS", "vole tests 2026-09-26 固定 context\0with NUL"] {
        for length in [0, 1, 32, 64, 1023, 1024, 1025, 17005] {
            let material: Vec<u8> = (0..length).map(|i| (i * 13 + 7) as u8).collect();
            assert_eq!(
                derive_key(context.as_bytes(), &material),
                blake3::derive_key(context, &material)
            );
        }
    }
}
