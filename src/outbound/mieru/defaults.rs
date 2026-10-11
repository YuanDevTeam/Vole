//! Implicit profile values from the SDK used by the frozen Mihomo consumer.
//! This marker selects native defaults; Vole does not link the Go SDK.
use sha2::{Digest, Sha256};

const REFERENCE_PROFILE_VERSION: &str = "3.38.0";

pub(super) fn fixed_host_int(upper: u32) -> u32 {
    if upper == 0 {
        return 0;
    }
    let host = hostname::get().unwrap_or_default();
    let mut hash = Sha256::new();
    hash.update(host.into_encoded_bytes());
    hash.update(b" ");
    hash.update(REFERENCE_PROFILE_VERSION.as_bytes());
    let digest = hash.finalize();
    u32::from_be_bytes([digest[0] & 0x7f, digest[1], digest[2], digest[3]]) % upper
}
