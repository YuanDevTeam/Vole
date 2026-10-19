//! Current-user DPAPI handoff for one immutable Windows session snapshot.
//! The ordinary snapshot stores only a public CA identity; this module never
//! serializes a public input DTO or sends private material through packet IPC.
use crate::http_processing::private_context::{CaMaterial, MAX_CA_INPUT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::{E_FAIL, HLOCAL, LocalFree},
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
    },
    core::{Error, PCWSTR, Result},
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_PROTECTED_CA_BYTES: usize = MAX_CA_INPUT + 16 * 1024;

fn invalid() -> Error {
    Error::new(E_FAIL, "invalid protected HTTP CA")
}

fn entropy(package_family: &str, snapshot_token: &str) -> Result<[u8; 32]> {
    super::snapshot::SessionReference::parse(snapshot_token)?;
    if package_family.is_empty()
        || package_family.len() > 512
        || package_family.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let mut digest = Sha256::new();
    digest.update(b"Vole Windows HTTP CA\0");
    digest.update(package_family.as_bytes());
    digest.update([0]);
    digest.update(snapshot_token.as_bytes());
    Ok(digest.finalize().into())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateEnvelope<'a> {
    snapshot_token: &'a str,
    ca: PrivateCa<'a>,
}

// A private, borrowed serialization boundary. CaMaterial deliberately has no
// Serialize implementation and cannot accidentally enter an ordinary snapshot.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateCa<'a> {
    certificate: &'a str,
    private_key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UnprotectedEnvelope {
    snapshot_token: String,
    ca: CaMaterial,
}

struct LocalBlob(CRYPT_INTEGER_BLOB);
impl LocalBlob {
    fn bytes(&self, maximum: usize) -> Result<&[u8]> {
        let length = self.0.cbData as usize;
        if self.0.pbData.is_null() || length == 0 || length > maximum {
            return Err(invalid());
        }
        // DPAPI owns this successful allocation until LocalFree below.
        Ok(unsafe { std::slice::from_raw_parts(self.0.pbData, length) })
    }
}
impl Drop for LocalBlob {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // Zero plaintext DPAPI output before returning the native memory.
            // Applying the same cleanup to ciphertext keeps a single owner.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                let _ = LocalFree(Some(HLOCAL(self.0.pbData.cast())));
            }
        }
    }
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}

pub(crate) fn seal(
    material: &CaMaterial,
    package_family: &str,
    snapshot_token: &str,
) -> Result<Vec<u8>> {
    material.validate_size().map_err(|_| invalid())?;
    let entropy_bytes = entropy(package_family, snapshot_token)?;
    let envelope = PrivateEnvelope {
        snapshot_token,
        ca: PrivateCa {
            certificate: &material.certificate,
            private_key: &material.private_key,
        },
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|_| invalid())?);
    if plaintext.len() > MAX_CA_INPUT {
        return Err(invalid());
    }
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &blob(&plaintext),
            PCWSTR::null(),
            Some(&blob(&entropy_bytes)),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let output = LocalBlob(output);
    result?;
    Ok(output.bytes(MAX_PROTECTED_CA_BYTES)?.to_vec())
}

pub(crate) fn open(
    protected: &[u8],
    package_family: &str,
    snapshot_token: &str,
    expected_identity: [u8; 32],
) -> Result<CaMaterial> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED_CA_BYTES {
        return Err(invalid());
    }
    let entropy_bytes = entropy(package_family, snapshot_token)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptUnprotectData(
            &blob(protected),
            None,
            Some(&blob(&entropy_bytes)),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    let output = LocalBlob(output);
    result?;
    let envelope: UnprotectedEnvelope =
        serde_json::from_slice(output.bytes(MAX_CA_INPUT)?).map_err(|_| invalid())?;
    if envelope.snapshot_token != snapshot_token
        || envelope.ca.identity().map_err(|_| invalid())? != expected_identity
    {
        return Err(invalid());
    }
    Ok(envelope.ca)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_handoff_is_bound_to_session_package_and_ca() {
        let ca = crate::http_processing::private_context::test_material();
        let token = format!("vole-session-v2:{}", "0".repeat(64));
        let identity = ca.identity().unwrap();
        let protected = seal(&ca, "ExamplePackage", &token).unwrap();
        let restored = open(&protected, "ExamplePackage", &token, identity).unwrap();
        assert_eq!(restored.certificate, ca.certificate);
        assert_eq!(restored.private_key.as_str(), ca.private_key.as_str());
        assert!(open(&protected, "OtherPackage", &token, identity).is_err());
        let other = format!("vole-session-v2:{}", "1".repeat(64));
        assert!(open(&protected, "ExamplePackage", &other, identity).is_err());
        assert!(open(&protected, "ExamplePackage", &token, [0; 32]).is_err());
        let mut corrupt = protected;
        corrupt[0] ^= 0x80;
        assert!(open(&corrupt, "ExamplePackage", &token, identity).is_err());
    }
}
