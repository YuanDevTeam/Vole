//! Private host inputs. These values are never part of a shared HTTP document.
use serde::Deserialize;
use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub(crate) const MAX_CA_PEM_BYTES: usize = 32 * 1024;
// Account for the worst-case JSON spelling before allocating decoded strings.
pub(crate) const MAX_CA_INPUT: usize = MAX_CA_PEM_BYTES * 12 + 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CaMaterial {
    pub(crate) certificate: String,
    #[serde(deserialize_with = "private_key")]
    pub(crate) private_key: Zeroizing<String>,
}

fn private_key<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaMaterial([redacted])")
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid private HTTP CA input")
}

impl CaMaterial {
    #[cfg(any(test, all(target_os = "windows", feature = "windows-uwp")))]
    pub(crate) fn identity(&self) -> io::Result<[u8; 32]> {
        use rustls::pki_types::{CertificateDer, pem::PemObject as _};
        use sha2::{Digest as _, Sha256};

        self.validate_size()?;
        // A snapshot identity names the public certificate, independently of
        // its PEM spelling or the HTTP adapter. Runtime binding still checks
        // certificate validity, CA constraints and the matching private key.
        let mut certificates = CertificateDer::pem_slice_iter(self.certificate.as_bytes());
        let certificate = certificates
            .next()
            .ok_or_else(invalid)?
            .map_err(|_| invalid())?;
        if certificate.as_ref().is_empty() || certificates.next().is_some() {
            return Err(invalid());
        }
        Ok(Sha256::digest(certificate.as_ref()).into())
    }

    pub(crate) fn validate_size(&self) -> io::Result<()> {
        if self.certificate.is_empty()
            || self.certificate.len() > MAX_CA_PEM_BYTES
            || self.private_key.is_empty()
            || self.private_key.len() > MAX_CA_PEM_BYTES
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn from_json_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CA_INPUT {
            return Err(invalid());
        }
        let material: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        material.validate_size()?;
        Ok(material)
    }

    /// Reads the foreground host's explicit private input, without resolving
    /// defaults or environment variables. The caller owns the file lifetime.
    pub(crate) fn read_file(path: &Path) -> io::Result<Self> {
        if path.as_os_str().is_empty() || path == Path::new("-") {
            return Err(invalid());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Avoid a path check/open race and reject symlinks, FIFOs and devices
            // without blocking on an attacker-controlled special file.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let mut file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CA_INPUT as u64 {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Unix permissions are checked on the opened inode, not the path.
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private HTTP CA file permissions are not restricted",
                ));
            }
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        Read::by_ref(&mut file)
            .take((MAX_CA_INPUT + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_json_bytes(&bytes)
    }
}

#[cfg(all(test, feature = "inbound-http"))]
pub(crate) fn test_material() -> CaMaterial {
    use base64::Engine as _;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let pem = |label: &str, bytes: &[u8]| {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    };
    CaMaterial {
        certificate: pem("CERTIFICATE", certificate.der().as_ref()),
        private_key: Zeroizing::new(pem("PRIVATE KEY", &key.serialize_der())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_identity_is_public_der_and_does_not_require_the_http_adapter() {
        use sha2::{Digest as _, Sha256};

        let mut material = CaMaterial {
            certificate: "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".into(),
            private_key: Zeroizing::new("private material".into()),
        };
        assert_eq!(
            material.identity().unwrap(),
            <[u8; 32]>::from(Sha256::digest([1, 2, 3]))
        );
        let identity = material.identity().unwrap();
        material.certificate = material.certificate.replace('\n', "\r\n");
        material.private_key = Zeroizing::new("different private material".into());
        assert_eq!(material.identity().unwrap(), identity);
        material.certificate.push_str(&material.certificate.clone());
        assert!(material.identity().is_err());
    }

    #[cfg(feature = "inbound-http")]
    #[test]
    fn ca_identity_matches_runtime_authority_without_weakening_key_validation() {
        let mut material = test_material();
        let authority =
            super::super::authority::Authority::load(&material.certificate, &material.private_key)
                .unwrap();
        let identity = material.identity().unwrap();
        assert_eq!(identity, authority.identity());
        material.private_key = Zeroizing::new("not a private key".into());
        assert_eq!(identity, material.identity().unwrap());
        assert!(
            super::super::authority::Authority::load(&material.certificate, &material.private_key)
                .is_err()
        );
    }

    #[test]
    fn private_ca_input_is_strict_bounded_and_redacted() {
        let material = CaMaterial::from_json_bytes(
            br#"{"certificate":"public certificate","privateKey":"private material"}"#,
        )
        .unwrap();
        assert_eq!(material.certificate, "public certificate");
        assert_eq!(material.private_key.as_str(), "private material");
        let debug = format!("{material:?}");
        assert!(!debug.contains("public certificate"));
        assert!(!debug.contains("private material"));
        for bytes in [
            br#"{"certificate":"public","privateKey":"secret","unknown":true}"#.as_slice(),
            br#"{"certificate":"public","privateKey":null}"#,
            br#"{"certificate":"public","privateKey":""}"#,
        ] {
            assert!(CaMaterial::from_json_bytes(bytes).is_err());
        }
        let oversized = format!(
            "{{\"certificate\":\"public\",\"privateKey\":\"{}\"}}",
            "x".repeat(MAX_CA_PEM_BYTES + 1)
        );
        assert!(CaMaterial::from_json_bytes(oversized.as_bytes()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_ca_file_requires_owner_only_regular_input() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.json");
        std::fs::write(&path, br#"{"certificate":"public","privateKey":"secret"}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(CaMaterial::read_file(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(CaMaterial::read_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link.json");
        symlink(&path, &link).unwrap();
        assert!(CaMaterial::read_file(&link).is_err());
        assert!(CaMaterial::read_file(directory.path()).is_err());
        assert!(CaMaterial::read_file(Path::new("-")).is_err());
    }
}
