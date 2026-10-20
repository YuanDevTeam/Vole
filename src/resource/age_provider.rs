//! Native subscription decryption; standard AGE authentication/STREAM belongs to age.
use crate::{Result, VoleError};
use age_core::format::{FileKey, Stanza};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use hpke::{Deserializable, aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing};
use serde_yaml_ng::Value;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    fmt,
    io::{self, Read},
    sync::Arc,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(crate) const ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const SECRET_BYTES: usize = 16 * 1024;
const IDENTITIES: usize = 128;
const HEADER_BYTES: usize = 64 * 1024;
const UNWRAP_ATTEMPTS: usize = 1024;
const HYBRID_TAG: &str = "mlkem768x25519";
const HYBRID_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

fn invalid(message: &'static str) -> VoleError {
    VoleError::InvalidConfig(message.into())
}

/// Immutable parsed identities, shared by template/spec clones. No source key text is kept.
#[derive(Clone)]
pub(crate) struct Identities {
    entries: Arc<[Identity]>,
    fingerprint: [u8; 32],
}
enum Identity {
    X25519(age::x25519::Identity),
    Hybrid(Box<<XWing as hpke::Kem>::PrivateKey>),
}
impl fmt::Debug for Identities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AgeIdentities { .. }")
    }
}
impl PartialEq for Identities {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}
impl Eq for Identities {}
impl Identities {
    pub(crate) fn from_value(value: Value) -> Result<Option<Self>> {
        let secret = match value {
            Value::Null => return Ok(None),
            Value::String(secret) => Zeroizing::new(secret),
            _ => return Err(invalid("age-secret-key requires a string")),
        };
        Self::parse(&secret).map(Some)
    }
    pub(crate) fn parse(secret: &str) -> Result<Self> {
        if secret.len() > SECRET_BYTES {
            return Err(invalid("AGE identity budget exceeded"));
        }
        let mut entries = Vec::new();
        for line in secret.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if entries.len() >= IDENTITIES {
                return Err(invalid("AGE identity budget exceeded"));
            }
            if line.starts_with("AGE-SECRET-KEY-PQ-1") {
                let parsed =
                    bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32>(line)
                        .map_err(|_| invalid("invalid AGE provider identity"))?;
                if !parsed
                    .hrp()
                    .to_string()
                    .eq_ignore_ascii_case("AGE-SECRET-KEY-PQ-")
                {
                    return Err(invalid("invalid AGE provider identity"));
                }
                let seed = Zeroizing::new(parsed.byte_iter().collect::<Vec<u8>>());
                let key = <XWing as hpke::Kem>::PrivateKey::from_bytes(&seed)
                    .map_err(|_| invalid("invalid AGE provider identity"))?;
                entries.push(Identity::Hybrid(Box::new(key)));
            } else {
                let key = line
                    .parse::<age::x25519::Identity>()
                    .map_err(|_| invalid("invalid AGE provider identity"))?;
                entries.push(Identity::X25519(key));
            }
        }
        Ok(Self {
            entries: entries.into(),
            fingerprint: Sha256::digest(secret.as_bytes()).into(),
        })
    }
}

/// Processing scope is shared by header reads, all identities and plaintext reads.
pub(crate) struct DecodeControl<'a> {
    cancellation: Option<&'a CancellationToken>,
    deadline: Instant,
    header: Cell<bool>,
    attempts: Cell<usize>,
}
impl<'a> DecodeControl<'a> {
    pub(crate) fn new(cancellation: Option<&'a CancellationToken>, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
            header: Cell::new(true),
            attempts: Cell::new(0),
        }
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self
            .cancellation
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(invalid("provider decoding cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(invalid("provider decoding deadline exceeded"));
        }
        Ok(())
    }
    fn unwrap(&self) -> std::result::Result<(), age::DecryptError> {
        if self.check().is_err() || self.attempts.get() >= UNWRAP_ATTEMPTS {
            return Err(age::DecryptError::DecryptionFailed);
        }
        self.attempts.set(self.attempts.get() + 1);
        Ok(())
    }
}
struct CheckedIdentity<'a> {
    identity: &'a Identity,
    control: &'a DecodeControl<'a>,
}
impl age::Identity for CheckedIdentity<'_> {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        // Unknown AGE extension stanzas remain skippable without private-key operations.
        let expected = match self.identity {
            Identity::X25519(_) => "X25519",
            Identity::Hybrid(_) => HYBRID_TAG,
        };
        if stanza.tag != expected {
            return None;
        }
        if let Err(error) = self.control.unwrap() {
            return Some(Err(error));
        }
        match self.identity {
            Identity::X25519(identity) => identity.unwrap_stanza(stanza),
            Identity::Hybrid(secret) => {
                if stanza.args.len() != 1 || stanza.body.len() != 32 || stanza.args[0].len() != 1494
                {
                    return Some(Err(age::DecryptError::InvalidHeader));
                }
                let encapsulated = match STANDARD_NO_PAD.decode(&stanza.args[0]) {
                    Ok(bytes) if bytes.len() == 1120 => bytes,
                    _ => return Some(Err(age::DecryptError::InvalidHeader)),
                };
                let encapped = match <XWing as hpke::Kem>::EncappedKey::from_bytes(&encapsulated) {
                    Ok(value) => value,
                    Err(_) => return Some(Err(age::DecryptError::InvalidHeader)),
                };
                let mut receiver = match hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
                    &hpke::OpModeR::Base,
                    secret,
                    &encapped,
                    HYBRID_INFO,
                ) {
                    Ok(receiver) => receiver,
                    Err(_) => return None,
                };
                let file_key = match receiver.open(&stanza.body, b"") {
                    Ok(value) => Zeroizing::new(value),
                    Err(_) => return None,
                };
                if file_key.len() != 16 {
                    return Some(Err(age::DecryptError::InvalidHeader));
                }
                Some(Ok(FileKey::init_with_mut(|key| {
                    key.copy_from_slice(&file_key)
                })))
            }
        }
    }
}
struct CheckedReader<'a, R> {
    inner: R,
    control: &'a DecodeControl<'a>,
    header_read: usize,
}
impl<R: Read> Read for CheckedReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.control
            .check()
            .map_err(|_| io::Error::other("provider decoding stopped"))?;
        let limit = if self.control.header.get() {
            HEADER_BYTES
                .saturating_sub(self.header_read)
                .saturating_add(1)
                .min(output.len())
        } else {
            output.len()
        };
        let count = self.inner.read(&mut output[..limit])?;
        if self.control.header.get() {
            self.header_read = self.header_read.saturating_add(count);
            if self.header_read > HEADER_BYTES {
                return Err(io::Error::other("AGE header budget exceeded"));
            }
        }
        Ok(count)
    }
}
pub(crate) enum Decoded<'a> {
    Plain(&'a [u8]),
    Decrypted(Zeroizing<Vec<u8>>),
}
impl AsRef<[u8]> for Decoded<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Plain(bytes) => bytes,
            Self::Decrypted(bytes) => bytes,
        }
    }
}

pub(crate) fn decode<'a>(
    bytes: &'a [u8],
    identities: Option<&Identities>,
    control: &DecodeControl<'_>,
    output_limit: usize,
) -> Result<Decoded<'a>> {
    control.check()?;
    // Exactly the reference armor prefix, with no BOM/whitespace/binary sniffing.
    if !bytes.starts_with(ARMOR_HEADER) {
        return Ok(Decoded::Plain(bytes));
    }
    let identities =
        identities.ok_or_else(|| invalid("AGE provider requires a matching identity"))?;
    control.header.set(true);
    let input = CheckedReader {
        inner: age::armor::ArmoredReader::new(bytes),
        control,
        header_read: 0,
    };
    let decryptor =
        age::Decryptor::new(input).map_err(|_| invalid("invalid AGE provider content"))?;
    control.header.set(false);
    let checked: Vec<_> = identities
        .entries
        .iter()
        .map(|identity| CheckedIdentity { identity, control })
        .collect();
    let mut plaintext = decryptor
        .decrypt(
            checked
                .iter()
                .map(|identity| identity as &dyn age::Identity),
        )
        .map_err(|_| invalid("AGE provider decryption failed"))?;
    control.check()?;
    let mut output = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0_u8; 16 * 1024]);
    loop {
        control.check()?;
        let available = output_limit
            .saturating_sub(output.len())
            .saturating_add(1)
            .min(buffer.len());
        let count = plaintext
            .read(&mut buffer[..available])
            .map_err(|_| invalid("AGE provider decryption failed"))?;
        if count == 0 {
            break;
        }
        if output
            .len()
            .checked_add(count)
            .is_none_or(|length| length > output_limit)
        {
            return Err(invalid("decrypted provider exceeds YAML byte limit"));
        }
        let required = output.len() + count;
        if required > output.capacity() {
            // Grow geometrically without exceeding the plaintext byte budget.
            let capacity = output
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(output_limit);
            let additional = capacity - output.len();
            output
                .try_reserve_exact(additional)
                .map_err(|_| invalid("AGE provider output allocation failed"))?;
        }
        output.extend_from_slice(&buffer[..count]);
    }
    control.check()?;
    Ok(Decoded::Decrypted(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, time::Duration};

    const X_KEY: &str = include_str!("../../tests/fixtures/provider-age/x25519.key");
    const PQ_KEY: &str = include_str!("../../tests/fixtures/provider-age/hybrid.key");
    const X_CONTENT: &[u8] = include_bytes!("../../tests/fixtures/provider-age/x25519.age");
    const PQ_CONTENT: &[u8] = include_bytes!("../../tests/fixtures/provider-age/hybrid.age");
    const PLAIN: &[u8] = include_bytes!("../../tests/fixtures/provider-age/provider.yaml");

    fn control() -> DecodeControl<'static> {
        DecodeControl::new(None, Instant::now() + Duration::from_secs(30))
    }

    #[test]
    fn age_official_fixtures_multiline_and_plaintext() {
        let identities = Identities::parse(&format!(
            "# public fixture identities\n\n{}\n{}\n",
            X_KEY.trim_end(),
            PQ_KEY.trim_end()
        ))
        .unwrap();
        for bytes in [X_CONTENT, PQ_CONTENT, PLAIN] {
            let decoded = decode(bytes, Some(&identities), &control(), PLAIN.len()).unwrap();
            assert_eq!(decoded.as_ref(), PLAIN);
        }
        assert!(matches!(
            decode(PLAIN, None, &control(), 0).unwrap(),
            Decoded::Plain(_)
        ));
        let prefixed = [b" ".as_slice(), X_CONTENT].concat();
        assert!(matches!(
            decode(&prefixed, None, &control(), 0).unwrap(),
            Decoded::Plain(_)
        ));
        assert!(!format!("{identities:?}").contains(X_KEY.trim_end()));
    }

    #[test]
    fn age_authentication_and_processing_budget_fail_closed() {
        let identities = Identities::parse(X_KEY.trim_end()).unwrap();
        assert!(decode(PQ_CONTENT, Some(&identities), &control(), PLAIN.len()).is_err());
        assert!(decode(X_CONTENT, Some(&identities), &control(), PLAIN.len() - 1).is_err());
        let mut binary = Vec::new();
        age::armor::ArmoredReader::new(X_CONTENT)
            .read_to_end(&mut binary)
            .unwrap();
        *binary.last_mut().unwrap() ^= 1;
        let mut damaged = Vec::new();
        let mut armor =
            age::armor::ArmoredWriter::wrap_output(&mut damaged, age::armor::Format::AsciiArmor)
                .unwrap();
        armor.write_all(&binary).unwrap();
        armor.finish().unwrap();
        assert!(decode(&damaged, Some(&identities), &control(), PLAIN.len()).is_err());
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(
            decode(
                X_CONTENT,
                Some(&identities),
                &DecodeControl::new(
                    Some(&cancellation),
                    Instant::now() + Duration::from_secs(30)
                ),
                PLAIN.len()
            )
            .is_err()
        );
        assert!(
            decode(
                X_CONTENT,
                Some(&identities),
                &DecodeControl::new(None, Instant::now()),
                PLAIN.len()
            )
            .is_err()
        );
        let error = Identities::parse(&format!("{}\ninvalid-private-fixture", X_KEY.trim_end()))
            .unwrap_err();
        assert!(!error.to_string().contains("invalid-private-fixture"));
        assert!(!error.to_string().contains(X_KEY.trim_end()));
    }
}
