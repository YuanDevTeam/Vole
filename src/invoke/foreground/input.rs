//! Foreground-only bounded source selection and shared AGE decryption.
use super::{InvokeFailure, Paths, failure, io_failure, read_config};
use crate::{config::MAX_CONFIG_BYTES, resource::age_provider};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(super) const MAX_ENCODED_BYTES: usize = MAX_CONFIG_BYTES.div_ceil(3) * 4;
const MAX_SECRET_BYTES: usize = 16 * 1024;

pub(super) fn private_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

fn option_text(
    value: Option<Zeroizing<String>>,
    environment: &str,
    limit: usize,
) -> Result<Option<Zeroizing<String>>, InvokeFailure> {
    let value = match value {
        Some(value) => Some(value),
        None => match std::env::var(environment) {
            Ok(value) => Some(Zeroizing::new(value)),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(value)) => {
                drop(Zeroizing::new(value.into_encoded_bytes()));
                return Err(failure("foreground text environment requires UTF-8"));
            }
        },
    };
    if value.as_ref().is_some_and(|value| value.len() > limit) {
        return Err(failure("foreground text input exceeds byte limit"));
    }
    Ok(value.filter(|value| !value.is_empty()))
}

pub(super) struct SourceOptions {
    pub(super) config: Option<Zeroizing<String>>,
    pub(super) key: Option<Zeroizing<String>>,
}
pub(super) fn options(
    config: Option<Zeroizing<String>>,
    key: Option<Zeroizing<String>>,
) -> Result<SourceOptions, InvokeFailure> {
    Ok(SourceOptions {
        config: option_text(config, "VOLE_CONFIG_STRING", MAX_ENCODED_BYTES)?,
        key: option_text(key, "VOLE_AGE_SECRET_KEY", MAX_SECRET_BYTES)?,
    })
}

pub(super) struct MainInput {
    bytes: Zeroizing<Vec<u8>>,
    key: Option<Zeroizing<String>>,
}
impl MainInput {
    pub(super) fn read(
        config: Option<Zeroizing<String>>,
        key: Option<Zeroizing<String>>,
        paths: &Paths,
        stdin: impl FnOnce() -> std::io::Result<Vec<u8>>,
    ) -> Result<Self, InvokeFailure> {
        // The alternative input is never opened, locked or probed.
        let bytes = if let Some(mut encoded) = config.filter(|value| !value.is_empty()) {
            if encoded.len() > MAX_ENCODED_BYTES {
                return Err(failure("encoded configuration exceeds byte limit"));
            }
            // Go's StdEncoding ignores CR/LF but still requires standard padding.
            encoded.retain(|character| !matches!(character, '\r' | '\n'));
            let mut bytes = Zeroizing::new(Vec::new());
            STANDARD
                .decode_vec(encoded.as_bytes(), &mut bytes)
                .map_err(|_| failure("invalid Base64 configuration"))?;
            drop(encoded);
            bytes
        } else {
            Zeroizing::new(if paths.stdin {
                stdin().map_err(|error| io_failure("read configuration input", error))?
            } else {
                read_config(&paths.config_file)
                    .map_err(|error| io_failure("read configuration file", error))?
            })
        };
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(failure("configuration exceeds byte limit"));
        }
        Ok(Self { bytes, key })
    }

    pub(super) fn into_yaml(
        self,
        cancellation: Option<&CancellationToken>,
    ) -> Result<String, InvokeFailure> {
        let Self { bytes, key } = self;
        // A supplied key does not add a failure path to an ordinary YAML input.
        let identities = if bytes.starts_with(age_provider::ARMOR_HEADER) {
            key.as_deref()
                .filter(|value| !value.is_empty())
                .map(|key| age_provider::Identities::parse(key))
                .transpose()
                .map_err(|_| failure("invalid AGE configuration identity"))?
        } else {
            None
        };
        drop(key);
        let control = age_provider::DecodeControl::new(
            cancellation,
            Instant::now() + Duration::from_secs(30),
        );
        let decrypted =
            match age_provider::decode(&bytes, identities.as_ref(), &control, MAX_CONFIG_BYTES)
                .map_err(|_| failure("configuration decryption failed"))?
            {
                age_provider::Decoded::Plain(_) => None,
                age_provider::Decoded::Decrypted(plaintext) => Some(plaintext),
            };
        // unwrap_or consumes and clears ciphertext when a plaintext allocation exists.
        let mut plaintext = decrypted.unwrap_or(bytes);
        String::from_utf8(std::mem::take(&mut *plaintext)).map_err(|error| {
            drop(Zeroizing::new(error.into_bytes()));
            failure("configuration is not UTF-8")
        })
    }
}

/// Enforce text limits before creating a potentially escaped JSON String/Value.
pub(super) fn check_envelope(request: &str) -> Result<(), InvokeFailure> {
    use serde_json::value::RawValue;
    let envelope: super::super::RawRequestEnvelope<'_> = serde_json::from_str(request)
        .map_err(|_| failure("invalid foreground request envelope"))?;
    if envelope.method.get().len() > 6 * "foreground".len() + 2
        || !serde_json::from_str::<String>(envelope.method.get())
            .is_ok_and(|method| method == "foreground")
    {
        return Ok(());
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Input<'a> {
        #[serde(borrow)]
        config_string: Option<&'a RawValue>,
        #[serde(borrow)]
        age_secret_key: Option<&'a RawValue>,
    }
    let input: Input<'_> = serde_json::from_str(envelope.payload.get())
        .map_err(|_| failure("invalid foreground input"))?;
    for (raw, limit) in [
        (input.config_string, MAX_ENCODED_BYTES),
        (input.age_secret_key, MAX_SECRET_BYTES),
    ] {
        if let Some(raw) = raw {
            super::super::check_json_string_limit(raw.get(), limit)
                .map_err(|_| failure("foreground text input exceeds limit or is not a string"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn paths(stdin: bool) -> Paths {
        Paths {
            data_dir: PathBuf::from("/absent"),
            config_file: PathBuf::from("/absent/config.yaml"),
            stdin,
        }
    }
    fn private(value: &str) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(value.to_owned()))
    }
    #[test]
    fn base64_has_priority_over_explicit_stdin_and_files() {
        let encoded = STANDARD.encode(b"rules: ['MATCH,DIRECT']");
        let encoded = format!("{}\r\n{}", &encoded[..4], &encoded[4..]);
        for stdin in [false, true] {
            let input = MainInput::read(private(&encoded), None, &paths(stdin), || {
                panic!("stdin read")
            })
            .unwrap();
            assert_eq!(input.into_yaml(None).unwrap(), "rules: ['MATCH,DIRECT']");
        }
        assert_eq!(
            MainInput::read(
                private(""),
                None,
                &paths(true),
                || Ok(b"rules: []".to_vec())
            )
            .unwrap()
            .into_yaml(None)
            .unwrap(),
            "rules: []"
        );
        for encoded in ["c2VjcmV0=", "c2VjcmV0_", "eA"] {
            assert!(
                MainInput::read(private(encoded), None, &paths(true), || panic!(
                    "stdin read"
                ))
                .is_err()
            );
        }
    }
    #[test]
    fn foreground_age_reuses_authenticated_official_vectors_and_bounds() {
        let key = include_str!("../../../tests/fixtures/provider-age/x25519.key");
        let content = include_bytes!("../../../tests/fixtures/provider-age/x25519.age");
        let expected = include_str!("../../../tests/fixtures/provider-age/provider.yaml");
        let input = MainInput::read(
            private(&STANDARD.encode(content)),
            private(key),
            &paths(true),
            || panic!("stdin read"),
        )
        .unwrap();
        assert_eq!(input.into_yaml(None).unwrap(), expected);
        let input = MainInput::read(None, None, &paths(true), || Ok(content.to_vec())).unwrap();
        assert!(input.into_yaml(None).is_err());
        let input = MainInput::read(
            None,
            private("invalid-private-fixture"),
            &paths(true),
            || Ok(b"rules: []".to_vec()),
        )
        .unwrap();
        assert_eq!(input.into_yaml(None).unwrap(), "rules: []");
        let input =
            MainInput::read(None, private(key), &paths(true), || Ok(content.to_vec())).unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(input.into_yaml(Some(&cancellation)).is_err());
        let input = MainInput::read(
            private(&"x".repeat(MAX_ENCODED_BYTES + 1)),
            None,
            &paths(true),
            || panic!("stdin read"),
        );
        assert!(input.is_err());
    }
    #[test]
    fn foreground_envelope_checks_decoded_lengths_without_disclosing_values() {
        for field in ["configString", "ageSecretKey"] {
            let bytes = if field == "configString" {
                MAX_ENCODED_BYTES
            } else {
                MAX_SECRET_BYTES
            };
            let request =
                serde_json::json!({"method":"foreground", "payload":{field:"x".repeat(bytes+1)}})
                    .to_string();
            assert!(check_envelope(&request).is_err());
        }
        let request = r#"{"method":"foreground","payload":{"ageSecretKey":"\u0078\u0078"}}"#;
        assert!(check_envelope(request).is_ok());
    }
}
