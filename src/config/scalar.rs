//! String-backed numeric fields retain their normalizer's syntax and bounds.
use serde::{Deserializer, de::Visitor};

pub(super) fn string_or_integer<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct Scalar;

    impl Visitor<'_> for Scalar {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            Ok(value.to_owned())
        }

        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
            Ok(value)
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<String, E> {
            Ok(value.to_string())
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<String, E> {
            Ok(value.to_string())
        }
    }

    deserializer.deserialize_any(Scalar)
}

pub(super) fn optional_string_or_integer<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    string_or_integer(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::config::Config;

    fn health_document(status: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "mixed-port": 1080,
            "proxy-groups": [{
                "name": "pool", "type": "select", "proxies": ["DIRECT"],
                "expected-status": status
            }],
            "proxy-providers": {"local": {
                "type": "inline", "payload": [],
                "health-check": {"expected-status": status}
            }}
        }))
        .unwrap()
    }

    #[test]
    fn health_status_accepts_integer_and_string_for_groups_and_providers() {
        for value in [0, 204, 65535] {
            let numeric = Config::parse_yaml(&health_document(json!(value))).unwrap();
            let quoted = Config::parse_yaml(&health_document(json!(value.to_string()))).unwrap();
            assert_eq!(
                numeric.proxy_groups[0].health,
                quoted.proxy_groups[0].health
            );
            assert_eq!(
                numeric.providers.as_ref().unwrap().proxies[0]
                    .1
                    .health_check,
                quoted.providers.as_ref().unwrap().proxies[0].1.health_check
            );
            assert_eq!(
                numeric.proxy_groups[0].health.expected_status,
                value.to_string()
            );
        }
        let ranged = Config::parse_yaml(&health_document(json!("200-299/304"))).unwrap();
        assert_eq!(ranged.proxy_groups[0].health.expected_status, "200-299/304");
    }

    #[test]
    fn health_status_retains_type_and_status_bounds_in_both_locations() {
        for value in [
            json!(null),
            json!(true),
            json!(204.0),
            json!(-1),
            json!(65536),
        ] {
            for provider in [false, true] {
                let mut document: Value =
                    serde_json::from_slice(&health_document(json!(204))).unwrap();
                let field = if provider {
                    &mut document["proxy-providers"]["local"]["health-check"]["expected-status"]
                } else {
                    &mut document["proxy-groups"][0]["expected-status"]
                };
                *field = value.clone();
                assert!(Config::parse_yaml(&serde_json::to_vec(&document).unwrap()).is_err());
            }
        }
    }
}
