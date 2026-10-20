//! Thin, bounded Controller adapter for temporary current-program switches.
use std::{fmt, io};

use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use tokio_util::sync::CancellationToken;

use super::{ControllerIo, read_small_json_body, write_error, write_response};
use crate::resource::control::{RuleUpdateError, RuntimeResources};

pub(super) async fn disable<S: ControllerIo>(
    stream: &mut S,
    request: crate::inbound::http::RequestHead,
    resources: Option<&dyn RuntimeResources>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if request.method != "PATCH" {
        return write_error(stream, 405, "Method not allowed", &[("Allow", "PATCH")]).await;
    }
    let Some(resources) = resources else {
        return write_error(stream, 404, "Resource not found", &[]).await;
    };
    let Some(body) = read_small_json_body(
        stream,
        &request.headers,
        request.buffered,
        cancellation.clone(),
    )
    .await?
    else {
        return Ok(());
    };
    let Ok(RulePatch(changes)) = serde_json::from_slice::<RulePatch>(&body) else {
        return write_error(stream, 400, "Body invalid", &[]).await;
    };
    if cancellation.is_cancelled() {
        return Ok(());
    }
    match resources.disable_rules(&changes) {
        Ok(()) => write_response(stream, 204, &[], &[]).await,
        Err(RuleUpdateError::NotFound) => write_error(stream, 404, "Resource not found", &[]).await,
        Err(RuleUpdateError::InvalidIndex) => {
            write_error(stream, 400, "Rule index invalid", &[]).await
        }
    }
}

#[derive(Debug)]
struct RulePatch(Vec<(usize, bool)>);
impl<'de> Deserialize<'de> for RulePatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PatchVisitor;
        impl<'de> Visitor<'de> for PatchVisitor {
            type Value = RulePatch;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a rule-index to disabled-bool object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut object: M) -> Result<Self::Value, M::Error> {
                let mut changes = Vec::new();
                while let Some(key) = object.next_key::<String>()? {
                    if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(de::Error::custom("rule index invalid"));
                    }
                    let index = key
                        .parse::<usize>()
                        .map_err(|_| de::Error::custom("rule index invalid"))?;
                    if changes.iter().any(|(old, _)| *old == index) {
                        return Err(de::Error::custom("duplicate rule index"));
                    }
                    changes.push((index, object.next_value::<bool>()?));
                }
                Ok(RulePatch(changes))
            }
        }
        deserializer.deserialize_map(PatchVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_is_one_strict_object_with_unique_unsigned_indexes_and_bool_values() {
        assert!(
            serde_json::from_str::<RulePatch>("{}")
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(
            serde_json::from_str::<RulePatch>(r#"{"0":true,"12":false}"#)
                .unwrap()
                .0,
            [(0, true), (12, false)]
        );
        for body in [
            r#"{"0":true,"0":false}"#,
            r#"{"0":true,"00":false}"#,
            r#"{"-1":true}"#,
            r#"{"1.0":true}"#,
            r#"{"0":null}"#,
            r#"{"0":"true"}"#,
            r#"{"0":1}"#,
            r#"{"9999999999999999999999999999999999999999":true}"#,
            "[]",
            "null",
            "{} {}",
        ] {
            assert!(serde_json::from_str::<RulePatch>(body).is_err(), "{body}");
        }
    }
}
