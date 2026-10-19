//! Latest-only, flat HTTP rule input types.
use serde::{Deserialize, Deserializer, Serialize};

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)?
        .map(Some)
        .ok_or_else(|| serde::de::Error::custom("null is not an omitted rule parameter"))
}

fn enabled() -> bool {
    true
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RawRule {
    pub(crate) url: String,
    #[serde(default, rename = "match")]
    pub(crate) match_kind: MatchKind,
    pub(crate) action: ActionKind,
    #[serde(default = "enabled")]
    pub(crate) enabled: bool,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) name: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) replacement: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) replacement_mode: Option<ReplacementMode>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) header: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) value: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) search: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) search_mode: Option<SearchMode>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) occurrences: Option<Occurrences>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) patch: Option<Vec<PatchOperation>>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MatchKind {
    #[default]
    Regex,
    Exact,
    Prefix,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReplacementMode {
    #[default]
    Match,
    Url,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SearchMode {
    #[default]
    Literal,
    Regex,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Occurrences {
    First,
    #[default]
    All,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ActionKind {
    Replace,
    Redirect302,
    Redirect307,
    Reject,
    RequestHeaderSet,
    RequestHeaderAdd,
    RequestHeaderRemove,
    RequestHeaderReplace,
    ResponseHeaderSet,
    ResponseHeaderAdd,
    ResponseHeaderRemove,
    ResponseHeaderReplace,
    RequestBodySet,
    RequestBodyReplace,
    RequestBodyJsonPatch,
    ResponseBodySet,
    ResponseBodyReplace,
    ResponseBodyJsonPatch,
}

impl ActionKind {
    pub(crate) fn is_url(self) -> bool {
        matches!(
            self,
            Self::Replace | Self::Redirect302 | Self::Redirect307 | Self::Reject
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Request,
    Response,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "op", deny_unknown_fields, rename_all = "lowercase")]
pub(crate) enum PatchOperation {
    Add {
        path: String,
        value: serde_json::Value,
    },
    Remove {
        path: String,
    },
    Replace {
        path: String,
        value: serde_json::Value,
    },
    Move {
        from: String,
        path: String,
    },
    Copy {
        from: String,
        path: String,
    },
    Test {
        path: String,
        value: serde_json::Value,
    },
}
