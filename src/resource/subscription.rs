//! Bounded numeric subscription metadata; raw headers are never retained.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct SubscriptionInfo {
    pub upload: i64,
    pub download: i64,
    pub total: i64,
    pub expire: i64,
}

impl SubscriptionInfo {
    pub fn parse(header: &str) -> Option<Self> {
        if header.is_empty() {
            return None;
        }
        let normalized = header.to_ascii_lowercase().replace(' ', "");
        let mut info = Self::default();
        for field in normalized.split(';') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            let slot = match name {
                "upload" => &mut info.upload,
                "download" => &mut info.download,
                "total" => &mut info.total,
                "expire" => &mut info.expire,
                _ => continue,
            };
            if let Some(value) = parse_value(value) {
                *slot = value;
            }
        }
        Some(info)
    }
}

fn parse_value(value: &str) -> Option<i64> {
    if let Ok(value) = value.parse::<i64>() {
        return Some(value);
    }
    let value = value.parse::<f64>().ok()?;
    // The upper bound is exclusive: i64::MAX rounds to 2^63 in f64.
    (value.is_finite()
        && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value))
    .then_some(value as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_header_matches_subscription_fields_without_retaining_raw_values() {
        let info = SubscriptionInfo::parse(
            " Upload = 12 ; DOWNLOAD=3.9; total=1e4; expire=-4.8; upload=19; upload=invalid; other=55",
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(info).unwrap(),
            serde_json::json!({"Upload":19,"Download":3,"Total":10000,"Expire":-4})
        );
        assert_eq!(SubscriptionInfo::parse(""), None);
        assert_eq!(
            SubscriptionInfo::parse("upload=NaN;download=Inf;total=9223372036854775808;expire=bad"),
            Some(SubscriptionInfo::default())
        );
        assert_eq!(
            SubscriptionInfo::parse("upload=9223372036854775807;download=-9223372036854775808"),
            Some(SubscriptionInfo {
                upload: i64::MAX,
                download: i64::MIN,
                ..Default::default()
            })
        );
    }
}
