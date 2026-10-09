use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupKind {
    #[default]
    Select,
    UrlTest,
    Fallback,
}
impl GroupKind {
    pub fn controller_type(self) -> &'static str {
        match self {
            Self::Select => "Selector",
            Self::UrlTest => "URLTest",
            Self::Fallback => "Fallback",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProfileConfig {
    pub store_fake_ip: bool,
    pub store_selected: bool,
}
impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            store_selected: true,
            store_fake_ip: false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct HealthCheckConfig {
    pub enable: bool,
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub lazy: bool,
    pub expected_status: String,
}
impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enable: false,
            url: String::new(),
            interval: 0,
            timeout: 5000,
            lazy: true,
            expected_status: String::new(),
        }
    }
}
impl HealthCheckConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.url.is_empty() {
            crate::resource::probe::Target::parse(&self.url).map_err(|_| {
                VoleError::InvalidConfig("health check requires an HTTP(S) URL".into())
            })?;
        }
        status_ranges(&self.expected_status)?;
        Ok(())
    }
}
pub(crate) fn status_ranges(value: &str) -> Result<Vec<(u16, u16)>> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Ok(Vec::new());
    }
    value
        .split('/')
        .map(|part| {
            let (first, last) = part.split_once('-').unwrap_or((part, part));
            let start = first
                .parse::<u16>()
                .map_err(|_| VoleError::InvalidConfig("invalid expected-status".into()))?;
            let end = last
                .parse::<u16>()
                .map_err(|_| VoleError::InvalidConfig("invalid expected-status".into()))?;
            if start > end {
                return invalid("invalid expected-status range");
            }
            Ok((start, end))
        })
        .collect()
}
