//! Resource acquisition shared by GeoData and providers.
pub(crate) mod age_provider;
pub(crate) mod bundle;
mod bundle_limits;
pub(crate) mod cache;
#[cfg(any(feature = "invoke", test))]
pub(crate) mod config_apply;
pub(crate) mod control;
pub(crate) mod http;
#[cfg(any(feature = "invoke", test))]
pub(crate) mod http_control;
pub(crate) mod paths;
pub(crate) mod probe;
pub(crate) mod profile;
pub(crate) mod provider_input;
pub(crate) mod subscription;
