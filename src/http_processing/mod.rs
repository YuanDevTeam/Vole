//! Business HTTP processing. Core-owned HTTP never enters this module.
#[cfg(feature = "inbound-http")]
mod authority;
pub(crate) mod body;
pub(crate) mod body_budget;
pub(crate) mod config;
#[cfg(feature = "http-diagnostics")]
#[doc(hidden)]
pub mod diagnostics;
#[cfg(not(feature = "http-diagnostics"))]
pub(crate) mod diagnostics;
pub(crate) mod headers;
mod mitm;
mod numeric_input;
mod origin;
pub(crate) mod private_context;
pub(crate) mod rules;
pub(crate) mod script_config;
#[cfg(feature = "inbound-http")]
pub(crate) mod script_message;
pub(crate) mod scripts;
pub(crate) use config::{MAX_ADDENDUM, Policy};
#[cfg(feature = "inbound-http")]
mod h1;
#[cfg(feature = "inbound-http")]
pub(crate) mod h1_body;
#[cfg(feature = "inbound-http")]
mod h2;
#[cfg(feature = "inbound-http")]
mod h2_body;
#[cfg(feature = "inbound-http")]
mod h2_h1;
#[cfg(feature = "inbound-http")]
mod h2_headers;
#[cfg(feature = "inbound-http")]
mod h2_reuse;
#[cfg(all(test, feature = "inbound-http"))]
mod h2_tests;
#[cfg(feature = "inbound-http")]
pub(crate) mod io;
#[cfg(feature = "inbound-http")]
mod request;

#[cfg(feature = "inbound-http")]
use crate::{dispatch::Dispatcher, security::SecurityContext};
#[cfg(feature = "inbound-http")]
use std::sync::Arc;

/// Fixed-session snapshot. The dispatcher itself owns its resource-generation
/// lease; no second generation owner or policy-to-runtime cycle is introduced.
#[cfg(feature = "inbound-http")]
#[derive(Clone)]
#[doc(hidden)]
pub struct HttpContext {
    policy: Arc<Policy>,
    dispatcher: Arc<dyn Dispatcher>,
    security: SecurityContext,
}
#[cfg(feature = "inbound-http")]
impl HttpContext {
    pub(crate) fn new(
        policy: Arc<Policy>,
        dispatcher: Arc<dyn Dispatcher>,
        security: SecurityContext,
    ) -> Self {
        Self {
            policy,
            dispatcher,
            security,
        }
    }
    pub(super) fn policy(&self) -> &Policy {
        &self.policy
    }
    pub(crate) fn dispatcher(&self) -> &Arc<dyn Dispatcher> {
        &self.dispatcher
    }
    pub(super) fn security(&self) -> &SecurityContext {
        &self.security
    }
    pub(crate) fn plain_port(&self, port: u16) -> bool {
        self.policy.plain_port(port)
    }
    pub(crate) fn candidate_port(&self, port: u16) -> bool {
        self.plain_port(port)
            || self
                .policy
                .mitm()
                .is_some_and(|policy| policy.candidate_port(port))
    }
}
#[cfg(feature = "inbound-http")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}
#[cfg(feature = "inbound-http")]
impl Scheme {
    fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}
#[cfg(feature = "inbound-http")]
pub(crate) enum Intercept {
    Handled,
    Transparent { prefix: Vec<u8> },
}

#[cfg(all(test, feature = "inbound-http"))]
mod h1_boundary_tests;
#[cfg(all(test, feature = "inbound-http"))]
mod tests;

#[cfg(test)]
mod h2_frame_validation;
