//! Shared request decisions for HTTP/1 and HTTP/2, before any upstream IO.
use super::{HttpContext, Scheme, config::Action};
use crate::session::{Destination, StreamSession};
use std::{io, net::IpAddr};
use url::Url;

pub(super) struct Target {
    pub(super) url: Url,
    pub(super) session: StreamSession,
    pub(super) logical_destination: Destination,
    pub(super) strip_origin_credentials: bool,
}
pub(super) enum Decision {
    Forward(Target),
    Redirect { status: u16, url: Url },
    Reject,
}
impl HttpContext {
    pub(super) fn plan(
        &self,
        original: Url,
        mut session: StreamSession,
        scheme: Scheme,
        apply_url_actions: bool,
    ) -> io::Result<Decision> {
        // P12 replaces this check with per-original-authority MITM permission;
        // an allowed SNI alone never authorizes another HTTP authority.
        if scheme == Scheme::Https {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "HTTPS interception is not enabled",
            ));
        }
        let origin = (
            original.scheme() == "https",
            original.host_str().unwrap_or_default().to_owned(),
            original.port_or_known_default(),
        );
        let action = if apply_url_actions {
            self.policy().evaluate(original)?
        } else {
            Action::Forward(original)
        };
        let url = match action {
            Action::Reject => return Ok(Decision::Reject),
            Action::Redirect { status, url } => return Ok(Decision::Redirect { status, url }),
            Action::Forward(url) => url,
        };
        let strip_origin_credentials = origin.0 != (url.scheme() == "https")
            || origin.1 != url.host_str().unwrap_or_default()
            || origin.2 != url.port_or_known_default();
        let host = url.host_str().ok_or_else(invalid)?.trim_matches(['[', ']']);
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        let destination = match host.parse::<IpAddr>() {
            Ok(ip) => Destination::Ip((ip, port).into()),
            Err(_) => Destination::domain(host, port)?,
        };
        session.capture_original();
        // A same-origin path/query action must not re-resolve an already
        // selected TUN address or silently change its CDN endpoint.
        if strip_origin_credentials {
            session.destination = destination.clone();
            session.sniffed_domain = None;
        }
        Ok(Decision::Forward(Target {
            url,
            session,
            logical_destination: destination,
            strip_origin_credentials,
        }))
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid rewritten HTTP target")
}
