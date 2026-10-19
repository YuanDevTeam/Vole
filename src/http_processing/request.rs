//! Shared request decisions for HTTP/1 and HTTP/2, before any upstream IO.
use super::{HttpContext, Scheme, config::Action};
use crate::session::{Destination, StreamSession};
use std::{io, net::IpAddr};
use url::Url;

pub(super) struct Target {
    pub(super) original: Url,
    pub(super) url: Url,
    pub(super) session: StreamSession,
    pub(super) logical_destination: Destination,
    pub(super) strip_origin_credentials: bool,
}
pub(super) enum Decision {
    Forward(Box<Target>),
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
        // Authorization is per original HTTP authority, before any URL action.
        // One allowed TLS SNI never grants other authorities on this connection.
        if scheme == Scheme::Https && !self.permits_https(&original) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HTTPS authority is not permitted",
            ));
        }
        let original_matches_tls = scheme != Scheme::Https
            || (session.sniffed_domain.as_deref().is_some_and(|sni| {
                original
                    .host_str()
                    .is_some_and(|host| host.eq_ignore_ascii_case(sni))
            }) && original.port_or_known_default() == Some(session.destination.port()));
        let origin = (
            original.scheme() == "https",
            original.host_str().unwrap_or_default().to_owned(),
            original.port_or_known_default(),
        );
        let action = if apply_url_actions {
            self.policy().evaluate(original.clone())?
        } else {
            Action::Forward(original.clone())
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
        if strip_origin_credentials || !original_matches_tls {
            session.destination = destination.clone();
            session.sniffed_domain = None;
        } else if scheme == Scheme::Https {
            // Retain the fixed SNI's selected IP only for its own authority.
            session.sniffed_domain = Some(host.to_owned());
        }
        Ok(Decision::Forward(Box::new(Target {
            original,
            url,
            session,
            logical_destination: destination,
            strip_origin_credentials,
        })))
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid rewritten HTTP target")
}
