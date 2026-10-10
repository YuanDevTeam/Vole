use std::{io, net::IpAddr, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Client-proxy credentials shared by the HTTP and SOCKS5 frontends.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    entries: Vec<(Arc<str>, String)>,
}

impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .finish_non_exhaustive()
    }
}

impl ProxyCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> io::Result<Self> {
        let username = username.into();
        let password = password.into();
        for (kind, value) in [("user", &username), ("password", &password)] {
            if !(1..=255).contains(&value.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("authentication {kind} must contain between 1 and 255 UTF-8 bytes"),
                ));
            }
        }
        if username.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authentication user must not contain `:`",
            ));
        }
        Ok(Self {
            entries: vec![(Arc::from(username), password)],
        })
    }

    #[must_use]
    pub fn matches(&self, username: &[u8], password: &[u8]) -> bool {
        self.authenticate(username, password).is_some()
    }

    pub(crate) fn authenticate(&self, username: &[u8], password: &[u8]) -> Option<Arc<str>> {
        let mut matched = None;
        for (expected_user, expected_password) in &self.entries {
            let mut difference = username.len() ^ expected_user.len();
            difference |= password.len() ^ expected_password.len();
            for index in 0..255 {
                difference |= usize::from(
                    username.get(index).copied().unwrap_or(0)
                        ^ expected_user.as_bytes().get(index).copied().unwrap_or(0),
                );
                difference |= usize::from(
                    password.get(index).copied().unwrap_or(0)
                        ^ expected_password
                            .as_bytes()
                            .get(index)
                            .copied()
                            .unwrap_or(0),
                );
            }
            if difference == 0 {
                matched = Some(expected_user.clone());
            }
        }
        matched
    }
    pub(crate) fn multiple(values: Vec<Self>) -> Self {
        let mut entries = std::collections::BTreeMap::new();
        for (username, password) in values.into_iter().flat_map(|value| value.entries) {
            entries.insert(username, password);
        }
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    #[must_use]
    pub fn authorization_header_value(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.entries[0].0, self.entries[0].1))
        )
    }

    #[cfg(test)]
    pub(crate) fn verifies(&self, headers: &[(String, String)]) -> bool {
        self.authenticate_headers(headers).is_some()
    }

    pub(crate) fn authenticate_headers(&self, headers: &[(String, String)]) -> Option<Arc<str>> {
        let mut values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, value)| value.as_str());
        let (Some(value), None) = (values.next(), values.next()) else {
            return None;
        };
        let mut parts = value.split_ascii_whitespace();
        let (Some(scheme), Some(encoded), None) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        if !scheme.eq_ignore_ascii_case("basic") || encoded.len() > 684 {
            return None;
        }
        let Ok(decoded) = STANDARD.decode(encoded) else {
            return None;
        };
        let separator = decoded.iter().position(|&byte| byte == b':')?;
        self.authenticate(&decoded[..separator], &decoded[separator + 1..])
    }
}

/// A fixed client-oriented listener policy, not an arbitrary address list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyAccess {
    pub bind_address: Option<IpAddr>,
    pub allow_lan: bool,
    pub ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAccessRules {
    pub allowed: Vec<super::IpCidr>,
    pub denied: Vec<super::IpCidr>,
    pub skip_auth: Vec<super::IpCidr>,
}
impl Default for ProxyAccessRules {
    fn default() -> Self {
        Self {
            allowed: vec![
                super::IpCidr {
                    network: "0.0.0.0".parse().unwrap(),
                    prefix_len: 0,
                },
                super::IpCidr {
                    network: "::".parse().unwrap(),
                    prefix_len: 0,
                },
            ],
            denied: Vec::new(),
            skip_auth: Vec::new(),
        }
    }
}
impl ProxyAccessRules {
    pub fn permits(&self, address: IpAddr) -> bool {
        self.allowed.iter().any(|cidr| cidr.contains(address))
            && !self.denied.iter().any(|cidr| cidr.contains(address))
    }
    pub fn skips_auth(&self, address: IpAddr) -> bool {
        self.skip_auth.iter().any(|cidr| cidr.contains(address))
    }
}
