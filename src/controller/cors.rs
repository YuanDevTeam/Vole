use crate::config::ControllerCors;

#[derive(Clone)]
pub(super) struct Policy {
    all: bool,
    origins: Vec<String>,
    private_network: bool,
}

pub(super) struct Outcome {
    pub preflight: bool,
    pub headers: Vec<(String, String)>,
}

impl Policy {
    pub fn new(config: &ControllerCors) -> Self {
        Self {
            all: config.allow_origins.is_empty() || config.allow_origins.iter().any(|o| o == "*"),
            origins: config
                .allow_origins
                .iter()
                .map(|o| o.to_lowercase())
                .collect(),
            private_network: config.allow_private_network,
        }
    }

    pub fn evaluate(&self, method: &str, headers: &[(String, String)]) -> Outcome {
        let first = |name| super::header_values(headers, name).next();
        let origin = first("origin");
        let requested_method = first("access-control-request-method").unwrap_or("");
        let preflight = method == "OPTIONS" && origin.is_some() && !requested_method.is_empty();
        let mut outcome = Outcome {
            preflight,
            headers: vec![("Vary".into(), "Origin".into())],
        };
        if preflight {
            outcome.headers.extend([
                ("Vary".into(), "Access-Control-Request-Method".into()),
                ("Vary".into(), "Access-Control-Request-Headers".into()),
            ]);
        }
        let Some(origin) = origin else { return outcome };
        let normalized = origin.to_lowercase();
        let allowed = self.all
            || self.origins.iter().any(|pattern| {
                pattern.split_once('*').map_or_else(
                    || pattern == &normalized,
                    |(prefix, suffix)| {
                        normalized.len() >= prefix.len() + suffix.len()
                            && normalized.starts_with(prefix)
                            && normalized.ends_with(suffix)
                    },
                )
            });
        let requested_headers: Vec<String> = first("access-control-request-headers")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(|h| {
                h.split('-')
                    .map(|part| {
                        let mut bytes = part.to_ascii_lowercase().into_bytes();
                        if let Some(first) = bytes.first_mut() {
                            first.make_ascii_uppercase();
                        }
                        String::from_utf8(bytes).expect("ASCII header name")
                    })
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .collect();
        let allowed_headers = requested_headers
            .iter()
            .all(|h| matches!(h.as_str(), "Content-Type" | "Authorization" | "Origin"));
        let relevant_method = if preflight { requested_method } else { method };
        let allowed_method = matches!(
            relevant_method.to_ascii_uppercase().as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        );
        if !allowed || !allowed_method || (preflight && !allowed_headers) {
            return outcome;
        }
        outcome.headers.push((
            "Access-Control-Allow-Origin".into(),
            if self.all { "*".into() } else { origin.into() },
        ));
        if preflight {
            outcome.headers.push((
                "Access-Control-Allow-Methods".into(),
                requested_method.to_ascii_uppercase(),
            ));
            if !requested_headers.is_empty() {
                outcome.headers.push((
                    "Access-Control-Allow-Headers".into(),
                    requested_headers.join(", "),
                ));
            }
            if self.private_network
                && first("access-control-request-private-network") == Some("true")
            {
                outcome
                    .headers
                    .push(("Access-Control-Allow-Private-Network".into(), "true".into()));
            }
            outcome
                .headers
                .push(("Access-Control-Max-Age".into(), "300".into()));
        }
        outcome
    }
}
