use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    config::{ExternalControllerConfig, MAX_CONTROLLER_SECRET_BYTES, validate_route_target_name},
    routing::{ProxyGroupError, ProxyGroupState, ProxyGroups},
    traffic::TunTrafficStats,
};

const CONTROLLER_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROLLER_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTROLLER_CONNECTIONS: usize = 8;
const MAX_CONTROLLER_BODY_BYTES: usize = 1024;

pub(crate) struct RuntimeController {
    listener: TcpListener,
    secret: Option<Arc<str>>,
    traffic: Option<Arc<TunTrafficStats>>,
    proxy_groups: Arc<ProxyGroups>,
    resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
}

impl std::fmt::Debug for RuntimeController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeController")
            .field("local_addr", &self.listener.local_addr().ok())
            .field("authenticated", &self.secret.is_some())
            .field("has_traffic", &self.traffic.is_some())
            .finish_non_exhaustive()
    }
}

impl RuntimeController {
    pub(crate) async fn bind(
        config: &ExternalControllerConfig,
        traffic: Option<Arc<TunTrafficStats>>,
        proxy_groups: Arc<ProxyGroups>,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(config.listen).await?,
            secret: config.secret.as_deref().map(Arc::from),
            traffic,
            proxy_groups,
            resources: None,
        })
    }

    pub(crate) fn with_resources(
        mut self,
        resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    ) -> Self {
        self.resources = resources;
        self
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(crate) async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => break,
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined {
                        tracing::warn!(
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "controller connection task failed"
                        );
                    }
                }
                accepted = self.listener.accept(), if tasks.len() < MAX_CONTROLLER_CONNECTIONS => {
                    let (stream, peer) = accepted?;
                    let secret = self.secret.clone();
                    let traffic = self.traffic.clone();
                    let proxy_groups = self.proxy_groups.clone();
                    let resources = self.resources.clone();
                    let child = cancellation.clone();
                    tasks.spawn(crate::resources::observation::task(async move {
                        if let Err(error) = handle_connection(
                            stream,
                            peer,
                            secret,
                            traffic,
                            proxy_groups,
                            resources,
                            child,
                        )
                        .await
                        {
                            tracing::debug!(
                                error_kind = ?error.kind(),
                                "controller request failed"
                            );
                        }
                    }));
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    secret: Option<Arc<str>>,
    traffic: Option<Arc<TunTrafficStats>>,
    proxy_groups: Arc<ProxyGroups>,
    resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if !peer.ip().is_loopback() {
        return write_error(&mut stream, 403, "Forbidden", &[]).await;
    }

    let request = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Ok(()),
        result = timeout(
            CONTROLLER_HEADER_TIMEOUT,
            crate::inbound::http::read_request_head(
                &mut stream,
                crate::inbound::DEFAULT_HEADER_LIMIT,
            ),
        ) => match result {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                write_error(&mut stream, 400, "Bad request", &[]).await?;
                return Err(error);
            }
            Err(_) => {
                write_error(&mut stream, 408, "Timeout", &[]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "controller request head timed out",
                ));
            }
        },
    };

    if !authorized(&request.headers, secret.as_deref()) {
        return write_error(
            &mut stream,
            401,
            "Unauthorized",
            &[("WWW-Authenticate", "Bearer")],
        )
        .await;
    }

    if request.target.contains(['?', '#']) {
        return write_error(&mut stream, 400, "Bad request", &[]).await;
    }

    if request.target == "/traffic" {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        return match traffic {
            Some(traffic) => write_json(&mut stream, 200, &traffic.snapshot(), &[]).await,
            None => write_error(&mut stream, 404, "Resource not found", &[]).await,
        };
    }

    if let Some(tail) = request.target.strip_prefix("/providers/") {
        let (kind, raw_name) = tail
            .split_once('/')
            .map_or((tail, None), |(kind, name)| (kind, Some(name)));
        let rules = match kind {
            "rules" => true,
            "proxies" => false,
            _ => return write_error(&mut stream, 404, "Resource not found", &[]).await,
        };
        let name = match raw_name {
            Some(raw) => match decode_group_name(raw) {
                Ok(name) => Some(name),
                Err(()) => return write_error(&mut stream, 400, "Bad request", &[]).await,
            },
            None => None,
        };
        let state = resources.as_ref().map_or_else(
            || serde_json::json!({"providers":{}}),
            |resources| resources.providers(rules),
        );
        if request.method == "GET" {
            if let Some(name) = name {
                return match state["providers"].get(&name) {
                    Some(value) => write_json(&mut stream, 200, value, &[]).await,
                    None => write_error(&mut stream, 404, "Resource not found", &[]).await,
                };
            }
            return write_json(&mut stream, 200, &state, &[]).await;
        }
        if request.method == "PUT"
            && let (Some(resources), Some(name)) = (&resources, name)
        {
            if state["providers"].get(&name).is_none() {
                return write_error(&mut stream, 404, "Resource not found", &[]).await;
            }
            let result = tokio::select! { biased; ()=cancellation.cancelled()=>return Ok(()), result=resources.refresh(rules,&name)=>result };
            return match result {
                Ok(()) => write_response(&mut stream, 204, &[], &[]).await,
                Err(_) => write_error(&mut stream, 503, "Provider update failed", &[]).await,
            };
        }
        return write_error(
            &mut stream,
            405,
            "Method not allowed",
            &[("Allow", "GET, PUT")],
        )
        .await;
    }
    let proxy_groups = resources
        .as_ref()
        .map_or(proxy_groups, |resources| resources.groups());

    if request.target == "/proxies" {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let mut health = resources.as_ref().map_or_else(
            || serde_json::json!({"proxies":{}}),
            |resources| resources.health(),
        );
        for state in proxy_groups.list_states() {
            let name = state.name.clone();
            health["proxies"][name] =
                serde_json::to_value(GroupResponse::from(state)).expect("group status");
        }
        return write_json(&mut stream, 200, &health, &[]).await;
    }

    if request.target == "/group" {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let proxies = proxy_groups
            .list_states()
            .into_iter()
            .map(GroupResponse::from)
            .collect();
        return write_json(&mut stream, 200, &GroupListResponse { proxies }, &[]).await;
    }

    if let Some(raw_name) = request.target.strip_prefix("/group/") {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let name = match decode_group_name(raw_name) {
            Ok(name) => name,
            Err(()) => return write_error(&mut stream, 400, "Bad request", &[]).await,
        };
        return match proxy_groups.state(&name) {
            Ok(state) => write_json(&mut stream, 200, &GroupResponse::from(state), &[]).await,
            Err(ProxyGroupError::UnknownGroup) => {
                write_error(&mut stream, 404, "Resource not found", &[]).await
            }
            Err(ProxyGroupError::UnknownMember) => unreachable!("state does not select a member"),
        };
    }

    if let Some(raw_name) = request.target.strip_prefix("/proxies/") {
        let name = match decode_group_name(raw_name) {
            Ok(name) => name,
            Err(()) => return write_error(&mut stream, 400, "Bad request", &[]).await,
        };
        return match request.method.as_str() {
            "GET" => match proxy_groups.state(&name) {
                Ok(state) => write_json(&mut stream, 200, &GroupResponse::from(state), &[]).await,
                Err(_) => {
                    let health = resources.as_ref().map(|resources| resources.health());
                    match health
                        .as_ref()
                        .and_then(|state| state["proxies"].get(&name))
                    {
                        Some(node) => write_json(&mut stream, 200, node, &[]).await,
                        None => write_error(&mut stream, 404, "Resource not found", &[]).await,
                    }
                }
            },
            "PUT" => {
                handle_select(
                    &mut stream,
                    &request.headers,
                    request.buffered,
                    &name,
                    &proxy_groups,
                    resources.as_deref(),
                    cancellation,
                )
                .await
            }
            _ => {
                write_error(
                    &mut stream,
                    405,
                    "Method not allowed",
                    &[("Allow", "GET, PUT")],
                )
                .await
            }
        };
    }

    write_error(&mut stream, 404, "Resource not found", &[]).await
}

async fn handle_select(
    stream: &mut TcpStream,
    headers: &[(String, String)],
    mut body: Vec<u8>,
    group: &str,
    proxy_groups: &ProxyGroups,
    resources: Option<&dyn crate::resource::control::RuntimeResources>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    if header_values(headers, "transfer-encoding").next().is_some() {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }

    let mut content_types = header_values(headers, "content-type");
    let valid_content_type = content_types
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        && content_types.next().is_none();
    if !valid_content_type {
        return write_error(stream, 415, "Unsupported media type", &[]).await;
    }

    let mut content_lengths = header_values(headers, "content-length");
    let Some(content_length) = content_lengths.next() else {
        return write_error(stream, 411, "Length required", &[]).await;
    };
    if content_lengths.next().is_some()
        || content_length.is_empty()
        || !content_length.bytes().all(|byte| byte.is_ascii_digit())
    {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }
    let Ok(content_length) = content_length.parse::<usize>() else {
        return write_error(stream, 400, "Body invalid", &[]).await;
    };
    if content_length > MAX_CONTROLLER_BODY_BYTES {
        return write_error(stream, 413, "Payload too large", &[]).await;
    }
    if body.len() > content_length {
        return write_error(stream, 400, "Body invalid", &[]).await;
    }

    let buffered = body.len();
    body.resize(content_length, 0);
    if buffered != content_length {
        let read = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            result = timeout(
                CONTROLLER_BODY_TIMEOUT,
                stream.read_exact(&mut body[buffered..]),
            ) => result,
        };
        match read {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                write_error(stream, 400, "Body invalid", &[]).await?;
                return Err(error);
            }
            Err(_) => {
                write_error(stream, 408, "Timeout", &[]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "controller request body timed out",
                ));
            }
        }
    }

    let request = match serde_json::from_slice::<SelectRequest>(&body) {
        Ok(request) => request,
        Err(_) => return write_error(stream, 400, "Body invalid", &[]).await,
    };
    match resources.map_or_else(
        || proxy_groups.select(group, &request.name),
        |resources| resources.select(group, &request.name),
    ) {
        Ok(()) => write_response(stream, 204, &[], b"").await,
        Err(ProxyGroupError::UnknownGroup) => {
            write_error(stream, 404, "Resource not found", &[]).await
        }
        Err(ProxyGroupError::UnknownMember) => {
            write_error(
                stream,
                400,
                "Selector update error: route target not found",
                &[],
            )
            .await
        }
    }
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    expected: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(name, _)| name.eq_ignore_ascii_case(expected))
        .map(|(_, value)| value.as_str())
}

fn authorized(headers: &[(String, String)], secret: Option<&str>) -> bool {
    let Some(secret) = secret else {
        return true;
    };
    let mut authorization = header_values(headers, "authorization");
    let Some(value) = authorization.next() else {
        return false;
    };
    if authorization.next().is_some() {
        return false;
    }
    value
        .strip_prefix("Bearer ")
        .is_some_and(|token| controller_token_eq(token.as_bytes(), secret.as_bytes()))
}

fn controller_token_eq(candidate: &[u8], secret: &[u8]) -> bool {
    let mut difference = candidate.len() ^ secret.len();
    for index in 0..MAX_CONTROLLER_SECRET_BYTES {
        let candidate = candidate.get(index).copied().unwrap_or_default();
        let secret = secret.get(index).copied().unwrap_or_default();
        difference |= usize::from(candidate ^ secret);
    }
    difference == 0
}

fn decode_group_name(raw: &str) -> Result<String, ()> {
    if raw.is_empty() || raw.contains('/') {
        return Err(());
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_value)
                .ok_or(())?;
            let low = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_value)
                .ok_or(())?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let name = String::from_utf8(decoded).map_err(|_| ())?;
    validate_route_target_name(&name, "controller group name").map_err(|_| ())?;
    Ok(name)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectRequest {
    name: String,
}

#[derive(Serialize)]
struct GroupListResponse {
    proxies: Vec<GroupResponse>,
}

#[derive(Serialize)]
struct GroupResponse {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    all: Vec<String>,
    now: String,
    hidden: bool,
    icon: String,
}

impl From<ProxyGroupState> for GroupResponse {
    fn from(state: ProxyGroupState) -> Self {
        Self {
            name: state.name,
            kind: state.kind.controller_type(),
            all: state.all,
            now: state.now,
            hidden: state.hidden,
            icon: state.icon,
        }
    }
}

async fn write_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    value: &T,
    headers: &[(&str, &str)],
) -> io::Result<()> {
    let body = serde_json::to_vec(value).map_err(io::Error::other)?;
    let mut response_headers = Vec::with_capacity(headers.len() + 1);
    response_headers.push(("Content-Type", "application/json"));
    response_headers.extend_from_slice(headers);
    write_response(stream, status, &response_headers, &body).await
}

async fn write_error(
    stream: &mut TcpStream,
    status: u16,
    message: &'static str,
    headers: &[(&str, &str)],
) -> io::Result<()> {
    #[derive(Serialize)]
    struct ErrorResponse {
        message: &'static str,
    }
    write_json(stream, status, &ErrorResponse { message }, headers).await
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use serde_json::Value;

    use super::*;
    use crate::{
        config::{
            ProxyGroupMemberConfig, ProxyGroupMemberTarget, ProxyId, RouteTargetId,
            SelectProxyGroupConfig,
        },
        dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
        session::{DatagramSession, StreamSession},
    };

    struct UnusedDispatcher;

    #[async_trait]
    impl Dispatcher for UnusedDispatcher {
        async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }

        async fn open_datagram(
            &self,
            _session: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
    }

    fn test_groups() -> Arc<ProxyGroups> {
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(UnusedDispatcher);
        ProxyGroups::new(
            &[SelectProxyGroupConfig {
                kind: crate::config::GroupKind::Select,
                health: crate::config::HealthCheckConfig::default(),
                tolerance: 0,
                max_failed_times: 5,
                disable_udp: false,
                hidden: false,
                icon: String::new(),
                name: "主线路".to_owned(),
                members: vec![
                    ProxyGroupMemberConfig {
                        name: "node-a".to_owned(),
                        target: ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(0).unwrap(),
                        )),
                    },
                    ProxyGroupMemberConfig {
                        name: "node-b".to_owned(),
                        target: ProxyGroupMemberTarget::Route(RouteTargetId::Proxy(
                            ProxyId::new(1).unwrap(),
                        )),
                    },
                ],
                initial_member: 0,
            }],
            vec![dispatcher.clone(), dispatcher.clone()],
            dispatcher,
        )
        .unwrap()
    }

    async fn request(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    fn response_body(response: &str) -> &str {
        response.split_once("\r\n\r\n").unwrap().1
    }

    #[test]
    fn bearer_auth_is_strict_and_duplicate_safe() {
        let valid = vec![("Authorization".to_owned(), "Bearer token".to_owned())];
        assert!(authorized(&valid, Some("token")));
        assert!(authorized(&[], None));
        assert!(!authorized(&[], Some("token")));
        assert!(!authorized(
            &[("Authorization".to_owned(), "bearer token".to_owned())],
            Some("token")
        ));
        assert!(!authorized(
            &[
                ("Authorization".to_owned(), "Bearer token".to_owned()),
                ("authorization".to_owned(), "Bearer token".to_owned()),
            ],
            Some("token")
        ));
        assert!(!controller_token_eq(b"toke", b"token"));
        assert!(!controller_token_eq(b"token-longer", b"token"));
        let longest = vec![b'x'; MAX_CONTROLLER_SECRET_BYTES];
        assert!(controller_token_eq(&longest, &longest));
    }

    #[test]
    fn percent_decoding_is_single_pass_and_utf8_safe() {
        assert_eq!(
            decode_group_name("%E4%B8%BB%E7%BA%BF%E8%B7%AF").unwrap(),
            "主线路"
        );
        assert_eq!(decode_group_name("a+b").unwrap(), "a+b");
        assert_eq!(decode_group_name("%252F").unwrap(), "%2F");
        assert_eq!(decode_group_name("%2F").unwrap(), "/");
        assert!(decode_group_name("%GG").is_err());
        assert!(decode_group_name("%A").is_err());
        assert!(decode_group_name("%FF").is_err());
        assert_eq!(decode_group_name("..").unwrap(), "..");
    }

    #[tokio::test]
    async fn controller_lists_queries_and_switches_select_groups() {
        let groups = test_groups();
        let controller = RuntimeController::bind(
            &ExternalControllerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                secret: Some("secret".to_owned()),
            },
            None,
            groups.clone(),
        )
        .await
        .unwrap();
        let address = controller.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(controller.serve(cancellation.clone()));

        let unauthorized = request(address, "GET /group HTTP/1.1\r\n\r\n").await;
        assert!(unauthorized.starts_with("HTTP/1.1 401 Unauthorized\r\n"));

        let listed = request(
            address,
            "GET /group HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        assert!(listed.starts_with("HTTP/1.1 200 OK\r\n"));
        let listed: Value = serde_json::from_str(response_body(&listed)).unwrap();
        assert_eq!(listed["proxies"][0]["name"], "主线路");
        assert_eq!(listed["proxies"][0]["type"], "Selector");
        assert_eq!(
            listed["proxies"][0]["all"],
            serde_json::json!(["node-a", "node-b"])
        );
        assert_eq!(listed["proxies"][0]["now"], "node-a");

        let body = r#"{"name":"node-b"}"#;
        let switched = request(
            address,
            &format!(
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(switched.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert_eq!(groups.state("主线路").unwrap().now, "node-b");

        let queried = request(
            address,
            "GET /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
        )
        .await;
        let queried: Value = serde_json::from_str(response_body(&queried)).unwrap();
        assert_eq!(queried["now"], "node-b");

        cancellation.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn controller_rejects_invalid_selector_bodies_without_mutation() {
        let groups = test_groups();
        let controller = RuntimeController::bind(
            &ExternalControllerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                secret: Some("secret".to_owned()),
            },
            None,
            groups.clone(),
        )
        .await
        .unwrap();
        let address = controller.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(controller.serve(cancellation.clone()));

        let body = r#"{"name":"missing"}"#;
        let unknown = request(
            address,
            &format!(
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(unknown.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(groups.state("主线路").unwrap().now, "node-a");

        let smuggled = request(
            address,
            "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 17\r\nTransfer-Encoding: chunked\r\n\r\n{\"name\":\"node-b\"}",
        )
        .await;
        assert!(smuggled.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert_eq!(groups.state("主线路").unwrap().now, "node-a");

        let malformed = [
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Length: 17\r\n\r\n{\"name\":\"node-b\"}",
                415,
            ),
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 17\r\n\r\n{\"name\":\"node-b\"}",
                415,
            ),
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\n\r\n{\"name\":\"node-b\"}",
                411,
            ),
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 17\r\nContent-Length: 17\r\n\r\n{\"name\":\"node-b\"}",
                400,
            ),
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"name\":\"node-b\",\"extra\":1}",
                400,
            ),
            (
                "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 33\r\n\r\n{\"name\":\"node-a\",\"name\":\"node-b\"}",
                400,
            ),
            (
                "GET /proxies/node-a HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
                404,
            ),
            (
                "GET /traffic HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
                404,
            ),
            (
                "GET /group?name=x HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
                400,
            ),
            (
                "GET /group/%2F HTTP/1.1\r\nAuthorization: Bearer secret\r\n\r\n",
                400,
            ),
            ("GET /group/missing HTTP/1.1\r\n\r\n", 401),
        ];
        for (raw, status) in malformed {
            let response = request(address, raw).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} ")),
                "{response}"
            );
            assert!(response.contains("\r\nCache-Control: no-store\r\n"));
            assert_eq!(groups.state("主线路").unwrap().now, "node-a");
        }

        let oversized = request(
            address,
            "PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 1025\r\n\r\n",
        )
        .await;
        assert!(oversized.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));

        let mut half_body = TcpStream::connect(address).await.unwrap();
        half_body
            .write_all(
                b"PUT /proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{",
            )
            .await
            .unwrap();
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("controller stop must cancel a partial body")
            .unwrap()
            .unwrap();
    }
}
