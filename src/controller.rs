use std::{io, net::SocketAddr, sync::Arc, time::Duration};

#[cfg(any(feature = "invoke", test))]
mod configs;
mod cors;
mod dns;
mod tls;
mod transport;
mod websocket;
use transport::{ControllerIo, H1Io};

#[cfg(test)]
#[path = "controller/tests_secure.rs"]
mod secure_tests;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{io::AsyncReadExt, net::TcpListener, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use tokio::{io::AsyncWriteExt, net::TcpStream};

use crate::{
    config::{ExternalControllerConfig, validate_route_target_name},
    routing::{ProxyGroupError, ProxyGroupState, ProxyGroups},
    traffic::TunTrafficStats,
};

const CONTROLLER_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROLLER_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONTROLLER_CONNECTIONS: usize = 8;
const MAX_CONTROLLER_BODY_BYTES: usize = 1024;

#[derive(Clone)]
struct RequestContext {
    secret: Option<Arc<str>>,
    traffic: Option<Arc<TunTrafficStats>>,
    proxy_groups: Arc<ProxyGroups>,
    resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    cors: Arc<cors::Policy>,
    requests: tokio_util::task::TaskTracker,
    subscriptions: Arc<tokio::sync::Semaphore>,
    logs: Option<Arc<crate::logging::RuntimeLog>>,
}

pub(crate) struct RuntimeController {
    listener: Option<TcpListener>,
    tls_listener: Option<TcpListener>,
    tls: Option<Arc<tls::ServerTls>>,
    context: RequestContext,
}

impl std::fmt::Debug for RuntimeController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeController")
            .field("authenticated", &self.context.secret.is_some())
            .field("https", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl RuntimeController {
    #[cfg(test)]
    pub(crate) async fn bind(
        config: &ExternalControllerConfig,
        traffic: Option<Arc<TunTrafficStats>>,
        proxy_groups: Arc<ProxyGroups>,
    ) -> io::Result<Self> {
        Self::bind_at(config, traffic, proxy_groups, std::path::Path::new(".")).await
    }

    pub(crate) async fn bind_at(
        config: &ExternalControllerConfig,
        traffic: Option<Arc<TunTrafficStats>>,
        proxy_groups: Arc<ProxyGroups>,
        root: &std::path::Path,
    ) -> io::Result<Self> {
        let listener = config
            .http_enabled
            .then(|| bind_controller(config))
            .transpose()?;
        let (tls_listener, tls) = if let Some(listen) = config.tls_listen {
            let tls_options = config.server_tls.clone();
            let root = root.to_owned();
            let tls =
                tokio::task::spawn_blocking(move || tls::ServerTls::load(&tls_options, &root))
                    .await
                    .map_err(io::Error::other)??;
            let listener = bind_controller(&ExternalControllerConfig {
                listen,
                ..ExternalControllerConfig::default()
            })?;
            (Some(listener), Some(Arc::new(tls)))
        } else {
            (None, None)
        };
        Ok(Self {
            listener,
            tls_listener,
            tls,
            context: RequestContext {
                secret: config.secret.as_deref().map(Arc::from),
                traffic,
                proxy_groups,
                resources: None,
                cors: Arc::new(cors::Policy::new(&config.cors)),
                requests: tokio_util::task::TaskTracker::new(),
                subscriptions: Arc::new(tokio::sync::Semaphore::new(websocket::MAX_SUBSCRIPTIONS)),
                logs: crate::logging::current(),
            },
        })
    }

    pub(crate) fn with_resources(
        mut self,
        resources: Option<Arc<dyn crate::resource::control::RuntimeResources>>,
    ) -> Self {
        self.context.resources = resources;
        self
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener
            .as_ref()
            .or(self.tls_listener.as_ref())
            .expect("controller listener")
            .local_addr()
    }

    pub(crate) async fn serve(self, cancellation: CancellationToken) -> io::Result<()> {
        let watcher = self
            .tls
            .as_ref()
            .filter(|tls| tls.watches_files())
            .map(|tls| {
                let tls = tls.clone();
                let child = cancellation.clone();
                tokio::spawn(crate::resources::observation::task(tls.watch(child)))
            });
        let mut tasks = JoinSet::new();
        let result = loop {
            tokio::select! { biased;
                () = cancellation.cancelled() => break Ok(()),
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined { break Err(io::Error::other(error)); }
                }
                accepted = async { self.listener.as_ref().unwrap().accept().await }, if self.listener.is_some() && tasks.len() < MAX_CONTROLLER_CONNECTIONS => {
                    let (stream, _) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let context = self.context.clone(); let child = cancellation.clone();
                    tasks.spawn(crate::resources::observation::task(async move { let _ = handle_connection(H1Io(stream), context, child).await; }));
                }
                accepted = async { self.tls_listener.as_ref().unwrap().accept().await }, if self.tls_listener.is_some() && tasks.len() < MAX_CONTROLLER_CONNECTIONS => {
                    let (stream, _) = match accepted { Ok(value) => value, Err(error) => break Err(error) };
                    let tls = self.tls.as_ref().unwrap().clone(); let context = self.context.clone(); let child = cancellation.clone();
                    tasks.spawn(crate::resources::observation::task(async move {
                        let _ = transport::serve_tls(stream, tls, context, child).await;
                    }));
                }
            }
        };
        cancellation.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.context.requests.close();
        self.context.requests.wait().await;
        if let Some(watcher) = watcher {
            watcher.await.map_err(io::Error::other)?;
        }
        result
    }
}

fn bind_controller(config: &ExternalControllerConfig) -> io::Result<TcpListener> {
    let listen = if config.listen.ip().is_unspecified() {
        SocketAddr::from(([0u16; 8], config.listen.port()))
    } else {
        config.listen
    };
    match bind_controller_tcp(listen) {
        Err(error)
            if config.listen.ip().is_unspecified()
                && crate::inbound::listen::address_family_unavailable(&error) =>
        {
            bind_controller_tcp(SocketAddr::from(([0, 0, 0, 0], config.listen.port())))
        }
        result => result,
    }
}

fn bind_controller_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if address.is_ipv6() {
        // Go's tcp listener allows IPv4-mapped peers on an IPv6 wildcard.
        socket.set_only_v6(false)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

async fn handle_connection<S: ControllerIo>(
    mut stream: S,
    context: RequestContext,
    cancellation: CancellationToken,
) -> io::Result<()> {
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

    handle_request(stream, request, context, cancellation).await
}

async fn handle_request<S: ControllerIo>(
    stream: S,
    request: crate::inbound::http::RequestHead,
    context: RequestContext,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let subscription = websocket::requested(&request).then(|| context.clone());
    let RequestContext {
        secret,
        traffic,
        proxy_groups,
        resources,
        cors,
        ..
    } = context;
    let outcome = cors.evaluate(&request.method, &request.headers);
    let mut stream = transport::CorsIo::new(stream, outcome.headers);
    if outcome.preflight {
        return write_response(&mut stream, 200, &[], &[]).await;
    }
    if let Some(context) = subscription {
        return websocket::handle(&mut stream, request, context, cancellation).await;
    }
    if !authorized(&request.headers, secret.as_deref()) {
        return write_error(
            &mut stream,
            401,
            "Unauthorized",
            &[("WWW-Authenticate", "Bearer")],
        )
        .await;
    }

    if request.target == "/version" {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        return write_json(
            &mut stream,
            200,
            &serde_json::json!({"meta":false,"version":env!("CARGO_PKG_VERSION")}),
            &[],
        )
        .await;
    }
    if request.target == "/memory" {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let value = serde_json::json!({"inuse":crate::memory::resident_bytes(),"oslimit":null});
        return write_json(&mut stream, 200, &value, &[]).await;
    }
    let route_path = request
        .target
        .split_once('?')
        .map_or(request.target.as_str(), |(path, _)| path);
    let probe_route = route_path.strip_suffix("/delay").and_then(|base| {
        base.strip_prefix("/proxies/")
            .map(|name| (false, name))
            .or_else(|| base.strip_prefix("/group/").map(|name| (true, name)))
    });
    if let Some((group, raw_name)) = probe_route {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        return delay_query(
            &mut stream,
            group,
            raw_name,
            &request.target,
            resources.as_deref(),
            &cancellation,
        )
        .await;
    }
    if let Some(raw_name) = route_path
        .strip_prefix("/providers/proxies/")
        .and_then(|tail| tail.strip_suffix("/healthcheck"))
    {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let Ok(name) = decode_group_name(raw_name) else {
            return write_error(&mut stream, 400, "Bad request", &[]).await;
        };
        let Some(resources) = resources.as_deref() else {
            return write_error(&mut stream, 404, "Resource not found", &[]).await;
        };
        let result = tokio::select! { biased;
            () = cancellation.cancelled() => return Ok(()),
            result = resources.provider_healthcheck(&name, &cancellation) => result,
        };
        return match result {
            Ok(()) => write_response(&mut stream, 204, &[], &[]).await,
            Err(error) => probe_error(&mut stream, error).await,
        };
    }

    if request.target == "/dns/query" || request.target.starts_with("/dns/query?") {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        return dns::query(
            &mut stream,
            &request.target,
            resources.as_deref(),
            cancellation,
        )
        .await;
    }

    if request.target.contains(['?', '#']) {
        return write_error(&mut stream, 400, "Bad request", &[]).await;
    }

    #[cfg(any(feature = "invoke", test))]
    if matches!(
        request.target.as_str(),
        "/cache/fakeip/flush" | "/configs/geo"
    ) {
        return configs::maintenance(&mut stream, request, resources.as_deref(), cancellation)
            .await;
    }

    if request.target == "/cache/dns/flush" {
        if request.method != "POST" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "POST")]).await;
        }
        if let Some(snapshot) = resources.as_ref().and_then(|resources| resources.dns()) {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Ok(()),
                () = snapshot.dns.flush_cache() => {}
            }
        }
        return write_response(&mut stream, 204, &[], &[]).await;
    }

    #[cfg(any(feature = "invoke", test))]
    if request.target == "/configs" && matches!(request.method.as_str(), "PATCH" | "PUT") {
        return configs::apply(&mut stream, request, resources.as_deref(), cancellation).await;
    }
    if matches!(request.target.as_str(), "/configs" | "/rules") {
        if request.method != "GET" {
            return write_error(&mut stream, 405, "Method not allowed", &[("Allow", "GET")]).await;
        }
        let Some(resources) = &resources else {
            return write_error(&mut stream, 404, "Resource not found", &[]).await;
        };
        let value = if request.target == "/configs" {
            resources.configs()
        } else {
            resources.rules()
        };
        return write_json(&mut stream, 200, &value, &[]).await;
    }
    if request.target == "/connections" || request.target.starts_with("/connections/") {
        let Some(resources) = &resources else {
            return write_error(&mut stream, 404, "Resource not found", &[]).await;
        };
        let registry = resources.connections();
        if request.method == "GET" && request.target == "/connections" {
            let snapshot = registry.snapshot();
            return write_json(&mut stream, 200, &snapshot, &[]).await;
        }
        if request.method == "DELETE" {
            if let Some(raw_id) = request.target.strip_prefix("/connections/") {
                let Ok(id) = decode_group_name(raw_id) else {
                    return write_error(&mut stream, 400, "Bad request", &[]).await;
                };
                registry.close(&id);
            } else {
                registry.close_all();
            }
            return write_response(&mut stream, 204, &[], &[]).await;
        }
        return write_error(
            &mut stream,
            405,
            "Method not allowed",
            &[(
                "Allow",
                if request.target == "/connections" {
                    "GET, DELETE"
                } else {
                    "DELETE"
                },
            )],
        )
        .await;
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
            Err(ProxyGroupError::UnknownMember | ProxyGroupError::NotSelectable) => {
                unreachable!("state does not select a member")
            }
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
            "DELETE" => {
                let result = resources.as_ref().map_or_else(
                    || proxy_groups.clear_fixed(&name),
                    |resources| resources.clear_fixed(&name),
                );
                match result {
                    Ok(()) => write_response(&mut stream, 204, &[], &[]).await,
                    Err(ProxyGroupError::UnknownGroup) => {
                        if resources
                            .as_ref()
                            .is_some_and(|r| r.health()["proxies"].get(&name).is_some())
                        {
                            write_error(&mut stream, 400, "Proxy is not an automatic group", &[])
                                .await
                        } else {
                            write_error(&mut stream, 404, "Resource not found", &[]).await
                        }
                    }
                    Err(_) => {
                        write_error(&mut stream, 400, "Proxy is not an automatic group", &[]).await
                    }
                }
            }
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
                    &[("Allow", "GET, PUT, DELETE")],
                )
                .await
            }
        };
    }

    write_error(&mut stream, 404, "Resource not found", &[]).await
}

fn parse_delay(target: &str, group: bool) -> Result<crate::resource::control::DelayRequest, ()> {
    if target.contains('#') {
        return Err(());
    }
    let (_, raw) = target.split_once('?').ok_or(())?;
    let mut values = std::collections::BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        values.entry(key).or_insert(value);
    }
    let url = values.get("url").ok_or(())?.to_string();
    crate::resource::probe::Target::parse(&url).map_err(|_| ())?;
    let raw_timeout = values.get("timeout").ok_or(())?;
    let millis = if group {
        raw_timeout.parse::<i32>().map(i64::from)
    } else {
        raw_timeout.parse::<i16>().map(i64::from)
    }
    .map_err(|_| ())?;
    let expected =
        crate::config::status_ranges(values.get("expected").map_or("", |value| value.as_ref()))
            .map_err(|_| ())?;
    Ok(crate::resource::control::DelayRequest {
        url,
        timeout: Duration::from_millis(millis.max(0) as u64),
        expected,
    })
}

async fn probe_error<S: ControllerIo>(
    stream: &mut S,
    error: crate::resource::control::ProbeError,
) -> io::Result<()> {
    use crate::resource::control::ProbeError;
    match error {
        ProbeError::NotFound => write_error(stream, 404, "Resource not found", &[]).await,
        ProbeError::Timeout => write_error(stream, 504, "Delay test timed out", &[]).await,
        ProbeError::Failed => write_error(stream, 503, "Delay test failed", &[]).await,
        ProbeError::Stopped => Ok(()),
    }
}

async fn delay_query<S: ControllerIo>(
    stream: &mut S,
    group: bool,
    raw_name: &str,
    target: &str,
    resources: Option<&dyn crate::resource::control::RuntimeResources>,
    cancellation: &CancellationToken,
) -> io::Result<()> {
    let (Ok(name), Ok(request)) = (decode_group_name(raw_name), parse_delay(target, group)) else {
        return write_error(stream, 400, "Bad request", &[]).await;
    };
    let Some(resources) = resources else {
        return write_error(stream, 404, "Resource not found", &[]).await;
    };
    let operation = async {
        if group {
            resources
                .group_delay(&name, &request, cancellation)
                .await
                .map(|value| serde_json::json!(value))
        } else {
            let delay = resources.node_delay(&name, &request, cancellation).await?;
            if delay == 0 {
                Err(crate::resource::control::ProbeError::Failed)
            } else {
                Ok(serde_json::json!({"delay":delay}))
            }
        }
    };
    let result = tokio::select! { biased;
        () = cancellation.cancelled() => return Ok(()),
        result = operation => result,
    };
    match result {
        Ok(value) => write_json(stream, 200, &value, &[]).await,
        Err(error) => probe_error(stream, error).await,
    }
}

async fn handle_select<S: ControllerIo>(
    stream: &mut S,
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
        Err(ProxyGroupError::UnknownMember | ProxyGroupError::NotSelectable) => {
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
    let limit = crate::inbound::DEFAULT_HEADER_LIMIT;
    if candidate.len() > limit || secret.len() > limit {
        return false;
    }
    let mut difference = candidate.len() ^ secret.len();
    for index in 0..limit {
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
    #[serde(skip_serializing_if = "String::is_empty")]
    now: String,
    hidden: bool,
    icon: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed: Option<String>,
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
            fixed: state.fixed,
        }
    }
}

async fn write_json<T: Serialize, S: ControllerIo>(
    stream: &mut S,
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

async fn write_error<S: ControllerIo>(
    stream: &mut S,
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

async fn write_response<S: ControllerIo>(
    stream: &mut S,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    stream.respond(status, headers, body).await
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

    pub(super) fn test_groups() -> Arc<ProxyGroups> {
        let dispatcher: Arc<dyn Dispatcher> = Arc::new(UnusedDispatcher);
        ProxyGroups::new(
            &[SelectProxyGroupConfig {
                kind: crate::config::GroupKind::Select,
                strategy: crate::config::BalanceStrategy::default(),
                hash_key: crate::config::BalanceHashKey::default(),
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
    fn delay_query_preserves_reference_timeout_width_and_expected_ranges() {
        let base = "/proxies/edge/delay?url=http%3A%2F%2Fexample.test%2F&timeout=30000&expected=200-204%2F302";
        let request = parse_delay(base, false).unwrap();
        assert_eq!(request.timeout, Duration::from_secs(30));
        assert_eq!(request.expected, [(200, 204), (302, 302)]);
        assert!(parse_delay(&base.replace("30000", "40000"), false).is_err());
        assert!(parse_delay(&base.replace("30000", "40000"), true).is_ok());
        assert_eq!(
            parse_delay(&base.replace("30000", "-1"), false)
                .unwrap()
                .timeout,
            Duration::ZERO
        );
        assert!(parse_delay("/proxies/edge/delay?timeout=1", false).is_err());
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
        let long_secret = "x".repeat(512);
        assert!(authorized(
            &[("Authorization".to_owned(), format!("Bearer {long_secret}"))],
            Some(&long_secret),
        ));
        let mut different = long_secret.as_bytes().to_vec();
        *different.last_mut().unwrap() = b'y';
        assert!(!controller_token_eq(&different, long_secret.as_bytes()));
        let oversized = vec![b'x'; crate::inbound::DEFAULT_HEADER_LIMIT + 1];
        assert!(!controller_token_eq(&oversized, &oversized));
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
                ..ExternalControllerConfig::default()
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
                ..ExternalControllerConfig::default()
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
