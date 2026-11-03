//! Bounded subscriptions over the existing Controller routes and lifecycle.
use super::{
    CONTROLLER_BODY_TIMEOUT, ControllerIo, RequestContext, authorized, controller_token_eq,
    header_values, write_error,
};
use crate::config::LogLevel;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};
use tokio_util::sync::CancellationToken;

pub(super) const MAX_SUBSCRIPTIONS: usize = 4;
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOT_CONNECTIONS: usize = 512;

pub(super) trait WebSocketIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WebSocketIo for T {}

pub(super) fn requested(request: &crate::inbound::http::RequestHead) -> bool {
    header_values(&request.headers, "upgrade").any(|v| v.eq_ignore_ascii_case("websocket"))
}

#[derive(Clone, Copy)]
enum Topic {
    Traffic,
    Memory,
    Connections,
    Logs { level: LogLevel, structured: bool },
}
struct Options {
    topic: Topic,
    interval: Duration,
    token: Option<String>,
}
impl Options {
    fn parse(target: &str) -> Result<Self, ()> {
        if target.len() > 8192 || target.contains('#') {
            return Err(());
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut token = None;
        let mut interval = None;
        let mut level = None;
        let mut format = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "token" if token.is_none() => token = Some(value.into_owned()),
                "interval" if path == "/connections" && interval.is_none() => {
                    let value = value.parse::<u64>().map_err(|_| ())?;
                    if !(100..=60_000).contains(&value) {
                        return Err(());
                    }
                    interval = Some(Duration::from_millis(value));
                }
                "level" if path == "/logs" && level.is_none() => {
                    level = Some(match value.as_ref() {
                        "debug" => LogLevel::Debug,
                        "info" => LogLevel::Info,
                        "warning" => LogLevel::Warning,
                        "error" => LogLevel::Error,
                        "silent" => LogLevel::Silent,
                        _ => return Err(()),
                    });
                }
                "format" if path == "/logs" && format.is_none() => {
                    format = Some(value.into_owned())
                }
                _ => return Err(()),
            }
        }
        let topic = match path {
            "/traffic" => Topic::Traffic,
            "/memory" => Topic::Memory,
            "/connections" => Topic::Connections,
            "/logs" => Topic::Logs {
                level: level.unwrap_or(LogLevel::Info),
                structured: format.as_deref() == Some("structured"),
            },
            _ => return Err(()),
        };
        Ok(Self {
            topic,
            token,
            interval: interval.unwrap_or(Duration::from_secs(1)),
        })
    }
}
fn valid_handshake(request: &crate::inbound::http::RequestHead) -> Option<String> {
    let unique = |name: &'static str| {
        let mut values = header_values(&request.headers, name);
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };
    if request.method != "GET"
        || request.version != "HTTP/1.1"
        || unique("host").is_none()
        || unique("upgrade").is_none_or(|v| !v.eq_ignore_ascii_case("websocket"))
        || unique("sec-websocket-version") != Some("13")
        || header_values(&request.headers, "transfer-encoding")
            .next()
            .is_some()
    {
        return None;
    }
    let mut length = header_values(&request.headers, "content-length");
    if length.next().is_some_and(|value| value != "0") || length.next().is_some() {
        return None;
    }
    if !header_values(&request.headers, "connection")
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
    {
        return None;
    }
    let key = unique("sec-websocket-key")?;
    if key.len() != 24
        || base64::engine::general_purpose::STANDARD
            .decode(key)
            .ok()?
            .len()
            != 16
    {
        return None;
    }
    Some(derive_accept_key(key.as_bytes()))
}

pub(super) async fn handle<S: ControllerIo>(
    stream: &mut S,
    request: crate::inbound::http::RequestHead,
    context: RequestContext,
    cancel: CancellationToken,
) -> io::Result<()> {
    let Ok(options) = Options::parse(&request.target) else {
        return write_error(stream, 400, "Bad request", &[]).await;
    };
    let authenticated = match (context.secret.as_deref(), options.token.as_deref()) {
        (Some(secret), Some(token)) => controller_token_eq(token.as_bytes(), secret.as_bytes()),
        _ => authorized(&request.headers, context.secret.as_deref()),
    };
    if !authenticated {
        return write_error(
            stream,
            401,
            "Unauthorized",
            &[("WWW-Authenticate", "Bearer")],
        )
        .await;
    }
    let Some(accept) = valid_handshake(&request) else {
        return write_error(stream, 400, "Bad request", &[]).await;
    };
    if stream.websocket_io().is_none() {
        return write_error(stream, 400, "WebSocket requires HTTP/1.1", &[]).await;
    }
    let registry = context
        .resources
        .as_ref()
        .map(|resources| resources.connections());
    if matches!(options.topic, Topic::Traffic | Topic::Connections) && registry.is_none() {
        return write_error(stream, 404, "Resource not found", &[]).await;
    }
    if matches!(options.topic, Topic::Logs { .. }) && context.logs.is_none() {
        return write_error(stream, 404, "Resource not found", &[]).await;
    }
    let Ok(_permit) = context.subscriptions.try_acquire() else {
        return write_error(stream, 503, "Subscription limit reached", &[]).await;
    };
    let mut head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\nCache-Control: no-store\r\n"
    );
    for (name, value) in stream.websocket_headers() {
        head.push_str(&name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let io = stream.websocket_io().expect("checked HTTP/1.1 transport");
    tokio::select! { biased;
        () = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONTROLLER_BODY_TIMEOUT, async { io.write_all(head.as_bytes()).await?; io.flush().await }) => result.map_err(|_| timed_out())??,
    }
    let config = WebSocketConfig::default()
        .read_buffer_size(1024)
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_MESSAGE_BYTES + 64)
        .max_message_size(Some(1024))
        .max_frame_size(Some(1024));
    let mut websocket =
        WebSocketStream::from_partially_read(io, request.buffered, Role::Server, Some(config))
            .await;
    match options.topic {
        Topic::Logs { level, structured } => {
            let mut subscription = context.logs.as_ref().unwrap().subscribe();
            loop {
                tokio::select! { biased;
                    () = cancel.cancelled() => return Ok(()),
                    incoming = websocket.next() => { if !incoming_message(&mut websocket, incoming, &cancel).await? { return Ok(()); } },
                    event = subscription.recv() => {
                        let Some(event) = event else { return Ok(()); };
                        if event.matches(level) { send_json(&mut websocket,&event.json(structured),&cancel).await?; }
                    }
                }
            }
        }
        topic => {
            let mut tick = tokio::time::interval(options.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            if !matches!(topic, Topic::Connections) {
                tick.reset();
            }
            let mut totals = registry
                .as_ref()
                .map_or((0, 0), |registry| registry.totals());
            let mut last = tokio::time::Instant::now();
            loop {
                tokio::select! { biased;
                    () = cancel.cancelled() => return Ok(()),
                    incoming = websocket.next() => { if !incoming_message(&mut websocket,incoming,&cancel).await? { return Ok(()); } },
                    _ = tick.tick() => {
                        match topic {
                            Topic::Traffic => {
                                let current = registry.as_ref().unwrap().totals();
                                let elapsed = last.elapsed().as_secs_f64().max(0.001);
                                let value = serde_json::json!({"up":((current.0.saturating_sub(totals.0)) as f64/elapsed) as u64,"down":((current.1.saturating_sub(totals.1)) as f64/elapsed) as u64,"upTotal":current.0,"downTotal":current.1});
                                totals = current;
                                last = tokio::time::Instant::now();
                                send_json(&mut websocket,&value,&cancel).await?;
                            }
                            Topic::Memory => send_json(&mut websocket,&serde_json::json!({"inuse":crate::memory::resident_bytes(),"oslimit":null}),&cancel).await?,
                            Topic::Connections => {
                                let snapshot = registry.as_ref().unwrap().snapshot_bounded(MAX_SNAPSHOT_CONNECTIONS).ok_or_else(|| io::Error::other("Controller snapshot exceeds its subscription budget"))?;
                                send_json(&mut websocket,&snapshot,&cancel).await?;
                            }
                            Topic::Logs{..} => unreachable!(),
                        }
                    }
                }
            }
        }
    }
}
fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Controller subscription write timed out",
    )
}
async fn send_json<T: Serialize + Sync, S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    value: &T,
    cancel: &CancellationToken,
) -> io::Result<()> {
    let mut bytes = BoundedJson(Vec::new());
    serde_json::to_writer(&mut bytes, value)
        .map_err(|_| io::Error::other("Controller subscription exceeds its message budget"))?;
    let text = String::from_utf8(bytes.0).expect("JSON is UTF-8");
    tokio::select! { biased;
        () = cancel.cancelled() => Ok(()),
        result = tokio::time::timeout(CONTROLLER_BODY_TIMEOUT,socket.send(Message::Text(text.into()))) => result.map_err(|_| timed_out())?.map_err(|_| io::Error::other("Controller subscription closed")),
    }
}
async fn incoming_message<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    message: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
    cancel: &CancellationToken,
) -> io::Result<bool> {
    match message {
        Some(Ok(Message::Pong(_))) => Ok(true),
        Some(Ok(Message::Ping(_))) => {
            tokio::select! { biased;
                () = cancel.cancelled() => Ok(false),
                result = tokio::time::timeout(CONTROLLER_BODY_TIMEOUT,socket.flush()) => { result.map_err(|_| timed_out())?.map_err(|_| io::Error::other("Controller subscription closed"))?; Ok(true) }
            }
        }
        Some(Ok(Message::Close(_))) => {
            tokio::select! { biased;
                () = cancel.cancelled() => {},
                _ = tokio::time::timeout(CONTROLLER_BODY_TIMEOUT, socket.flush()) => {},
            }
            Ok(false)
        }
        None => Ok(false),
        _ => Err(io::Error::other("Invalid Controller subscription frame")),
    }
}
struct BoundedJson(Vec<u8>);
impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > MAX_MESSAGE_BYTES)
        {
            return Err(io::Error::other(
                "Controller subscription exceeds its message budget",
            ));
        }
        let needed = self.0.len() + bytes.len();
        if needed > self.0.capacity() {
            let target = needed
                .max(self.0.capacity().max(1024).saturating_mul(2))
                .min(MAX_MESSAGE_BYTES);
            self.0
                .try_reserve_exact(target - self.0.len())
                .map_err(|_| io::Error::other("Controller message allocation failed"))?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::Registry;
    use crate::resource::control::{DnsSnapshot, RuntimeResources};
    use crate::routing::{ProxyGroupError, ProxyGroups};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, DuplexStream};

    struct Resources {
        registry: Arc<Registry>,
        groups: Arc<ProxyGroups>,
    }
    #[async_trait::async_trait]
    impl RuntimeResources for Resources {
        fn connections(&self) -> Arc<Registry> {
            self.registry.clone()
        }
        fn configs(&self) -> serde_json::Value {
            serde_json::Value::Null
        }
        fn rules(&self) -> serde_json::Value {
            serde_json::json!({"rules":[]})
        }
        fn groups(&self) -> Arc<ProxyGroups> {
            self.groups.clone()
        }
        fn select(&self, group: &str, member: &str) -> Result<(), ProxyGroupError> {
            self.groups.select(group, member)
        }
        fn clear_fixed(&self, group: &str) -> Result<(), ProxyGroupError> {
            self.groups.clear_fixed(group)
        }
        fn health(&self) -> serde_json::Value {
            serde_json::json!({"proxies":{}})
        }
        fn providers(&self, _: bool) -> serde_json::Value {
            serde_json::json!({"providers":{}})
        }
        fn dns(&self) -> Option<DnsSnapshot> {
            None
        }
        async fn refresh(&self, _: bool, _: &str) -> Result<(), &'static str> {
            Err("not configured")
        }
    }
    fn context() -> (RequestContext, Arc<Registry>) {
        let groups = super::super::tests::test_groups();
        let registry = Arc::new(Registry::default());
        (
            RequestContext {
                secret: Some("token".into()),
                traffic: None,
                proxy_groups: groups.clone(),
                resources: Some(Arc::new(Resources {
                    registry: registry.clone(),
                    groups,
                })),
                cors: Arc::new(super::super::cors::Policy::new(
                    &crate::config::ControllerCors::default(),
                )),
                requests: tokio_util::task::TaskTracker::new(),
                subscriptions: Arc::new(tokio::sync::Semaphore::new(MAX_SUBSCRIPTIONS)),
                logs: Some(Arc::new(crate::logging::RuntimeLog::new(LogLevel::Info))),
            },
            registry,
        )
    }
    fn info() -> crate::connections::ConnectionInfo {
        crate::connections::ConnectionInfo {
            metadata: crate::connections::ConnectionMetadata {
                network: "tcp",
                inbound_type: "Tun",
                source: "198.18.0.1:1234".parse().unwrap(),
                destination_ip: Some("198.51.100.1".parse().unwrap()),
                destination_port: 443,
                host: "fixture.invalid".into(),
                dns_mode: "normal",
                sniff_host: "".into(),
                process: Default::default(),
                original: None,
            },
            chains: vec!["DIRECT".into()],
            provider_chains: Vec::new(),
            rule: "Match",
            rule_payload: "".into(),
            dns_path: Vec::new(),
        }
    }
    async fn open(
        path: &str,
        context: RequestContext,
        capacity: usize,
    ) -> (
        WebSocketStream<DuplexStream>,
        tokio::task::JoinHandle<io::Result<()>>,
        CancellationToken,
    ) {
        let (client, server) = tokio::io::duplex(capacity);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(super::super::handle_connection(
            super::super::H1Io(server),
            context,
            cancel.clone(),
        ));
        let (client, response) =
            tokio_tungstenite::client_async(format!("ws://controller{path}"), client)
                .await
                .unwrap();
        assert_eq!(response.status(), 101);
        (client, task, cancel)
    }
    async fn json(client: &mut WebSocketStream<DuplexStream>) -> serde_json::Value {
        let message = client.next().await.unwrap().unwrap();
        serde_json::from_str(message.to_text().unwrap()).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn controller_websocket_traffic_connections_memory_and_stop_share_runtime_state() {
        let (context, registry) = context();
        let (mut traffic, traffic_task, traffic_cancel) =
            open("/traffic?token=token", context.clone(), 4096).await;
        tokio::task::yield_now().await;
        let connection = registry.open(info());
        connection.upload(101);
        connection.download(203);
        let value = json(&mut traffic).await;
        assert_eq!(value["upTotal"], 101);
        assert_eq!(value["downTotal"], 203);
        assert_eq!(value["up"], 101);
        assert_eq!(value["down"], 203);
        let (mut connections, connections_task, connections_cancel) = open(
            "/connections?interval=100&token=token",
            context.clone(),
            4096,
        )
        .await;
        let value = json(&mut connections).await;
        assert_eq!(value["uploadTotal"], 101);
        assert_eq!(value["connections"][0]["metadata"]["type"], "Tun");
        let id = value["connections"][0]["id"].as_str().unwrap();
        registry.close(id);
        let value = json(&mut connections).await;
        assert!(value["connections"].as_array().unwrap().is_empty());
        assert!(connection.cancelled());
        let (mut memory, memory_task, memory_cancel) =
            open("/memory?token=token", context.clone(), 4096).await;
        assert!(json(&mut memory).await.get("inuse").is_some());
        traffic_cancel.cancel();
        connections_cancel.cancel();
        memory_cancel.cancel();
        traffic_task.await.unwrap().unwrap();
        connections_task.await.unwrap().unwrap();
        memory_task.await.unwrap().unwrap();
        assert_eq!(context.subscriptions.available_permits(), MAX_SUBSCRIPTIONS);
    }

    #[tokio::test(start_paused = true)]
    async fn controller_websocket_admission_and_slow_consumers_remain_bounded() {
        let (context, _) = context();
        let (client, task, _cancel) = open("/memory?token=token", context.clone(), 64).await;
        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(context.subscriptions.available_permits(), MAX_SUBSCRIPTIONS);
        drop(client);
        let permit = context
            .subscriptions
            .acquire_many(MAX_SUBSCRIPTIONS as u32)
            .await
            .unwrap();
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(super::super::handle_connection(
            super::super::H1Io(server),
            context.clone(),
            CancellationToken::new(),
        ));
        let error = tokio_tungstenite::client_async("ws://controller/memory?token=token", client)
            .await
            .unwrap_err();
        match error {
            tokio_tungstenite::tungstenite::Error::Http(response) => {
                assert_eq!(response.status(), 503)
            }
            _ => panic!("expected HTTP refusal"),
        }
        task.await.unwrap().unwrap();
        drop(permit);
    }

    #[tokio::test]
    async fn controller_websocket_query_auth_and_buffered_control_frames_are_preserved() {
        let (context, _) = context();
        for path in ["/memory?token=wrong", "/memory?token=token&token=token"] {
            let (client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(super::super::handle_connection(
                super::super::H1Io(server),
                context.clone(),
                CancellationToken::new(),
            ));
            let error = tokio_tungstenite::client_async(format!("ws://controller{path}"), client)
                .await
                .unwrap_err();
            match error {
                tokio_tungstenite::tungstenite::Error::Http(response) => assert_eq!(
                    response.status(),
                    if path.contains("wrong") { 401 } else { 400 }
                ),
                _ => panic!("expected authentication refusal"),
            }
            task.await.unwrap().unwrap();
        }
        let (mut client, server) = tokio::io::duplex(4096);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(super::super::handle_connection(
            super::super::H1Io(server),
            context,
            cancel.clone(),
        ));
        let mut request=b"GET /memory?token=token HTTP/1.1\r\nHost: controller\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".to_vec();
        request.extend_from_slice(&[0x89, 0x83, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
        client.write_all(&request).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));
        let mut socket = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(message, Message::Pong(b"abc".to_vec().into()));
        cancel.cancel();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn controller_websocket_serialization_limits_before_growing_and_connections_are_not_truncated()
    {
        let mut writer = BoundedJson(Vec::new());
        let value = vec!["x".repeat(1024); 512];
        assert!(serde_json::to_writer(&mut writer, &value).is_err());
        assert!(writer.0.len() <= MAX_MESSAGE_BYTES);
        assert!(writer.0.capacity() <= MAX_MESSAGE_BYTES);
        let (_, registry) = context();
        let _connection = registry.open(info());
        assert!(registry.snapshot_bounded(0).is_none());
        assert!(registry.snapshot_bounded(1).is_some());
        assert_eq!(registry.totals(), (0, 0));
    }

    #[tokio::test]
    async fn controller_websocket_logs_use_the_session_bus_and_rest_tokens_do_not_authenticate() {
        let (mut context, _) = context();
        let filtered = crate::logging::dispatch(LogLevel::Debug);
        context.logs = tracing::dispatcher::with_default(&filtered, crate::logging::current);
        let (mut client, task, cancel) = open(
            "/logs?level=warning&format=structured&token=token",
            context.clone(),
            4096,
        )
        .await;
        tokio::task::yield_now().await;
        tracing::dispatcher::with_default(&filtered, || {
            tracing::info!(target:"vole::controller",bytes=1,"not requested");
            tracing::warn!(target:"external::library",bytes=7,secret="synthetic credential","synthetic message");
        });
        let value = tokio::time::timeout(Duration::from_secs(1), json(&mut client))
            .await
            .unwrap();
        assert_eq!(value["level"], "warn");
        assert!(value["message"].as_str().unwrap().contains("bytes=7"));
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("synthetic credential")
        );
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("synthetic message")
        );
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("external::library")
        );
        cancel.cancel();
        task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(super::super::handle_connection(
            super::super::H1Io(server),
            context,
            CancellationToken::new(),
        ));
        client
            .write_all(b"GET /version?token=token HTTP/1.1\r\nHost: controller\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 401"));
        task.await.unwrap().unwrap();
    }
}
