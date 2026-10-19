//! No sockets or host peers: adapters use duplex IO and a recording dispatcher.
use super::*;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    security::SecurityContext,
    session::{DatagramSession, Destination, InboundKind, InboundMetadata, StreamSession},
};
use async_trait::async_trait;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Instant, timeout},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Origin {
    sessions: Mutex<Vec<StreamSession>>,
    heads: Arc<Mutex<Vec<String>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
#[async_trait]
impl Dispatcher for Origin {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        self.sessions.lock().unwrap().push(session);
        let (client, mut server) = tokio::io::duplex(4096);
        let heads = self.heads.clone();
        let task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            while bytes.len() < 32768 {
                bytes.push(server.read_u8().await.unwrap());
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            heads
                .lock()
                .unwrap()
                .push(String::from_utf8(bytes).unwrap());
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });
        self.tasks.lock().unwrap().push(task);
        Ok(Box::new(client))
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
impl Origin {
    async fn join(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    }
}
struct Entry(HttpContext);
#[async_trait]
impl Dispatcher for Entry {
    fn http_context(&self) -> Option<HttpContext> {
        Some(self.0.clone())
    }
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        panic!("HTTP adapter bypassed its fixed generation")
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(80),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:54321".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:80".parse().unwrap()),
        sniffed_domain: Some("stale.invalid".into()),
    }
}
fn context(origin: Arc<Origin>) -> HttpContext {
    HttpContext::new(Policy::compile("rewrite:\n  enabled: true\n  rules:\n  - {url: '^http://old\\.invalid/(.*)$', action: replace, replacement: 'http://new.invalid:8081/$1'}\n").unwrap(),origin,SecurityContext::new())
}
#[tokio::test]
async fn transparent_h1_routes_only_the_final_target_and_preserves_original_facts() {
    let origin = Arc::new(Origin::default());
    let context = context(origin.clone());
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        assert!(matches!(
            context
                .try_intercept(&mut server, session(), CancellationToken::new())
                .await
                .unwrap(),
            Intercept::Handled
        ));
    });
    client
        .write_all(b"GET /path?q=1 HTTP/1.1\r\nHost: old.invalid\r\nAuthorization: Bearer private\r\nCookie: private=cookie\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(1), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    origin.join().await;
    assert!(response.ends_with("\r\n\r\nok"));
    let sessions = origin.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].destination,
        Destination::domain("new.invalid", 8081).unwrap()
    );
    assert!(sessions[0].sniffed_domain.is_none());
    assert_eq!(
        sessions[0].metadata.original.as_ref().unwrap().destination,
        session().destination
    );
    assert!(origin.heads.lock().unwrap()[0].starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    assert!(origin.heads.lock().unwrap()[0].contains("Host: new.invalid:8081\r\n"));
    assert!(
        !origin.heads.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("authorization:")
    );
    assert!(
        !origin.heads.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("cookie:")
    );
}
#[tokio::test]
async fn mixed_http_and_connect_use_the_same_context_with_preread_bytes() {
    for request in [b"GET http://old.invalid/path HTTP/1.1\r\nHost: old.invalid\r\nConnection: close\r\n\r\n".as_slice(),b"GET http://old.invalid/path HTTP/1.0\r\nConnection: close\r\n\r\n".as_slice(),b"CONNECT old.invalid:80 HTTP/1.1\r\nHost: old.invalid:80\r\n\r\nGET /path HTTP/1.1\r\nHost: old.invalid\r\nConnection: close\r\n\r\n"] {
        let origin=Arc::new(Origin::default());let dispatcher:Arc<dyn Dispatcher>=Arc::new(Entry(context(origin.clone())));
        let (mut client,server)=tokio::io::duplex(4096);
        let task=tokio::spawn(async move {crate::inbound::http::server::handle_connection_with_deadline(server,"127.0.0.1:30000".parse().unwrap(),"127.0.0.1:1080".parse().unwrap(),dispatcher,crate::inbound::http::HttpServerConfig::processing(),CancellationToken::new(),Instant::now()+Duration::from_secs(1)).await.unwrap();});
        client.write_all(request).await.unwrap();let mut response=String::new();timeout(Duration::from_secs(1),client.read_to_string(&mut response)).await.unwrap().unwrap();task.await.unwrap();origin.join().await;
        assert!(response.ends_with("\r\n\r\nok"));assert_eq!(origin.sessions.lock().unwrap().len(),1);
        assert_eq!(origin.sessions.lock().unwrap()[0].destination,Destination::domain("new.invalid",8081).unwrap());
    }
}
#[tokio::test]
async fn local_actions_do_not_connect_or_wait_for_an_unread_expect_body() {
    for (action, replacement, status) in [
        ("reject", "", 403),
        (
            "redirect302",
            ", replacement-mode: url, replacement: 'https://new.invalid/path'",
            302,
        ),
        (
            "redirect307",
            ", replacement-mode: url, replacement: 'https://new.invalid/path'",
            307,
        ),
    ] {
        let origin = Arc::new(Origin::default());
        let context = HttpContext::new(
            Policy::compile(&format!(
                "rewrite: {{enabled: true, rules: [{{url: '.', action: {action}{replacement}}}]}}"
            ))
            .unwrap(),
            origin.clone(),
            SecurityContext::new(),
        );
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            context
                .try_intercept(&mut server, session(), CancellationToken::new())
                .await
                .unwrap();
        });
        client.write_all(b"POST /path HTTP/1.1\r\nHost: old.invalid\r\nContent-Length: 1048576\r\nExpect: 100-continue\r\n\r\n").await.unwrap();
        let mut response = String::new();
        timeout(Duration::from_secs(1), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
        assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
        assert!(origin.sessions.lock().unwrap().is_empty());
    }
}
#[tokio::test]
async fn unclaimed_io_replays_every_byte_and_noncandidate_port_does_not_read() {
    let origin = Arc::new(Origin::default());
    let context = context(origin.clone());
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(b"\x16\x03\x01binary").await.unwrap();
    let Intercept::Transparent { prefix } = context
        .try_intercept(&mut server, session(), CancellationToken::new())
        .await
        .unwrap()
    else {
        panic!()
    };
    let mut replay = io::Replay::new(prefix, &mut server);
    let mut bytes = [0; 9];
    replay.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"\x16\x03\x01binary");
    let mut no_read = session();
    no_read.destination = Destination::Ip("203.0.113.1:12345".parse().unwrap());
    assert!(
        matches!(timeout(Duration::from_millis(100),context.try_intercept(&mut server,no_read,CancellationToken::new())).await.unwrap().unwrap(),Intercept::Transparent{prefix} if prefix.is_empty())
    );
    assert!(origin.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn same_origin_path_action_preserves_resolved_transport_and_logical_host() {
    let origin = Arc::new(Origin::default());
    let context = HttpContext::new(
        Policy::compile(
            "rewrite: {enabled: true, rules: [{url: '.', action: replace, replacement-mode: url, replacement: 'http://old.invalid/new'}]}",
        )
        .unwrap(),
        origin.clone(),
        SecurityContext::new(),
    );
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut server, session(), CancellationToken::new())
            .await
            .unwrap();
    });
    client.write_all(b"GET /old HTTP/1.1\r\nHost: old.invalid\r\nAuthorization: Bearer original\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = String::new();
    timeout(Duration::from_secs(1), client.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    task.await.unwrap();
    origin.join().await;
    assert_eq!(
        origin.sessions.lock().unwrap()[0].destination,
        session().destination
    );
    let heads = origin.heads.lock().unwrap();
    assert!(heads[0].starts_with("GET /new HTTP/1.1\r\n"));
    assert!(heads[0].contains("Host: old.invalid:80\r\n"));
    assert!(heads[0].contains("Authorization: Bearer original\r\n"));
}
