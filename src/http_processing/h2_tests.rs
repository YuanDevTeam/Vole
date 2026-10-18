//! Independent in-memory H2 peers. No host sockets or detached production tasks.
use super::*;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{DatagramSession, Destination, InboundKind, InboundMetadata, StreamSession},
};
use ::h2 as wire;
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const PAYLOAD: usize = 96 * 1024;
fn pem(label: &str, bytes: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}
struct Origin {
    authority: Arc<authority::Authority>,
    h2: bool,
    early: bool,
    truncated: bool,
    sessions: Mutex<Vec<StreamSession>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
#[async_trait]
impl Dispatcher for Origin {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let name = match &session.destination {
            Destination::Domain { host, .. } => host.clone(),
            _ => session.sniffed_domain.clone().unwrap(),
        };
        let mut config = (*self.authority.server_config(&name).unwrap()).clone();
        config.alpn_protocols = if self.h2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        self.sessions.lock().unwrap().push(session);
        let h2 = self.h2;
        let early = self.early;
        let truncated = self.truncated;
        let received = self.received.clone();
        let (client, peer) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(peer)
                .await
            else {
                return;
            };
            if h2 {
                let mut builder = wire::server::Builder::new();
                builder
                    .initial_window_size(8192)
                    .initial_connection_window_size(16384);
                let mut connection = builder.handshake::<_, Bytes>(tls).await.unwrap();
                let (request, mut response) = connection.accept().await.unwrap().unwrap();
                let exchange = async move {
                    if early || truncated {
                        received.lock().unwrap().push(Vec::new());
                        let mut out = response
                            .send_response(
                                Response::builder()
                                    .status(if early { 413 } else { 200 })
                                    .header("content-length", PAYLOAD)
                                    .body(())
                                    .unwrap(),
                                false,
                            )
                            .unwrap();
                        super::h2_body::send_data(
                            &mut out,
                            Bytes::from(vec![9; if truncated { PAYLOAD / 2 } else { PAYLOAD }]),
                        )
                        .await
                        .unwrap();
                        out.send_data(Bytes::new(), true).unwrap();
                        drop(request);
                        drop(out);
                        drop(response);
                        return;
                    }
                    assert_eq!(request.uri().path(), "/upload");
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(frame) = body.data().await {
                        let Ok(frame) = frame else {
                            return;
                        };
                        body.flow_control().release_capacity(frame.len()).unwrap();
                        bytes.extend_from_slice(&frame);
                    }
                    if bytes.len() != PAYLOAD {
                        return;
                    }
                    assert!(bytes.iter().all(|b| *b == 7));
                    received.lock().unwrap().push(bytes);
                    let mut out = response
                        .send_response(
                            Response::builder()
                                .header("content-length", PAYLOAD)
                                .body(())
                                .unwrap(),
                            false,
                        )
                        .unwrap();
                    super::h2_body::send_data(&mut out, Bytes::from(vec![9; PAYLOAD]))
                        .await
                        .unwrap();
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x-check", "complete".parse().unwrap());
                    out.send_trailers(trailers).unwrap();
                };
                tokio::pin!(exchange);
                loop {
                    tokio::select! {biased;()=&mut exchange=>break,next=connection.accept()=>{if next.is_none() { return; }}}
                }
                connection.graceful_shutdown();
                while matches!(connection.accept().await, Some(Ok(_))) {}
            } else {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    assert!(head.len() < 32768);
                    head.push(tls.read_u8().await.unwrap());
                }
                let head = String::from_utf8(head).unwrap();
                if early || truncated {
                    received.lock().unwrap().push(Vec::new());
                    let status = if early {
                        "413 Content Too Large"
                    } else {
                        "200 OK"
                    };
                    tls.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {PAYLOAD}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    let size = if truncated { PAYLOAD / 2 } else { PAYLOAD };
                    tls.write_all(&vec![9; size]).await.unwrap();
                    let _ = tls.shutdown().await;
                    if early {
                        // Preserve the read half after the final response. A
                        // peer that drops an unread request would instead reset
                        // the transport, invalidating its buffered response.
                        let mut scratch = [0; 4096];
                        timeout(Duration::from_secs(3), async {
                            while matches!(tls.read(&mut scratch).await, Ok(n) if n > 0) {}
                        })
                        .await
                        .unwrap();
                    }
                    return;
                }
                assert!(head.starts_with("POST /upload HTTP/1.1\r\n"));
                assert!(
                    head.to_lowercase()
                        .contains(&format!("content-length: {PAYLOAD}\r\n"))
                );
                let mut bytes = vec![0; PAYLOAD];
                tls.read_exact(&mut bytes).await.unwrap();
                assert!(bytes.iter().all(|b| *b == 7));
                received.lock().unwrap().push(bytes);
                tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-check\r\nConnection: close\r\n\r\n").await.unwrap();
                for _ in 0..PAYLOAD / 4096 {
                    tls.write_all(b"1000\r\n").await.unwrap();
                    tls.write_all(&[9; 4096]).await.unwrap();
                    tls.write_all(b"\r\n").await.unwrap();
                }
                tls.write_all(b"0\r\nx-check: complete\r\n\r\n")
                    .await
                    .unwrap();
                tls.shutdown().await.unwrap();
            }
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
            timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
fn prepared(h2: bool) -> (HttpContext, Arc<Origin>) {
    prepared_with(h2, false)
}
fn prepared_with(h2: bool, early: bool) -> (HttpContext, Arc<Origin>) {
    prepared_response(h2, early, false)
}
fn prepared_response(h2: bool, early: bool, truncated: bool) -> (HttpContext, Arc<Origin>) {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = pem("CERTIFICATE", cert.der());
    let key_pem = pem("PRIVATE KEY", &key.serialize_der());
    let authority = authority::Authority::load(&cert_pem, &key_pem).unwrap();
    let policy = Policy::compile(&format!(
        "mitm:\n  domains: [a.test, b.test]\n  certificate: {}\n  private-key: {}\n",
        serde_json::to_string(&cert_pem).unwrap(),
        serde_json::to_string(&key_pem).unwrap()
    ))
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let origin = Arc::new(Origin {
        authority,
        h2,
        early,
        truncated,
        sessions: Mutex::new(Vec::new()),
        received: Arc::new(Mutex::new(Vec::new())),
        tasks: Mutex::new(Vec::new()),
    });
    (
        HttpContext::new(
            policy,
            origin.clone(),
            SecurityContext::with_tls_roots(roots),
        ),
        origin,
    )
}
fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(443),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:30000".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:443".parse().unwrap()),
        sniffed_domain: Some("a.test".into()),
    }
}
#[tokio::test]
async fn h2_streams_large_bodies_and_trailers_through_actual_h2_and_h1_alpn() {
    for upstream_h2 in [true, false] {
        let (context, origin) = prepared(upstream_h2);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h2(&mut server, session(), stop)
                .await
                .unwrap();
        });
        let (mut sender, driver) = wire::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(driver);
        let request = Request::builder()
            .method("POST")
            .uri("https://a.test/upload")
            .header("content-length", PAYLOAD)
            .body(())
            .unwrap();
        let (response, mut body) = sender.send_request(request, false).unwrap();
        let upload = async {
            super::h2_body::send_data(&mut body, Bytes::from(vec![7; PAYLOAD]))
                .await
                .unwrap();
            body.send_data(Bytes::new(), true).unwrap();
        };
        let download = async {
            let response = response.await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.into_body();
            let mut count = 0;
            while let Some(frame) = body.data().await {
                let frame = frame.unwrap();
                assert!(frame.iter().all(|b| *b == 9));
                count += frame.len();
                body.flow_control().release_capacity(frame.len()).unwrap();
            }
            assert_eq!(count, PAYLOAD);
            assert_eq!(
                body.trailers().await.unwrap().unwrap()["x-check"],
                "complete"
            );
        };
        timeout(Duration::from_secs(5), async {
            tokio::join!(upload, download);
        })
        .await
        .unwrap();
        assert_eq!(origin.received.lock().unwrap().len(), 1);
        assert_eq!(
            origin.sessions.lock().unwrap()[0].destination,
            session().destination
        );
        cancel.cancel();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
        let _ = timeout(Duration::from_secs(1), driver).await.unwrap();
        origin.join().await;
    }
}
#[test]
fn https_authority_permission_and_sni_coalescing_are_per_request() {
    let (context, _) = prepared(true);
    for (url, expected) in [
        ("https://a.test/upload", session().destination),
        (
            "https://b.test/upload",
            Destination::domain("b.test", 443).unwrap(),
        ),
    ] {
        let request::Decision::Forward(target) = context
            .plan(url.parse().unwrap(), session(), Scheme::Https, true)
            .unwrap()
        else {
            panic!("expected forward")
        };
        assert_eq!(target.session.destination, expected);
        assert_eq!(
            target.session.metadata.original.unwrap().destination,
            session().destination
        );
    }
    assert!(
        context
            .plan(
                "https://forbidden.test/upload".parse().unwrap(),
                session(),
                Scheme::Https,
                true
            )
            .is_err()
    );
    let mut wrong_port = session();
    wrong_port.destination = Destination::Ip("203.0.113.1:8443".parse().unwrap());
    let request::Decision::Forward(target) = context
        .plan(
            "https://a.test/upload".parse().unwrap(),
            wrong_port,
            Scheme::Https,
            true,
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        target.session.destination,
        Destination::domain("a.test", 443).unwrap()
    );
    assert!(target.session.sniffed_domain.is_none());
}
#[tokio::test]
async fn h2_per_request_authority_and_cancellation_do_not_leave_inline_drivers() {
    let (context, origin) = prepared(true);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let worker = tokio::spawn(async move {
        context
            .serve_h2(&mut server, session(), stop)
            .await
            .unwrap();
    });
    let (mut sender, driver) = wire::client::handshake(client).await.unwrap();
    let driver = tokio::spawn(driver);
    let (forbidden, _) = sender
        .send_request(
            Request::builder()
                .uri("https://forbidden.test/upload")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), forbidden)
            .await
            .unwrap()
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(origin.sessions.lock().unwrap().is_empty());
    let (mut held, _held_upload) = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("https://b.test/upload")
                .header("content-length", PAYLOAD)
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    tokio::select! {result=&mut held=>panic!("incomplete body unexpectedly completed: {}",result.is_ok()),()=tokio::time::sleep(Duration::from_millis(20))=>{}}
    cancel.cancel();
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    drop(sender);
    let _ = timeout(Duration::from_secs(1), driver).await.unwrap();
    // Upstream fixture expects a complete business body; cancellation is
    // deliberately observed as EOF/reset instead of normal completion.
    let tasks = std::mem::take(&mut *origin.tasks.lock().unwrap());
    for task in tasks {
        let _ = timeout(Duration::from_secs(1), task).await.unwrap();
    }
}

#[tokio::test]
async fn h2_early_final_h2_and_h1_finish_large_bodies_without_waiting_for_upload() {
    for upstream_h2 in [true, false] {
        let (context, origin) = prepared_with(upstream_h2, true);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h2(&mut server, session(), stop)
                .await
                .unwrap();
        });
        let mut builder = wire::client::Builder::new();
        builder
            .initial_window_size(8192)
            .initial_connection_window_size(16384);
        let (mut sender, driver) = builder.handshake::<_, Bytes>(client).await.unwrap();
        let driver = tokio::spawn(driver);
        let (first, mut upload) = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://a.test/upload")
                    .header("content-length", PAYLOAD)
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        upload
            .send_data(Bytes::from(vec![7; PAYLOAD / 2]), false)
            .unwrap();
        let first = timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.status(), StatusCode::PAYLOAD_TOO_LARGE);
        timeout(
            Duration::from_secs(2),
            require_early_body(first.into_body()),
        )
        .await
        .unwrap();
        sender = sender.ready().await.unwrap();
        let (second, _) = sender
            .send_request(
                Request::builder()
                    .uri("https://b.test/upload")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let second = timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.status(), StatusCode::PAYLOAD_TOO_LARGE);
        timeout(
            Duration::from_secs(2),
            require_early_body(second.into_body()),
        )
        .await
        .unwrap();
        assert_eq!(origin.sessions.lock().unwrap().len(), 2);
        drop(upload);
        cancel.cancel();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
        let _ = timeout(Duration::from_secs(1), driver).await.unwrap();
        origin.join().await;
    }
}

async fn require_early_body(mut body: wire::RecvStream) {
    let mut bytes = 0;
    while let Some(frame) = body.data().await {
        let frame = frame.unwrap();
        assert!(frame.iter().all(|byte| *byte == 9));
        bytes += frame.len();
        // Keep a real downstream window outstanding while the upstream
        // final response closes its unread request half.
        tokio::time::sleep(Duration::from_millis(5)).await;
        body.flow_control().release_capacity(frame.len()).unwrap();
    }
    assert_eq!(bytes, PAYLOAD);
}

#[tokio::test]
async fn truncated_h2_and_h1_responses_still_reset_downstream() {
    for upstream_h2 in [true, false] {
        let (context, origin) = prepared_response(upstream_h2, false, true);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h2(&mut server, session(), stop)
                .await
                .unwrap();
        });
        let (mut sender, driver) = wire::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(driver);
        let (response, _) = sender
            .send_request(
                Request::builder()
                    .uri("https://a.test/upload")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let response = timeout(Duration::from_secs(1), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let rejected = timeout(Duration::from_secs(1), async {
            let mut received = 0;
            while let Some(frame) = body.data().await {
                let Ok(frame) = frame else {
                    return received < PAYLOAD;
                };
                received += frame.len();
                body.flow_control().release_capacity(frame.len()).unwrap();
            }
            false
        })
        .await
        .unwrap();
        assert!(
            rejected,
            "truncated response must not become a successful body"
        );
        cancel.cancel();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
        let _ = timeout(Duration::from_secs(1), driver).await.unwrap();
        origin.join().await;
    }
}
