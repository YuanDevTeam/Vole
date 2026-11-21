//! Protocol boundaries exercised through the real HTTP/1 adapter with duplex IO.
use super::*;
use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    session::{DatagramSession, Destination, InboundKind, InboundMetadata, StreamSession},
};
use async_trait::async_trait;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Origin {
    drain: bool,
    buffered: bool,
    reply: Reply,
    received: Arc<Mutex<Vec<u8>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
#[derive(Clone, Copy, Default)]
enum Reply {
    #[default]
    Standard,
    Continue,
    Upgrade,
}
#[async_trait]
impl Dispatcher for Origin {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        let (client, mut peer) = tokio::io::duplex(4096);
        let received = self.received.clone();
        let drain = self.drain;
        let reply = self.reply;
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let mut bytes = Vec::new();
            loop {
                match peer.read_u8().await {
                    Ok(byte) => bytes.push(byte),
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        *received.lock().unwrap() = bytes;
                        return;
                    }
                    Err(error) => panic!("origin head: {error}"),
                }
                assert!(bytes.len() <= 32768);
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            if drain {
                peer.read_to_end(&mut bytes).await.unwrap();
            } else {
                if matches!(reply, Reply::Upgrade) {
                    peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nServer: original\r\nX-Stage: original\r\n\r\nserver-first")
                        .await
                        .unwrap();
                    let mut ping = [0; 4];
                    peer.read_exact(&mut ping).await.unwrap();
                    assert_eq!(&ping, b"ping");
                    peer.write_all(b"pong").await.unwrap();
                    peer.shutdown().await.unwrap();
                    *received.lock().unwrap() = bytes;
                    return;
                }
                if matches!(reply, Reply::Continue) {
                    peer.write_all(b"HTTP/1.1 100 Continue\r\nServer: original\r\nX-Stage: original\r\n\r\n")
                        .await
                        .unwrap();
                }
                let head = std::str::from_utf8(&bytes).unwrap();
                let length = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                });
                if let Some(length) = length {
                    let at = bytes.len();
                    bytes.resize(at + length, 0);
                    peer.read_exact(&mut bytes[at..]).await.unwrap();
                }
                if matches!(reply, Reply::Continue) {
                    peer.write_all(b"HTTP/1.1 103 Early Hints\r\nServer: original\r\nX-Stage: original\r\n\r\n")
                        .await
                        .unwrap();
                }
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nServer: original\r\nX-Stage: original\r\n\r\nok",
                )
                .await
                .unwrap();
                peer.shutdown().await.unwrap();
            }
            *received.lock().unwrap() = bytes;
        }));
        if self.buffered {
            Ok(Box::new(FlushOnly {
                inner: client,
                pending: vec![],
                at: 0,
            }))
        } else {
            Ok(Box::new(client))
        }
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
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

// AsyncWrite is allowed to accept bytes before sending them. VMess and several
// other protocol transports depend on flush to make their last frame visible.
struct FlushOnly {
    inner: DuplexStream,
    pending: Vec<u8>,
    at: usize,
}
impl AsyncRead for FlushOnly {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, output)
    }
}
impl AsyncWrite for FlushOnly {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(self.pending.len() + input.len() <= 32768);
        self.pending.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.at < this.pending.len() {
            let count = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.at..]))?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.at += count;
        }
        this.pending.clear();
        this.at = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(80),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:54321".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:80".parse().unwrap()),
        sniffed_domain: None,
    }
}
fn context(origin: Arc<Origin>, body: bool) -> HttpContext {
    let request_body = if body {
        "          body:\n            - {set: changed}\n"
    } else {
        ""
    };
    let input = format!(
        r#"targets:
  - origins: [http://old.invalid]
    rules:
      - request:
          url: {{replace: http://new.invalid/rewritten}}
          headers:
            - {{set: {{Authorization: 'Bearer explicit'}}}}
            - {{set: {{Cookie: 'new=explicit'}}}}
{request_body}        response:
          headers:
            - {{set: {{X-Stage: changed}}}}
            - {{remove: Server}}
"#
    );
    HttpContext::new(
        Policy::compile(&input).unwrap(),
        origin,
        SecurityContext::new(),
    )
}
async fn exchange(context: HttpContext, input: &[u8]) -> (io::Result<Intercept>, Vec<u8>) {
    let (mut client, mut peer) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut peer, session(), CancellationToken::new())
            .await
    });
    client.write_all(input).await.unwrap();
    let mut output = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut output))
        .await
        .unwrap()
        .unwrap();
    (task.await.unwrap(), output)
}

async fn head(client: &mut DuplexStream) -> String {
    timeout(Duration::from_secs(1), async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 32768);
            bytes.push(client.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}
fn rewritten(head: &str, status: u16) {
    assert!(head.starts_with(&format!("HTTP/1.1 {status} ")));
    let lowercase = head.to_ascii_lowercase();
    assert!(lowercase.contains("x-stage: changed\r\n"));
    assert!(!lowercase.contains("server:"));
}

#[tokio::test]
async fn h1_native_local_reply_ends_an_unread_upload() {
    let origin = Arc::new(Origin::default());
    let yaml = r#"
targets:
  - origins: [http://old.invalid]
    rules:
      - match:
          method: POST
          request-headers:
            - {name: X-Mode, equals: mock}
        request:
          respond:
            status: 201
            headers:
              - {name: set-cookie, value: a=1}
              - {name: set-cookie, value: b=2}
            body: {base64: AQAC}
      - request:
          url: {reject: true}
      - response:
          headers:
            - {set: {X-Unreachable: yes}}
"#;
    let context = HttpContext::new(
        Policy::compile(yaml).unwrap(),
        origin.clone(),
        SecurityContext::new(),
    );
    let (result, output) = exchange(
        context,
        b"POST / HTTP/1.1\r\nHost: old.invalid\r\nX-MODE: real\r\nX-Mode: mock\r\nContent-Length: 64\r\nExpect: 100-continue\r\n\r\n",
    )
    .await;
    assert!(matches!(result.unwrap(), Intercept::Handled));
    let split = output.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&output[..split])
        .unwrap()
        .to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 201"), "{head}");
    assert!(head.contains("connection: close"), "{head}");
    assert!(head.contains("content-length: 3"), "{head}");
    assert!(
        head.contains("set-cookie: a=1\r\nset-cookie: b=2"),
        "{head}"
    );
    assert!(!head.contains("x-unreachable"), "{head}");
    assert_eq!(&output[split + 4..], &[1, 0, 2]);
    assert!(origin.tasks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn h1_staged_conditions_match_original_headers_through_body_rewrite() {
    let origin = Arc::new(Origin::default());
    let yaml = r#"
targets:
  - origins: [http://old.invalid]
    rules:
      - request:
          headers:
            - {set: {X-Mode: edited}}
        response:
          headers:
            - {set: {X-Stage: edited}}
      - match:
          request-headers:
            - {name: X-MODE, equals: original}
        request:
          headers:
            - {set: {X-Original-Request: '1'}}
        response:
          when:
            status: 200
            headers:
              - {name: X-STAGE, equals: original}
          body:
            - {set: edited-body}
      - match:
          request-headers:
            - {name: X-Mode, equals: edited}
        request:
          headers:
            - {set: {X-False-Request: '1'}}
      - response:
          when:
            headers:
              - {name: X-Stage, equals: edited}
          headers:
            - {set: {X-False-Response: '1'}}
"#;
    let context = HttpContext::new(
        Policy::compile(yaml).unwrap(),
        origin.clone(),
        SecurityContext::new(),
    );
    let (result, output) = exchange(
        context,
        b"GET / HTTP/1.1\r\nHost: old.invalid\r\nX-Mode: original\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(matches!(result.unwrap(), Intercept::Handled));
    let response = String::from_utf8(output).unwrap().to_ascii_lowercase();
    assert!(response.contains("x-stage: edited\r\n"), "{response}");
    assert!(!response.contains("x-false-response"), "{response}");
    assert!(response.ends_with("\r\n\r\nedited-body"), "{response}");
    origin.join().await;
    let request = String::from_utf8(origin.received.lock().unwrap().clone())
        .unwrap()
        .to_ascii_lowercase();
    assert!(request.contains("x-mode: edited\r\n"), "{request}");
    assert!(request.contains("x-original-request: 1\r\n"), "{request}");
    assert!(!request.contains("x-false-request"), "{request}");
}

#[tokio::test]
async fn cross_origin_explicit_credentials_survive_and_empty_requests_are_flushed() {
    let origin = Arc::new(Origin {
        buffered: true,
        ..Default::default()
    });
    let (result, output) = exchange(
        context(origin.clone(), false),
        b"GET / HTTP/1.1\r\nHost: old.invalid\r\nAuthorization: Bearer original\r\nCookie: old=original\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(matches!(result.unwrap(), Intercept::Handled));
    assert!(output.ends_with(b"\r\n\r\nok"));
    origin.join().await;
    let received = origin.received.lock().unwrap();
    let text = std::str::from_utf8(&received).unwrap();
    assert!(text.starts_with("GET /rewritten HTTP/1.1\r\n"));
    let lowercase = text.to_ascii_lowercase();
    assert!(lowercase.contains("authorization: bearer explicit\r\n"));
    assert!(lowercase.contains("cookie: new=explicit\r\n"));
    assert!(!text.contains("original"));
}

#[tokio::test]
async fn cross_origin_cookie_trailers_cannot_restore_original_credentials() {
    let origin = Arc::new(Origin {
        drain: true,
        ..Default::default()
    });
    let (result, output) = exchange(
        context(origin.clone(), false),
        b"POST / HTTP/1.1\r\nHost: old.invalid\r\nCookie: old=original\r\nTransfer-Encoding: chunked\r\nTrailer: Cookie\r\nConnection: close\r\n\r\n3\r\nold\r\n0\r\nCookie: trailer=original-secret\r\n\r\n",
    )
    .await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
    assert!(output.starts_with(b"HTTP/1.1 400"));
    origin.join().await;
    let received = origin.received.lock().unwrap();
    let text = std::str::from_utf8(&received).unwrap();
    assert!(
        text.to_ascii_lowercase()
            .contains("cookie: new=explicit\r\n")
    );
    assert!(!text.contains("original-secret"));
    assert!(!text.contains("old=original"));
}

#[tokio::test]
async fn request_body_commit_rebuilds_a_valid_fixed_length_head() {
    let origin = Arc::new(Origin {
        buffered: true,
        ..Default::default()
    });
    let (result, output) = exchange(
        context(origin.clone(), true),
        b"POST / HTTP/1.1\r\nHost: old.invalid\r\nContent-Length: 3\r\nConnection: close\r\n\r\nold",
    )
    .await;
    assert!(matches!(result.unwrap(), Intercept::Handled));
    assert!(output.ends_with(b"\r\n\r\nok"));
    origin.join().await;
    let received = origin.received.lock().unwrap();
    let text = std::str::from_utf8(&received).unwrap();
    assert!(text.contains("Content-Length: 7\r\n"));
    assert!(text.ends_with("\r\n\r\nchanged"));
}

#[tokio::test]
async fn local_continue_preserves_original_connection_trailer_blocklist() {
    let origin = Arc::new(Origin::default());
    let context = context(origin.clone(), true);
    let (mut client, peer) = tokio::io::duplex(4096);
    let mut peer = FlushOnly {
        inner: peer,
        pending: vec![],
        at: 0,
    };
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut peer, session(), CancellationToken::new())
            .await
    });
    client.write_all(b"POST / HTTP/1.1\r\nHost: old.invalid\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\nConnection: X-Private, close\r\nX-Private: original\r\n\r\n").await.unwrap();
    let mut interim = [0u8; 25];
    timeout(Duration::from_secs(1), client.read_exact(&mut interim))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    client
        .write_all(b"3\r\nold\r\n0\r\nX-Private: trailer-secret\r\n\r\n")
        .await
        .unwrap();
    let error = timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    origin.join().await;
    assert!(origin.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn informational_headers_are_rewritten_and_continue_is_flushed_before_upload() {
    let origin = Arc::new(Origin {
        buffered: true,
        reply: Reply::Continue,
        ..Default::default()
    });
    let context = context(origin.clone(), false);
    let (mut client, peer) = tokio::io::duplex(4096);
    let mut peer = FlushOnly {
        inner: peer,
        pending: vec![],
        at: 0,
    };
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut peer, session(), CancellationToken::new())
            .await
    });
    client.write_all(b"POST / HTTP/1.1\r\nHost: old.invalid\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").await.unwrap();
    rewritten(&head(&mut client).await, 100);
    client.write_all(b"old").await.unwrap();
    rewritten(&head(&mut client).await, 103);
    rewritten(&head(&mut client).await, 200);
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, b"ok");
    assert!(matches!(task.await.unwrap().unwrap(), Intercept::Handled));
    origin.join().await;
    assert!(origin.received.lock().unwrap().ends_with(b"\r\n\r\nold"));
}

#[tokio::test]
async fn upgrade_headers_are_rewritten_and_flushed_before_tunnel_half_close() {
    let origin = Arc::new(Origin {
        buffered: true,
        reply: Reply::Upgrade,
        ..Default::default()
    });
    let context = context(origin.clone(), false);
    let (mut client, peer) = tokio::io::duplex(4096);
    let mut peer = FlushOnly {
        inner: peer,
        pending: vec![],
        at: 0,
    };
    let task = tokio::spawn(async move {
        context
            .try_intercept(&mut peer, session(), CancellationToken::new())
            .await
    });
    client.write_all(b"GET / HTTP/1.1\r\nHost: old.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
    let response = head(&mut client).await;
    rewritten(&response, 101);
    assert!(response.contains("Connection: Upgrade\r\nUpgrade: websocket\r\n"));
    client.write_all(b"ping").await.unwrap();
    client.shutdown().await.unwrap();
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body, b"server-firstpong");
    assert!(matches!(task.await.unwrap().unwrap(), Intercept::Handled));
    origin.join().await;
}
