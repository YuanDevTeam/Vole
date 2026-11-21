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

#[path = "h2_receive_credit_memory_tests.rs"]
mod receive_credit_memory_tests;

#[cfg(target_vendor = "apple")]
async fn script_memory_response(
    context: HttpContext,
    request: Request<()>,
    payload: Bytes,
) -> Response<Vec<u8>> {
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let worker = tokio::spawn(async move {
        context
            .serve_h2(&mut server, session(), stop)
            .await
            .unwrap();
    });
    let (mut sender, connection) = wire::client::handshake(client).await.unwrap();
    let driver = tokio::spawn(connection);
    let (response, mut upload) = sender.send_request(request, payload.is_empty()).unwrap();
    let sending = async {
        if !payload.is_empty() {
            super::h2_body::send_data(&mut upload, payload)
                .await
                .unwrap();
            upload.send_data(Bytes::new(), true).unwrap();
        }
    };
    let receiving = async {
        let response = response.await.unwrap();
        let (parts, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(frame) = body.data().await {
            let frame = frame.unwrap();
            body.flow_control().release_capacity(frame.len()).unwrap();
            bytes.extend_from_slice(&frame);
        }
        Response::from_parts(parts, bytes)
    };
    let (_, response) = timeout(Duration::from_secs(5), async {
        tokio::join!(sending, receiving)
    })
    .await
    .unwrap();
    cancel.cancel();
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    drop(sender);
    driver.abort();
    let _ = driver.await;
    response
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn h2_scripts_only_local_response_skips_upstream_and_response_hooks() {
    let scripts = r#"
targets:
  - origins: [https://a.test]
    rules:
      - name: local
        match: {path-exact: /local}
        request:
          js:
            source: 'function rewrite(input) { return {type:"respond",status:201,headers:[{name:"Set-Cookie",value:"a=1"},{name:"Set-Cookie",value:"b=2"}],body:{kind:"bytes",data:Uint8Array.from([1,2,3])}}; }'
      - name: unreachable-request
        match: {path-exact: /local}
        request:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
      - name: unreachable-response
        match: {path-exact: /local}
        response:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
"#;
    let (context, origin) = prepared_origin_rules(true, false, false, OriginMode::None, scripts);
    let response = script_memory_response(
        context,
        Request::builder()
            .uri("https://a.test/local")
            .body(())
            .unwrap(),
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.body(), &[1, 2, 3]);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert!(origin.sessions.lock().unwrap().is_empty());
    origin.join().await;
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn h2_script_local_response_preserves_unfinished_upload_and_sibling_stream() {
    h2_local_response_preserves_streams(r#"
targets:
  - origins: [https://a.test]
    rules:
      - name: local
        match: {path-exact: /local}
        request:
          js:
            source: 'function rewrite(input) { return {type:"respond",status:201,body:{kind:"text",data:"local"}}; }'
"#, http::HeaderValue::from_static(""))
    .await;
}

#[tokio::test]
async fn h2_native_local_response_preserves_unfinished_upload_and_sibling_stream() {
    h2_local_response_preserves_streams(
        r#"
targets:
  - origins: [https://a.test]
    rules:
      - match:
          path-exact: /local
          request-headers:
            - {name: X-Present, exists: true}
        request:
          respond:
            status: 201
            body: {text: local}
      - request:
          url: {reject: true}
"#,
        http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    )
    .await;
}

async fn h2_local_response_preserves_streams(settings: &str, present: http::HeaderValue) {
    let (context, origin) = prepared_origin_rules(true, false, false, OriginMode::None, settings);
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let (client, mut server) = tokio::io::duplex(8192);
    let worker = tokio::spawn(async move {
        context
            .serve_h2(&mut server, session(), stop)
            .await
            .unwrap();
    });
    let (mut sender, connection) = wire::client::handshake(client).await.unwrap();
    let driver = tokio::spawn(connection);
    let (first, mut unfinished) = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("https://a.test/local")
                .header("x-present", present.clone())
                .header("content-length", 100)
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    unfinished
        .send_data(Bytes::from_static(b"part"), false)
        .unwrap();
    for response in [Some(first), None] {
        let response = if let Some(response) = response {
            response
        } else {
            sender = sender.ready().await.unwrap();
            sender
                .send_request(
                    Request::builder()
                        .uri("https://a.test/local")
                        .header("x-present", present.clone())
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap()
                .0
        };
        let response = timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(2), body.data()).await.unwrap() {
            let frame = frame.unwrap();
            body.flow_control().release_capacity(frame.len()).unwrap();
            bytes.extend_from_slice(&frame);
        }
        assert_eq!(bytes, b"local");
    }
    assert!(origin.sessions.lock().unwrap().is_empty());
    drop(unfinished);
    cancel.cancel();
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    drop(sender);
    driver.abort();
    let _ = driver.await;
    origin.join().await;
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn h2_scripts_mix_native_results_u0_selection_and_per_call_rollback() {
    let settings = r#"
targets:
  - origins: [https://a.test]
    rules:
      - match: {path-exact: /upload}
        request:
          url: {replace: {value: https://b.test/rewritten, mode: match}}
          headers:
            - {set: {X-Request: rewritten}}
            - {set: {Authorization: 'Bearer explicit'}}
            - {set: {Cookie: 'new=explicit'}}
          body:
            - {replace: {search: old, replacement: new}}
        response:
          headers:
            - {remove: Server}
          body:
            - {json-patch: [{op: replace, path: /token, value: native}]}
      - name: request-view
        match: {path-exact: /upload}
        request:
          js:
            body: text
            source: 'function rewrite(input) { if (input.request.url !== "https://b.test/rewritten" || input.body.data !== "new request") { return {type:"abort"}; } return {type:"modify",headers:[{op:"set",name:"x-js",values:["accepted"]}]}; }'
      - name: invalid-request
        match: {path-exact: /upload}
        request:
          js:
            source: 'function rewrite(input) { return {type:"modify",url:"https://invalid host/",headers:[{op:"remove",name:"authorization"}]}; }'
  - origins: [https://b.test]
    rules:
      - name: effective-url-is-not-selector
        match: {path-exact: /rewritten}
        request:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
  - origins: [https://a.test]
    rules:
      - name: response-body
        match: {path-exact: /upload}
        response:
          js:
            body: text
            source: 'function rewrite(input) { if (input.request.url !== "https://b.test/rewritten" || input.original.url !== "https://a.test/upload") { return {type:"abort"}; } let value=JSON.parse(input.body.data); if (value.token !== "native") { return {type:"abort"}; } value.token="script"; return {type:"modify",status:201,headers:[{op:"add",name:"set-cookie",values:["a=1","b=2"]}],body:{kind:"text",data:JSON.stringify(value)}}; }'
      - name: invalid-response
        match: {path-exact: /upload}
        response:
          js:
            source: 'function rewrite(input) { return {type:"modify",status:204,headers:[{op:"remove",name:"set-cookie"}]}; }'
"#;
    for upstream_h2 in [true, false] {
        let (context, origin) =
            prepared_origin_rules(upstream_h2, false, false, OriginMode::Rewrite, settings);
        let response = script_memory_response(
            context,
            Request::builder()
                .method("POST")
                .uri("https://a.test/upload")
                .header("content-length", 11)
                .header("authorization", "original")
                .header("cookie", "old=original")
                .body(())
                .unwrap(),
            Bytes::from_static(b"old request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(!response.headers().contains_key("server"));
        assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(response.body()).unwrap(),
            serde_json::json!({"ads":[1],"token":"script"})
        );
        assert_eq!(origin.received.lock().unwrap()[0], b"new request");
        assert_eq!(
            origin.sessions.lock().unwrap()[0].destination,
            Destination::domain("b.test", 443).unwrap()
        );
        origin.join().await;
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn h2_scripts_do_not_erase_obs_text_to_make_an_input_snapshot() {
    let settings = r#"
targets:
  - origins: [https://a.test]
    rules:
      - name: should-skip
        match: {path-exact: /upload}
        request:
          js:
            source: 'function rewrite(input) { return {type:"respond",status:201}; }'
      - name: response-must-also-have-representable-request
        match: {path-exact: /upload}
        response:
          js:
            source: 'function rewrite(input) { return {type:"abort"}; }'
"#;
    let (context, origin) = prepared_origin_rules(true, false, false, OriginMode::None, settings);
    let mut request = Request::builder()
        .method("POST")
        .uri("https://a.test/upload")
        .header("content-length", PAYLOAD)
        .body(())
        .unwrap();
    request
        .headers_mut()
        .insert("x-opaque", http::HeaderValue::from_bytes(&[0xff]).unwrap());
    let response = script_memory_response(context, request, Bytes::from(vec![7; PAYLOAD])).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), &vec![9; PAYLOAD]);
    assert_eq!(origin.received.lock().unwrap()[0], vec![7; PAYLOAD]);
    origin.join().await;
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn h2_script_body_collection_preserves_early_response_while_upload_is_unfinished() {
    let settings = r#"
targets:
  - origins: [https://a.test]
    rules:
      - name: complete-response-only
        match: {path-exact: /upload}
        response:
          js:
            body: bytes
            source: 'function rewrite(input) { if (input.body.data.length !== 98304) { return {type:"abort"}; } return {type:"modify",headers:[{op:"set",name:"x-js-complete",values:["yes"]}]}; }'
"#;
    for upstream_h2 in [true, false] {
        let (context, origin) =
            prepared_origin_rules(upstream_h2, true, false, OriginMode::None, settings);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h2(&mut server, session(), stop)
                .await
                .unwrap();
        });
        let (mut sender, connection) = wire::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, mut upload) = sender
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
        let response = timeout(Duration::from_secs(3), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.headers()["x-js-complete"], "yes");
        timeout(
            Duration::from_secs(3),
            require_early_body(response.into_body()),
        )
        .await
        .unwrap();
        drop(upload);
        cancel.cancel();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        drop(sender);
        driver.abort();
        let _ = driver.await;
        origin.join().await;
    }
}

#[tokio::test]
async fn h2_rewrite_stages_use_original_url_for_h2_and_h1_origins() {
    let rules = r#"
targets:
  - origins: [https://a.test]
    rules:
      - match: {url-regex: '^https://a\.test/upload$'}
        request:
          url: {replace: {value: https://b.test/rewritten, mode: match}}
          headers:
            - {set: {X-Request: rewritten}}
            - {set: {Authorization: 'Bearer explicit'}}
            - {set: {Cookie: 'new=explicit'}}
          body:
            - {replace: {search: old, replacement: new}}
        response:
          headers:
            - {remove: Server}
      - match:
          request-headers:
            - {name: Authorization, equals: Bearer original}
        response:
          when:
            status: 200
            headers:
              - {name: Server, exists: true}
          body:
            - {json-patch: [{op: replace, path: /ads, value: []}, {op: replace, path: /token, value: new}]}
"#;
    for upstream_h2 in [true, false] {
        let (context, origin) =
            prepared_origin_rules(upstream_h2, false, false, OriginMode::Rewrite, rules);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let (client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h2(&mut server, session(), stop)
                .await
                .unwrap();
        });
        let (mut sender, connection) = wire::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, mut upload) = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://a.test/upload")
                    .header("content-length", 11)
                    .header("authorization", "Bearer original")
                    .header("cookie", "old=original")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        upload
            .send_data(Bytes::from_static(b"old request"), true)
            .unwrap();
        let response = timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap();
        assert!(!response.headers().contains_key("server"));
        let expected = response.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = timeout(Duration::from_secs(5), body.data()).await.unwrap() {
            let frame = frame.unwrap();
            body.flow_control().release_capacity(frame.len()).unwrap();
            bytes.extend_from_slice(&frame);
        }
        assert_eq!(bytes.len(), expected);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"ads":[],"token":"new"})
        );
        assert_eq!(origin.received.lock().unwrap()[0], b"new request");
        cancel.cancel();
        timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        origin.join().await;
        driver.abort();
        let _ = driver.await;
    }
}
#[derive(Clone, Copy)]
enum OriginMode {
    None,
    BeforeUpload,
    AfterUpload,
    ShortClose {
        truncated: bool,
    },
    Rewrite,
    #[cfg(all(feature = "invoke", target_vendor = "apple"))]
    P1(P1Case),
}

#[cfg(all(feature = "invoke", target_vendor = "apple"))]
#[derive(Clone, Copy)]
struct P1Case {
    path: &'static str,
    media: &'static str,
    original: &'static [u8],
    changed: &'static [u8],
    witness: &'static str,
}

#[cfg(all(feature = "invoke", target_vendor = "apple"))]
#[tokio::test]
async fn p1_same_yaml_matches_offline_h1_and_h2() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};

    let yaml = include_str!("p1_memory_fixture.yaml");
    for case in [
        P1Case {
            path: "/filter",
            media: "application/json",
            original: br#"{"data":{"bottomBarControl":{"tabs":[{"tabType":"home"},{"tabType":"keep","weight":1.2000},{"tabType":"mall"},{"future":17}]}}}"#,
            changed: br#"{"data":{"bottomBarControl":{"tabs":[{"tabType":"keep","weight":1.2000},{"future":17}]}}}"#,
            witness: "json",
        },
        P1Case {
            path: "/protobuf",
            media: "application/protobuf",
            original: &[0x3a, 2, 0xff, 0, 0x4a, 8, 0x90, 1, 1, 8, 0x96, 1, 8, 2],
            changed: &[0x4a, 5, 8, 0x96, 1, 8, 2],
            witness: "protobuf",
        },
    ] {
        let url = format!("https://a.test{}?probe=p1+ok", case.path);
        let input = json!({
            "method":"testHttp",
            "payload": {
                "httpConfigYaml":yaml, "httpContext":{"mitmEnabled":true},
                "url":url, "executeScripts":true, "request":{},
                "response":{"status":200, "headers":[["content-type",case.media]], "bodyBase64":STANDARD.encode(case.original)}
            }
        });
        let offline: Value =
            serde_json::from_slice(&crate::invoke::invoke_bytes(&serde_json::to_vec(&input).unwrap()))
                .unwrap();
        assert_eq!(offline["success"], true, "{offline}");
        let offline = &offline["data"];
        assert!(offline["terminal"].is_null(), "{offline}");
        let stage = &offline["stages"][1];
        assert_eq!(stage["scripts"][0]["outcome"], "accepted", "{stage}");
        assert_eq!(stage["bodyOutcome"], "changed", "{stage}");
        let offline_body = STANDARD.decode(stage["bodyBase64"].as_str().unwrap()).unwrap();
        assert_eq!(offline_body, case.changed);
        assert!(stage["headers"].as_array().unwrap().contains(&json!(["x-p1",case.witness])));

        let (context, origin) =
            prepared_origin_rules(true, false, false, OriginMode::P1(case), yaml);
        let h2 = script_memory_response(
            context,
            Request::builder().uri(&url).body(()).unwrap(),
            Bytes::new(),
        )
        .await;
        assert_eq!(h2.status(), StatusCode::OK);
        assert_eq!(h2.body(), &offline_body);
        assert_eq!(h2.headers()["x-p1"], case.witness);
        assert_eq!(h2.headers()["content-length"], case.changed.len().to_string());
        origin.join().await;

        let (context, origin) =
            prepared_origin_rules(false, false, false, OriginMode::P1(case), yaml);
        let (mut client, mut server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(async move {
            context
                .serve_h1(&mut server, session(), Scheme::Https, CancellationToken::new())
                .await
                .unwrap();
        });
        let request = format!(
            "GET {}?probe=p1+ok HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n",
            case.path
        );
        client.write_all(request.as_bytes()).await.unwrap();
        let mut h1 = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut h1)).await.unwrap().unwrap();
        worker.await.unwrap();
        origin.join().await;
        let end = h1.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let head = std::str::from_utf8(&h1[..end + 2]).unwrap().to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 200 "));
        assert!(head.contains(&format!("x-p1: {}\r\n", case.witness)));
        assert!(head.contains(&format!("content-length: {}\r\n", case.changed.len())));
        assert_eq!(&h1[end + 4..], offline_body);
    }
}
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
    mode: OriginMode,
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
        let mode = self.mode;
        let received = self.received.clone();
        let (client, peer) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(peer)
                .await
            else {
                return;
            };
            if let OriginMode::ShortClose { truncated } = mode {
                if let Ok(body) = short_h2_reply_and_close(&mut tls, truncated).await {
                    received.lock().unwrap().push(body);
                }
                // Match an origin that sends one complete response and closes
                // without GOAWAY or TLS close_notify.
                return;
            }
            if h2 {
                let mut builder = wire::server::Builder::new();
                builder
                    .initial_window_size(8192)
                    .initial_connection_window_size(16384);
                let mut connection = builder.handshake::<_, Bytes>(tls).await.unwrap();
                let (request, mut response) = connection.accept().await.unwrap().unwrap();
                let exchange = async move {
                    #[cfg(all(feature = "invoke", target_vendor = "apple"))]
                    if let OriginMode::P1(case) = mode {
                        assert_eq!(request.uri().path(), case.path);
                        assert_eq!(request.headers()["x-p1-query"], "p1 ok");
                        let out = Response::builder()
                            .header("content-type", case.media)
                            .header("content-length", case.original.len())
                            .body(())
                            .unwrap();
                        response
                            .send_response(out, false)
                            .unwrap()
                            .send_data(Bytes::from_static(case.original), true)
                            .unwrap();
                        return;
                    }
                    if matches!(mode, OriginMode::Rewrite) {
                        assert_eq!(request.uri().path(), "/rewritten");
                        assert_eq!(request.headers()["x-request"], "rewritten");
                        assert_eq!(request.headers()["authorization"], "Bearer explicit");
                        assert_eq!(request.headers()["cookie"], "new=explicit");
                        let mut body = request.into_body();
                        let mut bytes = Vec::new();
                        while let Some(frame) = body.data().await {
                            let frame = frame.unwrap();
                            body.flow_control().release_capacity(frame.len()).unwrap();
                            bytes.extend_from_slice(&frame);
                        }
                        assert_eq!(bytes, b"new request");
                        received.lock().unwrap().push(bytes);
                        let payload = Bytes::from_static(br#"{"ads":[1],"token":"old"}"#);
                        let mut outgoing = response
                            .send_response(
                                Response::builder()
                                    .header("content-length", payload.len())
                                    .header("content-type", "application/json")
                                    .header("server", "origin")
                                    .body(())
                                    .unwrap(),
                                false,
                            )
                            .unwrap();
                        super::h2_body::send_data(&mut outgoing, payload)
                            .await
                            .unwrap();
                        outgoing.send_data(Bytes::new(), true).unwrap();
                        return;
                    }
                    if matches!(mode, OriginMode::BeforeUpload) {
                        tokio::time::sleep(Duration::from_secs(31)).await;
                        return;
                    }
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
                    if matches!(mode, OriginMode::AfterUpload) {
                        tokio::time::sleep(Duration::from_secs(31)).await;
                        return;
                    }
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
                #[cfg(all(feature = "invoke", target_vendor = "apple"))]
                if let OriginMode::P1(case) = mode {
                    assert!(
                        head.starts_with(&format!("GET {}?probe=p1+ok HTTP/1.1\r\n", case.path))
                    );
                    assert!(head.to_ascii_lowercase().contains("x-p1-query: p1 ok\r\n"));
                    tls.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        case.media, case.original.len()
                    ).as_bytes()).await.unwrap();
                    tls.write_all(case.original).await.unwrap();
                    tls.shutdown().await.unwrap();
                    return;
                }
                if matches!(mode, OriginMode::Rewrite) {
                    assert!(head.starts_with("POST /rewritten HTTP/1.1\r\n"));
                    assert!(
                        head.to_ascii_lowercase()
                            .contains("x-request: rewritten\r\n")
                    );
                    assert!(head.contains("Bearer explicit\r\n"));
                    assert!(head.contains("new=explicit\r\n"));
                    assert!(!head.contains("original\r\n"));
                    let mut body = [0u8; 11];
                    tls.read_exact(&mut body).await.unwrap();
                    assert_eq!(&body, b"new request");
                    received.lock().unwrap().push(body.to_vec());
                    let payload = br#"{"ads":[1],"token":"old"}"#;
                    tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nServer: origin\r\nConnection: close\r\n\r\n", payload.len()).as_bytes()).await.unwrap();
                    tls.write_all(payload).await.unwrap();
                    tls.shutdown().await.unwrap();
                    return;
                }
                if matches!(mode, OriginMode::BeforeUpload) {
                    tokio::time::sleep(Duration::from_secs(31)).await;
                    return;
                }
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
                if tls.read_exact(&mut bytes).await.is_err() {
                    return;
                }
                assert!(bytes.iter().all(|b| *b == 7));
                received.lock().unwrap().push(bytes);
                if matches!(mode, OriginMode::AfterUpload) {
                    tokio::time::sleep(Duration::from_secs(31)).await;
                    return;
                }
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
fn raw_h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 16 * 1024);
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.extend_from_slice(&[kind, flags]);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
async fn short_h2_reply_and_close<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    truncated: bool,
) -> std::io::Result<Vec<u8>> {
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    if preface != *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return Err(std::io::Error::other("invalid H2 preface"));
    }
    stream
        .write_all(&raw_h2_frame(4, 0, 0, &[0, 1, 0, 0, 0, 0]))
        .await?;
    let mut body = Vec::new();
    for _ in 0..128 {
        let mut head = [0; 9];
        stream.read_exact(&mut head).await?;
        let size = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        if size > 16 * 1024 {
            return Err(std::io::Error::other("oversized H2 frame"));
        }
        let mut frame = vec![0; size];
        stream.read_exact(&mut frame).await?;
        let id = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
        if head[3] == 4 && head[4] & 1 == 0 {
            stream.write_all(&raw_h2_frame(4, 1, 0, &[])).await?;
        } else if head[3] == 0 && id == 1 {
            body.extend_from_slice(&frame);
            if body.len() > 21_504 || frame.iter().any(|byte| *byte != 7) {
                return Err(std::io::Error::other("incorrect short upload"));
            }
            if !frame.is_empty() {
                let count = (frame.len() as u32).to_be_bytes();
                stream
                    .write_all(
                        &[raw_h2_frame(8, 0, 0, &count), raw_h2_frame(8, 0, 1, &count)].concat(),
                    )
                    .await?;
            }
        } else if matches!(head[3], 3 | 7) {
            return Err(std::io::Error::other("upload reset before short response"));
        }
        if id == 1 && (matches!(head[3], 0 | 1) && head[4] & 1 != 0) {
            if body.len() != 21_504 {
                return Err(std::io::Error::other("incomplete short upload"));
            }
            // HPACK: zero table, :status 200, literal content-length 11264.
            let mut headers = vec![0x20, 0x88];
            headers.extend_from_slice(&[0x0f, 0x0d, 5]);
            headers.extend_from_slice(b"11264");
            let mut reply = raw_h2_frame(1, 4, 1, &headers);
            let data = [9; 11_264];
            reply.extend_from_slice(&raw_h2_frame(
                0,
                1,
                1,
                &data[..if truncated { 5_632 } else { 11_264 }],
            ));
            stream.write_all(&reply).await?;
            stream.flush().await?;
            return Ok(body);
        }
    }
    Err(std::io::Error::other("short origin frame budget exceeded"))
}
fn prepared(h2: bool) -> (HttpContext, Arc<Origin>) {
    prepared_with(h2, false)
}
fn prepared_with(h2: bool, early: bool) -> (HttpContext, Arc<Origin>) {
    prepared_response(h2, early, false)
}
fn prepared_response(h2: bool, early: bool, truncated: bool) -> (HttpContext, Arc<Origin>) {
    prepared_origin(h2, early, truncated, OriginMode::None)
}
fn prepared_origin(
    h2: bool,
    early: bool,
    truncated: bool,
    mode: OriginMode,
) -> (HttpContext, Arc<Origin>) {
    prepared_origin_rules(h2, early, truncated, mode, "")
}
fn prepared_origin_rules(
    h2: bool,
    early: bool,
    truncated: bool,
    mode: OriginMode,
    rules: &str,
) -> (HttpContext, Arc<Origin>) {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = pem("CERTIFICATE", cert.der());
    let key_pem = pem("PRIVATE KEY", &key.serialize_der());
    let authority = authority::Authority::load(&cert_pem, &key_pem).unwrap();
    let document = super::config::Document::parse(if rules.is_empty() {
        "targets:\n  - origins: [https://a.test, https://b.test]\n    intercept-only: true\n"
    } else {
        rules
    })
    .unwrap();
    let candidate = document.compile().unwrap();
    let material = super::private_context::CaMaterial {
        certificate: cert_pem,
        private_key: zeroize::Zeroizing::new(key_pem),
    };
    let policy = candidate
        .bind_settings(
            &super::config::HttpSettings {
                mitm_enabled: true,
                allow_intercept_only: true,
                ..Default::default()
            },
            Some(&material),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let origin = Arc::new(Origin {
        authority,
        h2,
        early,
        truncated,
        mode,
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
async fn join_memory_owner<T>(mut task: tokio::task::JoinHandle<T>, seconds: u64) -> bool {
    match timeout(Duration::from_secs(seconds), &mut task).await {
        Ok(result) => result.is_ok(),
        Err(_) => {
            task.abort();
            let _ = task.await;
            false
        }
    }
}
#[tokio::test]
async fn h2_short_upload_preserves_complete_response_after_abrupt_origin_close() {
    let mut outcomes = Vec::new();
    for truncated in [false, true] {
        let (context, origin) =
            prepared_origin(true, false, false, OriginMode::ShortClose { truncated });
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
        let (response, mut body) = sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://a.test/upload")
                    .header("content-length", 21_504)
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let upload = async {
            super::h2_body::send_data(&mut body, Bytes::from_static(&[7; 21_504])).await?;
            body.send_data(Bytes::new(), true)
                .map_err(std::io::Error::other)
        };
        let download = async {
            let response = response.await.map_err(std::io::Error::other)?;
            if response.status() != StatusCode::OK {
                return Err(std::io::Error::other("wrong short response status"));
            }
            let mut body = response.into_body();
            let mut count = 0;
            while let Some(frame) = body.data().await {
                let frame = frame.map_err(std::io::Error::other)?;
                if frame.iter().any(|byte| *byte != 9) {
                    return Err(std::io::Error::other("incorrect short response body"));
                }
                count += frame.len();
                body.flow_control()
                    .release_capacity(frame.len())
                    .map_err(std::io::Error::other)?;
            }
            Ok(count)
        };
        let result = timeout(Duration::from_secs(3), async {
            tokio::join!(upload, download)
        })
        .await;
        cancel.cancel();
        let worker_joined = join_memory_owner(worker, 1).await;
        drop(sender);
        let driver_joined = join_memory_owner(driver, 1).await;
        let tasks = std::mem::take(&mut *origin.tasks.lock().unwrap());
        let mut origin_joined = true;
        for task in tasks {
            origin_joined &= join_memory_owner(task, 1).await;
        }
        let delivered = if truncated {
            matches!(&result, Ok((Ok(()), Err(_))))
        } else {
            matches!(&result, Ok((Ok(()), Ok(11_264))))
        };
        let received = origin.received.lock().unwrap();
        let complete_upload = received.len() == 1 && received[0].len() == 21_504;
        outcomes.push((
            truncated,
            delivered && complete_upload && worker_joined && driver_joined && origin_joined,
            format!("{result:?}"),
        ));
    }
    assert!(
        outcomes.iter().all(|(_, passed, _)| *passed),
        "short origin close changed delivery: {outcomes:?}"
    );
}
#[tokio::test(start_paused = true)]
async fn h2_continuous_upload_can_outlive_response_idle_for_h2_and_h1_origins() {
    let mut outcomes = Vec::new();
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
        let start = tokio::time::Instant::now();
        let upload = async {
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_secs(8)).await;
                super::h2_body::send_data(&mut body, Bytes::from_static(&[7; PAYLOAD / 6])).await?;
            }
            body.send_data(Bytes::new(), true)
                .map_err(std::io::Error::other)
        };
        let download = async {
            let response = response.await.map_err(std::io::Error::other)?;
            let mut body = response.into_body();
            let mut count = 0;
            while let Some(frame) = body.data().await {
                let frame = frame.map_err(std::io::Error::other)?;
                if frame.iter().any(|byte| *byte != 9) {
                    return Err(std::io::Error::other("incorrect response body"));
                }
                count += frame.len();
                body.flow_control()
                    .release_capacity(frame.len())
                    .map_err(std::io::Error::other)?;
            }
            if count != PAYLOAD
                || body
                    .trailers()
                    .await
                    .map_err(std::io::Error::other)?
                    .and_then(|trailers| trailers.get("x-check").cloned())
                    .is_none_or(|value| value != "complete")
            {
                return Err(std::io::Error::other(
                    "incomplete response body or trailers",
                ));
            }
            Ok(())
        };
        let result = timeout(Duration::from_secs(70), async {
            tokio::join!(upload, download)
        })
        .await;
        let elapsed = start.elapsed();
        cancel.cancel();
        let worker_joined = join_memory_owner(worker, 1).await;
        drop(sender);
        let driver_joined = join_memory_owner(driver, 1).await;
        let tasks = std::mem::take(&mut *origin.tasks.lock().unwrap());
        let mut origins_joined = true;
        for task in tasks {
            origins_joined &= join_memory_owner(task, 1).await;
        }
        let passed = matches!(&result, Ok((Ok(()), Ok(()))))
            && elapsed >= Duration::from_secs(48)
            && elapsed < Duration::from_secs(49)
            && origin.received.lock().unwrap().len() == 1
            && worker_joined
            && driver_joined
            && origins_joined;
        outcomes.push((upstream_h2, passed, elapsed, format!("{result:?}")));
    }
    assert!(
        outcomes.iter().all(|(_, passed, _, _)| *passed),
        "continuous upload was cut off before its response: {outcomes:?}"
    );
}
#[tokio::test(start_paused = true)]
async fn h2_response_wait_stays_bounded_after_upload_and_during_backpressure() {
    let mut outcomes = Vec::new();
    for upstream_h2 in [true, false] {
        for (mode, empty) in [
            (OriginMode::BeforeUpload, false),
            (OriginMode::AfterUpload, false),
            (OriginMode::BeforeUpload, true),
        ] {
            let (context, origin) = prepared_origin(upstream_h2, false, false, mode);
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
            let (response, mut body) = sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("https://a.test/upload")
                        .header("content-length", if empty { 0 } else { PAYLOAD })
                        .body(())
                        .unwrap(),
                    empty,
                )
                .unwrap();
            let start = tokio::time::Instant::now();
            let upload = async {
                if empty {
                    return Ok(());
                }
                super::h2_body::send_data(&mut body, Bytes::from_static(&[7; PAYLOAD])).await?;
                body.send_data(Bytes::new(), true)
                    .map_err(std::io::Error::other)
            };
            let download = async {
                let result = response.await;
                (result.is_err(), start.elapsed())
            };
            let result = timeout(Duration::from_secs(35), async {
                tokio::join!(upload, download)
            })
            .await;
            cancel.cancel();
            let worker_joined = join_memory_owner(worker, 1).await;
            drop(sender);
            let driver_joined = join_memory_owner(driver, 1).await;
            let tasks = std::mem::take(&mut *origin.tasks.lock().unwrap());
            let mut origins_joined = true;
            for task in tasks {
                origins_joined &= join_memory_owner(task, 2).await;
            }
            let uploaded = !matches!(mode, OriginMode::AfterUpload)
                || (matches!(&result, Ok((Ok(()), _)))
                    && origin.received.lock().unwrap().len() == 1);
            let bounded = matches!(result,
                Ok((_, (true, elapsed))) if elapsed >= Duration::from_secs(30)
                    && elapsed < Duration::from_secs(31));
            outcomes.push((
                upstream_h2,
                empty,
                bounded && uploaded && worker_joined && driver_joined && origins_joined,
            ));
        }
    }
    assert!(
        outcomes.iter().all(|(_, _, passed)| *passed),
        "unbounded response wait: {outcomes:?}"
    );
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
            .plan(
                url.parse().unwrap(),
                http::Method::GET,
                session(),
                Scheme::Https,
                true,
            )
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
    assert!(matches!(
        context.plan(
            "https://forbidden.test/upload".parse().unwrap(),
            http::Method::GET,
            session(),
            Scheme::Https,
            true,
        ),
        Ok(request::Decision::Reject)
    ));
    let mut wrong_port = session();
    wrong_port.destination = Destination::Ip("203.0.113.1:8443".parse().unwrap());
    for (url, downstream) in [
        ("https://a.test/upload", wrong_port),
        ("https://a.test:8443/upload", session()),
    ] {
        assert!(matches!(
            context.plan(
                url.parse().unwrap(),
                http::Method::GET,
                downstream,
                Scheme::Https,
                true,
            ),
            Ok(request::Decision::Reject)
        ));
    }
}
#[tokio::test]
async fn h2_per_request_authority_and_cancellation_do_not_leave_inline_drivers() {
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
