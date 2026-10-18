use super::*;
use crate::config::{ControllerCors, ControllerTls};
use bytes::Bytes;

fn context() -> RequestContext {
    RequestContext {
        secret: Some("token".into()),
        traffic: None,
        proxy_groups: tests::test_groups(),
        resources: None,
        cors: Arc::new(cors::Policy::new(&ControllerCors {
            allow_origins: vec!["https://*.example".into()],
            allow_private_network: true,
        })),
        requests: tokio_util::task::TaskTracker::new(),
        subscriptions: Arc::new(tokio::sync::Semaphore::new(websocket::MAX_SUBSCRIPTIONS)),
        logs: None,
    }
}

async fn h1(request: &str, context: RequestContext) -> String {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let serve = tokio::spawn(handle_connection(
        H1Io(server),
        context,
        CancellationToken::new(),
    ));
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    serve.await.unwrap().unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn controller_secure_http_cors_keeps_bearer_and_preflight_boundaries() {
    let context = context();
    let response = h1("OPTIONS /group HTTP/1.1\r\nHost: local\r\nOrigin: https://UI.example\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: authorization, content-type\r\nAccess-Control-Request-Private-Network: true\r\n\r\n", context.clone()).await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("Access-Control-Allow-Origin: https://UI.example\r\n"));
    assert!(response.contains("Access-Control-Allow-Headers: Authorization, Content-Type\r\n"));
    assert!(response.contains("Access-Control-Allow-Private-Network: true\r\n"));
    assert!(response.contains("Access-Control-Max-Age: 300\r\n"));
    assert_eq!(response.matches("Vary:").count(), 3);
    assert!(!response.contains("Allow-Credentials"));
    let response = h1(
        "GET /group HTTP/1.1\r\nHost: local\r\nOrigin: https://ui.example\r\n\r\n",
        context.clone(),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 401"));
    assert!(response.contains("Access-Control-Allow-Origin: https://ui.example"));
    let response = h1("OPTIONS /group HTTP/1.1\r\nHost: local\r\nOrigin: https://other.invalid\r\nAccess-Control-Request-Method: PUT\r\n\r\n", context.clone()).await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.contains("Access-Control-Allow-Origin"));
    let response = h1("GET /group HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer token\r\nOrigin: https://ui.example\r\n\r\n", context).await;
    assert!(response.starts_with("HTTP/1.1 200"));
    let body: serde_json::Value =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["proxies"][0]["now"], "node-a");
}

fn tls() -> (Arc<tls::ServerTls>, Arc<rustls::ClientConfig>) {
    let material = rcgen::generate_simple_self_signed(vec!["controller.example".into()]).unwrap();
    use base64::Engine as _;
    let pem = |label, bytes| {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    };
    let options = ControllerTls {
        certificate: pem("CERTIFICATE", material.cert.der().as_ref()).into(),
        private_key: pem("PRIVATE KEY", &material.signing_key.serialize_der()).into(),
        ..Default::default()
    };
    let server = Arc::new(tls::ServerTls::load(&options, std::path::Path::new(".")).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(material.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    (server, Arc::new(client))
}

#[tokio::test]
async fn controller_secure_https_h1_and_real_h2_share_routes_and_stop_children() {
    let (tls, client_config) = tls();
    for alpn in [b"http/1.1".as_slice(), b"h2".as_slice()] {
        let context = context();
        let tracker = context.requests.clone();
        let cancel = CancellationToken::new();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let serve = tokio::spawn(transport::serve_tls(
            server,
            tls.clone(),
            context,
            cancel.clone(),
        ));
        let mut config = client_config.as_ref().clone();
        config.alpn_protocols = vec![alpn.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        let mut client = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect("controller.example".try_into().unwrap(), client)
            .await
            .unwrap();
        assert_eq!(client.get_ref().1.alpn_protocol(), Some(alpn));
        if alpn == b"http/1.1" {
            client
                .write_all(
                    b"GET /group HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer token\r\n\r\n",
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
        } else {
            let (mut sender, driver) = h2::client::handshake(client).await.unwrap();
            let driver = tokio::spawn(driver);
            let request = |method, path, body| {
                let mut request = http::Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", "Bearer token")
                    .header("origin", "https://ui.example");
                if body {
                    request = request
                        .header("content-type", "application/json")
                        .header("content-length", "17");
                }
                request.body(()).unwrap()
            };
            let (aborted, mut upload) = sender
                .send_request(
                    request("PUT", "/proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF", true),
                    false,
                )
                .unwrap();
            while tracker.len() == 0 {
                tokio::task::yield_now().await;
            }
            let (query, _) = sender
                .send_request(request("GET", "/group", false), true)
                .unwrap();
            let response = query.await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.headers()["access-control-allow-origin"],
                "https://ui.example"
            );
            let mut body = response.into_body();
            let mut json = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                json.extend_from_slice(&bytes);
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&json).unwrap()["proxies"][0]["now"],
                "node-a"
            );
            upload.send_reset(h2::Reason::CANCEL);
            assert!(aborted.await.is_err());
            while tracker.len() != 0 {
                tokio::task::yield_now().await;
            }
            let (selected, mut upload) = sender
                .send_request(
                    request("PUT", "/proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF", true),
                    false,
                )
                .unwrap();
            upload
                .send_data(Bytes::from_static(b"{\"name\":\"node-b\"}"), true)
                .unwrap();
            assert_eq!(selected.await.unwrap().status(), 204);
            let (query, _) = sender
                .send_request(request("GET", "/group", false), true)
                .unwrap();
            let mut body = query.await.unwrap().into_body();
            let mut json = Vec::new();
            while let Some(bytes) = body.data().await {
                let bytes = bytes.unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                json.extend_from_slice(&bytes);
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&json).unwrap()["proxies"][0]["now"],
                "node-b"
            );
            let (waiting, _body) = sender
                .send_request(
                    request("PUT", "/proxies/%E4%B8%BB%E7%BA%BF%E8%B7%AF", true),
                    false,
                )
                .unwrap();
            while tracker.len() == 0 {
                tokio::task::yield_now().await;
            }
            cancel.cancel();
            serve.await.unwrap().unwrap();
            tracker.close();
            tokio::time::timeout(Duration::from_secs(2), tracker.wait())
                .await
                .unwrap();
            assert_eq!(tracker.len(), 0);
            assert!(waiting.await.is_err());
            drop(sender);
            let _ = driver.await.unwrap();
            continue;
        }
        cancel.cancel();
        serve.await.unwrap().unwrap();
        assert_eq!(tracker.len(), 0);
    }
}
