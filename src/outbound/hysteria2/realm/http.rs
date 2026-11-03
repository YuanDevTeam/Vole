//! One bounded control POST over caller-owned IO. The HTTP driver is polled
//! inline with the exchange: dropping setup cannot detach a connection task.
use super::{fail, wire};
use crate::{
    config::Hysteria2Realm,
    dispatch::{BoxStream, DispatchError},
    outbound::{EstablishContext, UpstreamPath},
    security::StandardTlsClient,
    session::{DatagramSession, StreamSession},
};
use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
const BODY_LIMIT: usize = 16 * 1024;
struct JsonBody(Option<Bytes>);
impl Body for JsonBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Bytes>>>> {
        Poll::Ready(self.0.take().map(|bytes| Ok(Frame::data(bytes))))
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |b| b.len() as u64))
    }
}
#[derive(serde::Deserialize)]
struct Answer {
    addresses: Vec<SocketAddr>,
    nonce: String,
    obfs: String,
}
async fn driven<T>(
    driver: impl Future<Output = io::Result<()>>,
    exchange: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::pin!(driver, exchange);
    let mut done = false;
    loop {
        tokio::select! {
            result=&mut exchange=>return result,
            result=&mut driver,if !done=>{result?;done=true;}
        }
    }
}
async fn h1(io: BoxStream, mut request: http::Request<Bytes>) -> io::Result<Vec<u8>> {
    let (mut sender, driver) = hyper::client::conn::http1::Builder::new()
        .max_headers(100)
        .max_buf_size(16 * 1024)
        .handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|_| fail())?;
    let authority = request
        .uri()
        .authority()
        .ok_or_else(fail)?
        .as_str()
        .to_owned();
    request
        .headers_mut()
        .insert(http::header::HOST, authority.parse().map_err(|_| fail())?);
    request.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("close"),
    );
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .ok_or_else(fail)?
        .as_str()
        .parse()
        .map_err(|_| fail())?;
    let exchange = async {
        let response = sender
            .send_request(request.map(|bytes| JsonBody(Some(bytes))))
            .await
            .map_err(|_| fail())?;
        if !response.status().is_success() {
            return Err(fail());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
        {
            let frame = frame.map_err(|_| fail())?;
            if let Ok(data) = frame.into_data() {
                if bytes.len() + data.len() > BODY_LIMIT {
                    return Err(fail());
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    };
    driven(async { driver.await.map_err(|_| fail()) }, exchange).await
}
async fn h2(io: BoxStream, request: http::Request<Bytes>) -> io::Result<Vec<u8>> {
    let (sender, driver) = h2::client::Builder::new()
        .max_header_list_size(16 * 1024)
        .initial_window_size(16 * 1024)
        .initial_connection_window_size(32 * 1024)
        .handshake(io)
        .await
        .map_err(|_| fail())?;
    let (parts, body) = request.into_parts();
    let exchange = async {
        let mut sender = sender.ready().await.map_err(|_| fail())?;
        let (response, mut send) = sender
            .send_request(http::Request::from_parts(parts, ()), false)
            .map_err(|_| fail())?;
        send.send_data(body, true).map_err(|_| fail())?;
        let response = response.await.map_err(|_| fail())?;
        if !response.status().is_success() {
            return Err(fail());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(data) = body.data().await {
            let data = data.map_err(|_| fail())?;
            if bytes.len() + data.len() > BODY_LIMIT {
                return Err(fail());
            }
            bytes.extend_from_slice(&data);
            body.flow_control()
                .release_capacity(data.len())
                .map_err(|_| fail())?;
        }
        Ok(bytes)
    };
    driven(async { driver.await.map_err(|_| fail()) }, exchange).await
}
pub(super) async fn connect(
    options: &Hysteria2Realm,
    tls: Option<&StandardTlsClient>,
    upstream: &UpstreamPath,
    datagram: &DatagramSession,
    context: &EstablishContext,
    addresses: &[SocketAddr],
    metadata: &wire::Metadata,
) -> Result<(Vec<SocketAddr>, wire::Metadata), DispatchError> {
    let mut url = url::Url::parse(&options.server_url).map_err(|_| fail())?;
    let base = url.path().trim_end_matches('/').to_owned();
    url.set_path(&format!(
        "{base}/v1/{}/connect",
        percent_segment(&options.realm_id)
    ));
    // Url::set_path preserves valid percent escapes; credentials/query are
    // already rejected by normalization and never become error text.
    let server = crate::outbound::server_destination(
        url.host_str().ok_or_else(fail)?.trim_matches(['[', ']']),
        url.port_or_known_default().ok_or_else(fail)?,
    )?;
    let session = StreamSession {
        inbound: datagram.inbound,
        source: datagram.source,
        destination: server.clone(),
        sniffed_domain: None,
        metadata: datagram.metadata.clone(),
    };
    let raw = upstream
        .for_server(&server, false)
        .connect_server(session, &server, context)
        .await?
        .io;
    let (raw, alpn) = if let Some(tls) = tls {
        tls.connect_negotiated(raw).await?
    } else {
        (raw, None)
    };
    let body=serde_json::to_vec(&serde_json::json!({"addresses":addresses,"nonce":wire::hex(&metadata.nonce),"obfs":wire::hex(&metadata.key)})).map_err(|_|fail())?;
    if body.len() > BODY_LIMIT {
        return Err(fail().into());
    }
    let mut builder = http::Request::builder()
        .method("POST")
        .uri(url.as_str())
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len());
    if !options.token.is_empty() {
        builder = builder.header("Authorization", format!("Bearer {}", options.token));
    }
    let request = builder.body(Bytes::from(body)).map_err(|_| fail())?;
    let bytes = match alpn.as_deref() {
        Some(b"h2") => h2(raw, request).await?,
        None | Some(b"http/1.1") => h1(raw, request).await?,
        _ => return Err(fail().into()),
    };
    let answer: Answer = serde_json::from_slice(&bytes).map_err(|_| fail())?;
    if answer.addresses.is_empty()
        || answer.addresses.len() > 32
        || answer
            .addresses
            .iter()
            .any(|addr| addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast())
    {
        return Err(fail().into());
    }
    let metadata = wire::Metadata {
        nonce: wire::unhex(&answer.nonce).ok_or_else(fail)?,
        key: wire::unhex(&answer.obfs).ok_or_else(fail)?,
    };
    Ok((answer.addresses, metadata))
}
fn percent_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn request() -> http::Request<Bytes> {
        http::Request::builder()
            .method("POST")
            .uri("http://192.0.2.1/v1/zone/connect")
            .header("Content-Length", 2)
            .body(Bytes::from_static(b"{}"))
            .unwrap()
    }
    async fn fixture(body: Vec<u8>) -> io::Result<Vec<u8>> {
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut one = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut one).await.unwrap();
                request.push(one[0]);
                assert!(request.len() <= 16 * 1024);
            }
            let mut bytes = [0; 2];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"{}");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            if server.write_all(head.as_bytes()).await.is_ok() {
                let _ = server.write_all(&body).await;
            }
            let _ = server.shutdown().await;
        });
        let result = h1(Box::new(client), request()).await;
        peer.await.unwrap();
        result
    }
    #[tokio::test]
    async fn realm_memory_http_control_body_limits_and_cancellation_close_inline_driver() {
        assert_eq!(fixture(b"answer".to_vec()).await.unwrap(), b"answer");
        assert!(fixture(vec![0; BODY_LIMIT + 1]).await.is_err());
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut bytes = Vec::new();
            server.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.starts_with(b"POST "));
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(5), h1(Box::new(client), request()))
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn realm_memory_h2_control_consumes_body_and_releases_its_driver() {
        let (client, server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            let exchange = async {
                let mut receive = request.into_body();
                let upload = receive.data().await.unwrap().unwrap();
                assert_eq!(upload, b"{}".as_slice());
                receive
                    .flow_control()
                    .release_capacity(upload.len())
                    .unwrap();
                let mut send = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                send.send_data(Bytes::from_static(b"answer"), true).unwrap();
            };
            let driver = async { while connection.accept().await.is_some() {} };
            tokio::pin!(exchange, driver);
            let mut submitted = false;
            loop {
                tokio::select! {()=&mut exchange,if !submitted=>submitted=true,()=&mut driver=>break}
            }
        });
        assert_eq!(h2(Box::new(client), request()).await.unwrap(), b"answer");
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
    }
}
