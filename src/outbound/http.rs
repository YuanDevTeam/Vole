//! HTTP/1.1 CONNECT over a shared plain or TLS upstream stream.
use crate::{
    config::HttpOutboundConfig,
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        server_destination,
    },
    security::{SecurityContext, StandardTlsClient, TlsClientIdentity, TlsClientOptions},
    session::{Destination, StreamSession},
};
use async_trait::async_trait;
use std::{collections::BTreeMap, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub struct HttpOutbound {
    server: Destination,
    upstream: UpstreamPath,
    tls: Option<StandardTlsClient>,
    headers: BTreeMap<String, String>,
    authorization: Option<String>,
}
impl HttpOutbound {
    pub(crate) fn with_shared_security(
        config: &HttpOutboundConfig,
        upstream: UpstreamPath,
        security: &SecurityContext,
        sessions: usize,
        buffer_limit: usize,
    ) -> io::Result<Self> {
        let tls = config
            .tls
            .as_ref()
            .map(|config| {
                StandardTlsClient::with_options(
                    security,
                    &config.server_name,
                    TlsClientOptions {
                        alpn: config.alpn.clone(),
                        certificate: config.certificate.clone(),
                        identity: config
                            .identity
                            .as_ref()
                            .map(|identity| TlsClientIdentity::from_config(identity, security))
                            .transpose()?,
                        ..Default::default()
                    },
                    sessions,
                    buffer_limit,
                )
            })
            .transpose()?;
        Ok(Self {
            server: server_destination(&config.address, config.port)?,
            upstream,
            tls,
            headers: config.headers.clone(),
            authorization: config
                .auth
                .as_ref()
                .map(|auth| auth.authorization_header_value()),
        })
    }
}
async fn handshake(
    mut stream: BoxStream,
    target: &Destination,
    headers: &BTreeMap<String, String>,
    authorization: Option<&str>,
) -> io::Result<BoxStream> {
    let authority = match target {
        Destination::Ip(address) => address.to_string(),
        Destination::Domain { host, port } => format!("{host}:{port}"),
    };
    let mut fields = BTreeMap::from([
        ("host".to_owned(), authority.clone()),
        ("proxy-connection".into(), "Keep-Alive".into()),
        (
            "user-agent".into(),
            concat!("Vole/", env!("CARGO_PKG_VERSION")).into(),
        ),
    ]);
    for (name, value) in headers {
        fields.insert(name.to_ascii_lowercase(), value.clone());
    }
    if let Some(value) = authorization {
        fields.insert("proxy-authorization".into(), value.into());
    }
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\n");
    for (name, value) in fields {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut total = 0;
    loop {
        let mut head = Vec::new();
        // Exact reads preserve application bytes coalesced with the response.
        while !head.ends_with(b"\r\n\r\n") {
            if total >= 32 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP CONNECT response too large",
                ));
            }
            head.push(stream.read_u8().await?);
            total += 1;
        }
        let status = crate::resource::probe::parse_status(&head)?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        if status != 200 {
            // A remote rejection is a failed proxy connection. PermissionDenied
            // becomes NotAllowed, which group health excludes as a local policy.
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "HTTP CONNECT was rejected",
            ));
        }
        return Ok(stream);
    }
}
#[async_trait]
impl OutboundConnector for HttpOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        if tokio::time::Instant::now() >= context.deadline() {
            return Err(DispatchError::TimedOut);
        }
        let target = session.destination.clone();
        let raw = self
            .upstream
            .connect_server(session, &self.server, context)
            .await?;
        let io = match &self.tls {
            Some(tls) => {
                context
                    .run_io("HTTP proxy TLS", tls.connect(raw.io))
                    .await?
            }
            None => raw.io,
        };
        let io = context
            .run_io(
                "HTTP CONNECT",
                handshake(io, &target, &self.headers, self.authorization.as_deref()),
            )
            .await?;
        Ok(ConnectedStream {
            io,
            effective_peer: target,
        })
    }
    async fn open_datagram(
        &self,
        _: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn stalled_connect_obeys_deadline_and_releases_stream() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let context = EstablishContext::with_timeout(std::time::Duration::from_secs(1));
        let result = context
            .run_io(
                "HTTP CONNECT",
                handshake(
                    Box::new(client),
                    &Destination::Ip("192.0.2.1:443".parse().unwrap()),
                    &BTreeMap::new(),
                    None,
                ),
            )
            .await;
        assert!(matches!(result, Err(DispatchError::TimedOut)));
        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert!(request.ends_with(b"\r\n\r\n"));
    }
    #[tokio::test]
    async fn connect_auth_and_prebuffer_are_preserved() {
        for status in [200, 407, 503] {
            let (client, mut peer) = tokio::io::duplex(4096);
            let remote = tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(peer.read_u8().await.unwrap());
                }
                let text = String::from_utf8(request).unwrap();
                assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
                assert!(text.contains("proxy-authorization: Basic dTpw\r\n"));
                assert!(text.contains("x-proxy: custom\r\n"));
                peer.write_all(format!("HTTP/1.1 {status} Status\r\n\r\nfirst-byte").as_bytes())
                    .await
                    .unwrap();
            });
            let result = handshake(
                Box::new(client),
                &Destination::Domain {
                    host: "example.com".into(),
                    port: 443,
                },
                &BTreeMap::from([("X-Proxy".into(), "custom".into())]),
                Some("Basic dTpw"),
            )
            .await;
            if status == 200 {
                let mut bytes = [0; 10];
                result.unwrap().read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"first-byte");
            } else {
                assert_eq!(
                    result.err().unwrap().kind(),
                    io::ErrorKind::ConnectionRefused
                );
            }
            remote.await.unwrap();
        }
    }
}
