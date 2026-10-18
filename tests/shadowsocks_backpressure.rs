#![cfg(feature = "outbound-shadowsocks")]
//! Connector contract with bounded in-memory IO, not a host protocol server.
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use shadowsocks::{
    config::ServerType,
    context::Context,
    relay::tcprelay::{
        crypto_io::{CryptoStream, CryptoWrite, StreamType},
        proxy_stream::ProxyServerStream,
    },
};
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, ReadBuf};
use vole::{
    config::{ShadowsocksCipher, ShadowsocksOutboundConfig},
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, ShadowsocksOutbound,
        UpstreamPath,
    },
    session::{Destination, InboundKind, StreamSession},
};

struct MemoryUpstream(Mutex<Option<BoxStream>>);

struct RecordedIo {
    inner: tokio::io::DuplexStream,
    written: Arc<AtomicUsize>,
}

impl AsyncRead for RecordedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for RecordedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(written)) = result {
            self.written.fetch_add(written, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[async_trait]
impl OutboundConnector for MemoryUpstream {
    async fn connect_stream(
        &self,
        session: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Ok(ConnectedStream {
            io: self.0.lock().unwrap().take().unwrap(),
            effective_peer: session.destination,
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

#[tokio::test]
async fn empty_writes_after_first_payload_emit_no_extra_encrypted_chunks() {
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let key = vec![7; cipher.key_len()];
        let config = ShadowsocksOutboundConfig {
            address: "fixture.invalid".into(),
            port: 443,
            cipher,
            password: STANDARD.encode(&key),
            plugin: None,
            udp_over_tcp: false,
        };
        let (client, peer) = tokio::io::duplex(4096);
        let written = Arc::new(AtomicUsize::new(0));
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(
                RecordedIo {
                    inner: client,
                    written: written.clone(),
                },
            )))))),
        )
        .unwrap();
        let target = Destination::domain("target.invalid", 80).unwrap();
        let mut stream = outbound
            .connect_stream(
                StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:1234".parse().unwrap(),
                    destination: target,
                    sniffed_domain: None,
                },
                &EstablishContext::default(),
            )
            .await
            .unwrap()
            .io;
        assert!(
            poll_fn(|cx| Poll::Ready(
                Pin::new(&mut stream).poll_read(cx, &mut ReadBuf::new(&mut []))
            ))
            .await
            .is_ready()
        );
        stream.flush().await.unwrap();
        assert_eq!(written.load(Ordering::Relaxed), 0);
        stream.write_all(b"first").await.unwrap();
        stream.flush().await.unwrap();
        let before = written.load(Ordering::Relaxed);
        for _ in 0..2 {
            assert_eq!(stream.write(&[]).await.unwrap(), 0);
            stream.flush().await.unwrap();
            assert_eq!(
                written.load(Ordering::Relaxed),
                before,
                "{cipher:?}: an empty write emitted another encrypted chunk"
            );
        }
        let mut decoder = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            cipher.as_str().parse().unwrap(),
            &key,
        );
        assert_eq!(
            decoder.handshake().await.unwrap(),
            ("target.invalid".to_owned(), 80).into()
        );
        let mut payload = [0; 5];
        decoder.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"first");
    }
}

#[tokio::test]
async fn growing_caller_buffer_after_backpressure_never_loses_plaintext() {
    #[cfg(feature = "interop-test")]
    let _case =
        vole::resources::case_events::Case::new("INTEGRATION-ADAPTER", "growing_caller_buffer");
    for (cipher, initial) in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ]
    .into_iter()
    .flat_map(|cipher| [4096, 32768].map(|size| (cipher, size)))
    {
        let key = vec![7; cipher.key_len()];
        let config = ShadowsocksOutboundConfig {
            address: "fixture.invalid".into(),
            port: 443,
            cipher,
            password: STANDARD.encode(&key),
            plugin: None,
            udp_over_tcp: false,
        };
        let (client, peer) = tokio::io::duplex(4096);
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(client)))))),
        )
        .unwrap();
        let target = Destination::domain("target.invalid", 80).unwrap();
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Socks5,
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: target,
            sniffed_domain: None,
        };
        let mut stream = outbound
            .connect_stream(session, &EstablishContext::default())
            .await
            .unwrap()
            .io;
        let mut payload = vec![0x5a; initial * 2];
        payload[initial..].fill(0xa5);
        // Tokio copy tops up its caller buffer after a pending write. Exercise
        // that public AsyncWrite pattern rather than assuming a fixed retry length.
        let first =
            poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_write(cx, &payload[..initial])))
                .await;
        let accepted = match first {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => 0,
        };
        assert_eq!(accepted, initial.min(vole::limits::SHADOWSOCKS_WRITE_CHUNK));
        let mut decoder = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            cipher.as_str().parse().unwrap(),
            &key,
        );
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            let ((), decoded) = tokio::join!(
                async {
                    stream.write_all(&payload[accepted..]).await.unwrap();
                    stream.shutdown().await.unwrap();
                },
                async {
                    decoder.handshake().await.unwrap();
                    let mut decoded = Vec::new();
                    decoder.read_to_end(&mut decoded).await.unwrap();
                    decoded
                }
            );
            decoded
        })
        .await
        .unwrap();
        assert_eq!(
            received.len(),
            payload.len(),
            "{cipher:?}: acknowledged bytes were lost"
        );
        assert_eq!(received, payload);
    }
}

#[tokio::test]
async fn read_first_flushes_the_official_header_over_a_buffered_upstream() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "INTEGRATION-ADAPTER",
        "server_first_buffered_upstream",
    );
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let key = vec![7; cipher.key_len()];
        let config = ShadowsocksOutboundConfig {
            address: "fixture.invalid".into(),
            port: 443,
            cipher,
            password: STANDARD.encode(&key),
            plugin: None,
            udp_over_tcp: false,
        };
        let (client, peer) = tokio::io::duplex(4096);
        // Buffered carriers may acknowledge the complete SS header before
        // delivering it. A read-first application has no payload to flush it.
        let outbound = ShadowsocksOutbound::new_with_path(
            &config,
            UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(Box::new(
                BufWriter::new(client),
            )))))),
        )
        .unwrap();
        let mut stream = outbound
            .connect_stream(
                StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::Socks5,
                    source: "127.0.0.1:1234".parse().unwrap(),
                    destination: Destination::domain("target.invalid", 80).unwrap(),
                    sniffed_domain: None,
                },
                &EstablishContext::default(),
            )
            .await
            .unwrap()
            .io;
        let mut decoder = ProxyServerStream::from_stream(
            Context::new_shared(ServerType::Server),
            peer,
            cipher.as_str().parse().unwrap(),
            &key,
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                async {
                    let mut greeting = [0; 5];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(&greeting, b"hello");
                },
                async {
                    assert_eq!(
                        decoder.handshake().await.unwrap(),
                        ("target.invalid".to_owned(), 80).into()
                    );
                    decoder.write_all(b"hello").await.unwrap();
                    decoder.flush().await.unwrap();
                }
            );
        })
        .await
        .expect("server-first greeting must arrive without application writes");
    }
}

#[tokio::test]
async fn official_server_rejects_zero_padding_without_payload_deterministically() {
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        for padding_size in [0, 1] {
            let method = cipher.as_str().parse().unwrap();
            let key = vec![7; cipher.key_len()];
            let context = Context::new_shared(ServerType::Local);
            let (client, peer) = tokio::io::duplex(4096);
            let mut writer =
                CryptoStream::from_stream(&context, client, StreamType::Client, method, &key);
            let target: shadowsocks::relay::socks5::Address =
                ("target.invalid".to_owned(), 80).into();
            let mut header = Vec::new();
            target.write_to_buf(&mut header);
            header.extend_from_slice(&u16::to_be_bytes(padding_size));
            header.resize(header.len() + usize::from(padding_size), 0);
            poll_fn(|cx| Pin::new(&mut writer).poll_write_encrypted(cx, &header))
                .await
                .unwrap();
            poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
            let mut decoder = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                peer,
                method,
                &key,
            );
            let result = tokio::time::timeout(Duration::from_secs(2), decoder.handshake())
                .await
                .unwrap();
            if padding_size == 0 {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "no payload in first data chunk, and padding is 0"
                );
            } else {
                assert_eq!(result.unwrap(), ("target.invalid".to_owned(), 80).into());
            }
        }
    }
}
