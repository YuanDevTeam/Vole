//! VLESS Encryption over caller-owned IO. No sockets or background tasks.
mod cache;
mod config;
mod crypto;
mod handshake;
mod header_xor;
mod records;
pub(crate) use handshake::Handshake;
use std::{io, sync::Arc};

pub struct Client {
    settings: config::Settings,
    cache: Arc<cache::Cache>,
    suite: crypto::Suite,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionClient")
            .field("key_count", &self.settings.keys.len())
            .finish_non_exhaustive()
    }
}

impl Client {
    pub fn parse(value: &str) -> io::Result<Self> {
        Ok(Self {
            settings: config::Settings::parse(value)?,
            cache: Arc::new(cache::Cache::default()),
            suite: crypto::Suite::for_cpu(),
        })
    }

    #[cfg(any(test, feature = "interop-test"))]
    pub async fn connect(
        &self,
        raw: crate::dispatch::BoxStream,
        deadline: tokio::time::Instant,
    ) -> io::Result<crate::dispatch::BoxStream> {
        let flight = self.start()?;
        flight.finish(raw, false, deadline).await
    }

    pub(crate) fn start(&self) -> io::Result<Handshake> {
        Handshake::start(&self.settings, self.cache.clone(), self.suite)
    }

    #[cfg(feature = "inbound-http")]
    pub(crate) fn permits_http_tcp_reuse(&self) -> bool {
        !self.cache.cancellation.is_cancelled()
            && matches!(
                self.settings.appearance,
                config::Appearance::Native
                    | config::Appearance::XorPublic
                    | config::Appearance::Random
            )
    }

    /// Exercise the non-AES hardware branch against an independent peer.
    /// Never compiled into production, and never a public YAML cipher option.
    #[cfg(feature = "interop-test")]
    #[doc(hidden)]
    pub fn with_chacha20_poly1305_for_interop(mut self) -> Self {
        self.suite = crypto::Suite::ChaCha;
        self
    }

    /// Clears node-local tickets and cancels owned connections. Never reopens.
    pub fn close(&self) {
        self.cache.close();
    }
}

fn invalid_config() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid VLESS Encryption configuration",
    )
}

pub(crate) fn validate_config(value: &str) -> io::Result<()> {
    config::Settings::parse(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn accepts_the_native_one_rtt_key_configuration() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        assert!(Client::parse(&format!("mlkem768x25519plus.native.1rtt.{key}")).is_ok());
    }
    #[test]
    fn accepts_all_six_modes_and_ordered_keys_with_fragment_padding() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        for style in ["native", "xorpub", "random"] {
            for mode in ["1rtt", "0rtt"] {
                let config = format!(
                    "mlkem768x25519plus.{style}.{mode}.{key}.100-35-35.100-0-1.50-1-5.{key}"
                );
                assert!(Client::parse(&config).is_ok(), "{style}/{mode}");
            }
        }
    }

    #[test]
    fn rejects_malformed_or_unbounded_settings_without_reflecting_input() {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        let prefix = format!("mlkem768x25519plus.native.1rtt.{key}");
        for value in [
            "secret-invalid-profile".to_owned(),
            format!("{prefix}.100-34-35"),
            format!("{prefix}.99-35-35"),
            format!("{prefix}.100-65554-65554"),
            format!("{prefix}.100-32777-32777.100-0-0.100-32777-32777"),
            format!("{prefix}.100-35-35.100--1-0"),
            format!("{prefix}.100-35-35-1"),
            format!("{prefix}.100-35-35.100-0-4294967296"),
            format!(
                "mlkem768x25519plus.native.1rtt.{}",
                vec![key.as_str(); 17].join(".")
            ),
            format!("{prefix}.{}", vec!["100-35-35"; 129].join(".")),
            "x".repeat(65537),
            "mlkem768x25519plus.native.1rtt.100-35-35".to_owned(),
        ] {
            let error = Client::parse(&value).unwrap_err();
            assert_eq!(error.to_string(), "invalid VLESS Encryption configuration");
        }
        assert!(Client::parse(&format!("{prefix}.100-65553-65553")).is_ok());
        assert!(
            Client::parse(&format!(
                "mlkem768x25519plus.native.1rtt.{}",
                vec![key.as_str(); 16].join(".")
            ))
            .is_ok()
        );
        assert!(!format!("{:?}", Client::parse(&prefix).unwrap()).contains(&key));
    }

    #[tokio::test]
    async fn close_cancels_an_inflight_handshake_without_waiting_for_the_peer() {
        use std::{
            pin::Pin,
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
            task::{Context, Poll},
        };
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        struct Blackhole(Arc<AtomicBool>, Arc<AtomicUsize>);
        impl Drop for Blackhole {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl AsyncRead for Blackhole {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for Blackhole {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                input: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.1.fetch_add(input.len(), Ordering::SeqCst);
                Poll::Ready(Ok(input.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]);
        let client =
            Client::parse(&format!("mlkem768x25519plus.native.0rtt.{key}.100-35-35")).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let bytes = Arc::new(AtomicUsize::new(0));
        let raw = Box::new(Blackhole(dropped.clone(), bytes.clone()));
        let mut connect = std::pin::pin!(client.connect(
            raw,
            tokio::time::Instant::now() + std::time::Duration::from_secs(30)
        ));
        assert!(
            connect
                .as_mut()
                .poll(&mut Context::from_waker(std::task::Waker::noop()))
                .is_pending()
        );
        assert_eq!(bytes.load(Ordering::SeqCst), 1333);
        client.close();
        let error = tokio::time::timeout(std::time::Duration::from_millis(100), connect)
            .await
            .unwrap()
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(bytes.load(Ordering::SeqCst), 1333);
    }
}
