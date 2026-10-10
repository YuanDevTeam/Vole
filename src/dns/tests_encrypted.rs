use super::*;
use crate::dispatch::DatagramTransport;
use async_trait::async_trait;

struct Peer {
    tls: Arc<rustls::ServerConfig>,
    https: bool,
    opens: AtomicUsize,
    tasks: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
}
#[async_trait]
impl Dispatcher for Peer {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        self.opens.fetch_add(1, Ordering::Relaxed);
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let tls = self.tls.clone();
        let https = self.https;
        self.tasks.lock().unwrap().push(tokio::spawn(async move {
            let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(tls).accept(peer).await else { return; };
            for _ in 0..2 {
                let length = if https {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = stream.read_u8().await else { return; };
                        head.push(byte);
                        assert!(head.len() < 4096);
                    }
                    let head = String::from_utf8(head).unwrap();
                    assert!(head.starts_with("POST /dns-query HTTP/1.1\r\n"));
                    head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse::<usize>().unwrap()
                } else { let Ok(length) = stream.read_u16().await else { return; }; length as usize };
                let mut query = vec![0; length];
                stream.read_exact(&mut query).await.unwrap();
                let question = classify_query(&query).unwrap();
                let response = super::super::synthesize_empty_response(&question, 0).unwrap();
                if https {
                    // Chunked replies exercise persistence without detached HTTP drivers.
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", response.len()).as_bytes()).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                    stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
                } else {
                    stream.write_u16(response.len() as u16).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                }
                stream.flush().await.unwrap();
            }
        }));
        Ok(Box::new(client))
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
impl Peer {
    async fn join(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    }
}

#[tokio::test]
async fn encrypted_dns_authenticates_and_reuses_tls_and_https_streams() {
    let certificate = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    for upstream in ["tls://dns.example", "https://dns.example/dns-query"] {
        let config = crate::config::Config::parse_yaml(format!("mixed-port: 1080\nhosts: {{dns.example: 192.0.2.1}}\ndns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{upstream}']\n").as_bytes()).unwrap();
        let peer = Arc::new(Peer {
            tls: Arc::new(server.clone()),
            https: upstream.starts_with("https"),
            opens: AtomicUsize::new(0),
            tasks: StdMutex::new(Vec::new()),
        });
        let mut dns = RuntimeDns::new(&config.dns, peer.clone());
        Arc::get_mut(&mut dns.tcp_pool).unwrap().security =
            crate::security::SecurityContext::with_tls_roots(roots.clone());
        assert!(dns.resolve("first.example").await.unwrap().is_empty());
        assert!(dns.resolve("second.example").await.unwrap().is_empty());
        assert_eq!(peer.opens.load(Ordering::Relaxed), 1);
        assert_eq!(dns.tcp_pool.snapshot().reuse_hits, 1);
        peer.join().await;
        // The same peer's untrusted certificate cannot reach a DNS exchange.
        let untrusted = RuntimeDns::new(&config.dns, peer.clone());
        assert!(untrusted.resolve("untrusted.example").await.is_err());
        peer.join().await;
    }
}

#[tokio::test]
async fn upstream_tls_options_verify_names_skip_roots_and_disable_only_dot_reuse() {
    let certificate = rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(certificate.signing_key.serialize_der().into()),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    for (upstream, trusted, succeeds, opens) in [
        (
            "tls://192.0.2.1#name-cert-verify=dns.example&disable-reuse=true",
            true,
            true,
            2,
        ),
        (
            "https://192.0.2.1/dns-query#name-cert-verify=dns.example&disable-reuse=true",
            true,
            true,
            1,
        ),
        ("tls://192.0.2.1#skip-cert-verify=true", false, true, 1),
        (
            "tls://192.0.2.1#name-cert-verify=wrong.example&skip-cert-verify=true",
            true,
            false,
            2,
        ),
    ] {
        let config = crate::config::Config::parse_yaml(format!("mixed-port: 1080\ndns:\n  enable: true\n  use-system-hosts: false\n  nameserver: ['{upstream}']\n").as_bytes()).unwrap();
        let peer = Arc::new(Peer {
            tls: Arc::new(server.clone()),
            https: upstream.starts_with("https"),
            opens: AtomicUsize::new(0),
            tasks: StdMutex::new(Vec::new()),
        });
        let mut dns = RuntimeDns::new(&config.dns, peer.clone());
        if trusted {
            Arc::get_mut(&mut dns.tcp_pool).unwrap().security =
                crate::security::SecurityContext::with_tls_roots(roots.clone());
        }
        for name in ["first.example", "second.example"] {
            assert_eq!(dns.resolve(name).await.is_ok(), succeeds, "{upstream}");
        }
        assert_eq!(peer.opens.load(Ordering::Relaxed), opens, "{upstream}");
        assert_eq!(
            dns.tcp_pool.snapshot().current_idle,
            usize::from(succeeds && opens == 1),
            "{upstream}"
        );
        peer.join().await;
    }
}
