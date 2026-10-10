use super::SecurityClient;
use crate::{
    config::{Config, ProxyProtocol},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    dns::{classify_query, resolution::ResolutionContext, runtime::RuntimeDns},
    outbound::EstablishContext,
    session::{Datagram, DatagramSession, StreamSession},
};
use async_trait::async_trait;
use boring::{
    hpke::HpkeKey,
    pkey::PKey,
    ssl::{NameType, SslAcceptor, SslEchKeys, SslMethod, SslVersion},
    x509::X509,
};
use bytes::Bytes;
use hpke::{Kem, Serializable};
use rand::SeedableRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct DnsPeer {
    list: Vec<u8>,
    calls: AtomicUsize,
    names: Arc<Mutex<Vec<String>>>,
}
struct DnsTransport {
    list: Vec<u8>,
    query: Option<Datagram>,
    names: Arc<Mutex<Vec<String>>>,
}
#[async_trait]
impl Dispatcher for DnsPeer {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(DnsTransport {
            list: self.list.clone(),
            query: None,
            names: self.names.clone(),
        }))
    }
}
#[async_trait]
impl DatagramTransport for DnsTransport {
    async fn send(&mut self, query: Datagram) -> Result<(), DispatchError> {
        let question = classify_query(&query.payload).unwrap().question;
        assert_eq!(question.query_type, 65);
        self.names.lock().unwrap().push(question.name);
        self.query = Some(query);
        Ok(())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let query = self.query.take().unwrap();
        let mut wire = query.payload.to_vec();
        wire[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        wire[6..8].copy_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1]);
        wire.extend_from_slice(&60u32.to_be_bytes());
        let mut data = vec![0, 1, 0, 0, 5];
        data.extend_from_slice(&(self.list.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.list);
        wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
        wire.extend_from_slice(&data);
        Ok(Datagram {
            remote: query.remote,
            payload: Bytes::from(wire),
            sniffed_domain: None,
        })
    }
}

#[tokio::test]
async fn dynamic_ech_dns_configuration_is_consumed_by_real_tls_before_business_data() {
    let mut rng = rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng).unwrap();
    let (sk, pk) = hpke::kem::X25519HkdfSha256::gen_keypair_with_rng(&mut rng);
    let mut content = vec![7, 0, 32, 0, 32];
    content.extend_from_slice(&pk.to_bytes());
    content.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0, 14]);
    content.extend_from_slice(b"public.invalid");
    content.extend_from_slice(&[0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(content.len() as u16).to_be_bytes());
    config.extend_from_slice(&content);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    let cert =
        rcgen::generate_simple_self_signed(vec!["inner.invalid".into(), "public.invalid".into()])
            .unwrap();
    let pin: String = Sha256::digest(cert.cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // This existing safe API's implementation imports X25519 despite its name.
    let key = HpkeKey::dhkem_p256_sha256(&sk.to_bytes()).unwrap();
    let mut keys = SslEchKeys::builder().unwrap();
    keys.add_key(true, &config, key).unwrap();
    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    server
        .set_certificate(&X509::from_der(cert.cert.der()).unwrap())
        .unwrap();
    server
        .set_private_key(&PKey::private_key_from_der(&cert.signing_key.serialize_der()).unwrap())
        .unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.set_ech_keys(&keys.build()).unwrap();
    let server = server.build();
    let peer = Arc::new(DnsPeer {
        list,
        calls: AtomicUsize::new(0),
        names: Arc::new(Mutex::new(Vec::new())),
    });
    let dns_config = Config::parse_yaml(b"mixed-port: 1080\ndns:\n  enable: true\n  use-system-hosts: false\n  nameserver: [203.0.113.53]\n").unwrap();
    let dns = Arc::new(RuntimeDns::new(&dns_config.dns, peer.clone()));
    let resolution = ResolutionContext::runtime(false);
    resolution.bind_runtime(Some(&dns)).unwrap();
    for profile in ["none", "ios"] {
        let config = Config::parse_yaml(&serde_json::to_vec(&json!({"mixed-port":1080,"proxies":[{"name":"edge","type":"vless","server":"inner.invalid","port":443,"uuid":"07070707-0707-0707-0707-070707070707","tls":true,"client-fingerprint":profile,"fingerprint":pin,"ech-opts":{"enable":true,"query-server-name":"query.invalid"}}]})).unwrap()).unwrap();
        let ProxyProtocol::Vless(node) = &config.proxies[0].protocol else {
            panic!()
        };
        let client = SecurityClient::from_proxy(node).unwrap();
        let context = EstablishContext::with_resolution(Duration::from_secs(2), resolution.clone());
        let (io, server_io) = tokio::io::duplex(65536);
        tokio::time::timeout(Duration::from_secs(2), async {
            let consumer = async {
                let mut stream = client
                    .connect_with_context(Box::new(io), &context)
                    .await
                    .unwrap();
                stream.write_all(b"payload").await.unwrap();
                stream.flush().await.unwrap();
                let mut reply = [0; 5];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"reply");
            };
            let receiver = async {
                let mut stream = tokio_boring::accept(&server, server_io).await.unwrap();
                assert!(stream.ssl().ech_accepted());
                assert!(!stream.ssl().session_reused());
                assert_eq!(
                    stream.ssl().servername(NameType::HOST_NAME),
                    Some("inner.invalid")
                );
                let mut payload = [0; 7];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"payload");
                stream.write_all(b"reply").await.unwrap();
                stream.flush().await.unwrap();
            };
            tokio::join!(consumer, receiver);
        })
        .await
        .unwrap();
    }
    assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
    assert_eq!(*peer.names.lock().unwrap(), ["query.invalid"]);
}
