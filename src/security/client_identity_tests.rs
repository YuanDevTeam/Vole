//! Shared identity dispatch and cancellation on memory IO, without any peer socket.
use super::{SecurityClient, SecurityContext};
#[cfg(feature = "shadow-tls-v3")]
use crate::config::ShadowTlsConfig;
use crate::config::{JlsConfig, RealityConfig, SecurityConfig, TlsConfig};
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn shared_identity_handshakes_cancel_without_retaining_io_or_reusing_hellos() {
    let mut tls = TlsConfig::xhttp("cover.invalid".into());
    tls.alpn.clear();
    tls.required_alpn = None;
    let identities = vec![
        SecurityConfig::Jls(JlsConfig {
            tls,
            username: "synthetic-shared-user".into(),
            password: "synthetic-shared-password".into(),
        }),
        SecurityConfig::Reality(RealityConfig {
            client_fingerprint: None,
            support_x25519mlkem768: false,
            server_name: "cover.invalid".into(),
            public_key: [7; 32],
            short_id: vec![1, 2],
            alpn: Vec::new(),
        }),
    ];
    let identities = identities.into_iter();
    #[cfg(feature = "shadow-tls-v3")]
    let identities = identities.chain(std::iter::once(SecurityConfig::ShadowTls(
        ShadowTlsConfig {
            server_name: "cover.invalid".into(),
            password: "synthetic-shared-cover-password".into(),
            alpn: Vec::new(),
            required_alpn: None,
            certificate: Default::default(),
            identity: None,
            client_fingerprint: None,
        },
    )));
    let context = SecurityContext::new();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        for identity in identities {
            let client =
                SecurityClient::from_security_with_context(&identity, &context, 0, 8192).unwrap();
            let mut previous = None;
            for _ in 0..2 {
                let (raw, mut peer) = tokio::io::duplex(73);
                let client = client.clone();
                let task = tokio::spawn(async move { client.connect(Box::new(raw)).await });
                let mut header = [0; 5];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!((71..=16_384).contains(&length));
                let mut hello = vec![0; length];
                peer.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1);
                assert_eq!(hello[38], 32);
                let session_id: [u8; 32] = hello[39..71].try_into().unwrap();
                assert_ne!(previous.replace(session_id), Some(session_id));
                if let SecurityConfig::ShadowTls(config) = &identity {
                    hello[67..71].fill(0);
                    let tag = boring::hash::hmac_sha1(config.password.as_bytes(), &hello).unwrap();
                    assert_eq!(&session_id[28..], &tag[..4]);
                }
                task.abort();
                assert!(task.await.is_err_and(|error| error.is_cancelled()));
                assert_eq!(peer.read(&mut header).await.unwrap(), 0);
            }
        }
    })
    .await
    .unwrap();
}
