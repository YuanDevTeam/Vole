//! Public ShadowTLS stream and cancellation behavior over bounded memory IO.
//! These are local fault/IO checks, not replacements for official container peers.
#![cfg(feature = "shadow-tls-v3")]

use std::{collections::HashSet, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vole::{
    config::{ClientFingerprint, ShadowTlsConfig},
    security::{SecurityContext, ShadowTlsClient},
};

const PASSWORD: &str = " synthetic-memory-shadow-password ";

fn options(profile: Option<ClientFingerprint>) -> ShadowTlsConfig {
    ShadowTlsConfig {
        server_name: "cover.invalid".into(),
        password: PASSWORD.into(),
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        required_alpn: None,
        identity: None,
        certificate: Default::default(),
        client_fingerprint: profile,
    }
}

#[tokio::test]
async fn cancelled_shadowtls_handshakes_release_io_and_never_reuse_authenticated_hellos() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("SHADOWTLS-STREAM", "cancelled_hello");
    use ClientFingerprint::*;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut seen = HashSet::new();
        for profile in [
            None,
            Some(Chrome133),
            Some(Firefox120),
            Some(Safari16),
            Some(Ios14),
        ] {
            let client = ShadowTlsClient::new(&SecurityContext::new(), &options(profile)).unwrap();
            for _ in 0..4 {
                let (io, mut peer) = tokio::io::duplex(73);
                let client = client.clone();
                let task = tokio::spawn(async move { client.connect(Box::new(io)).await });
                let mut header = [0; 5];
                peer.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let size = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(size <= 16_384);
                let mut hello = vec![0; size];
                peer.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1);
                assert_eq!(hello[38], 32);
                let session_id: [u8; 32] = hello[39..71].try_into().unwrap();
                hello[67..71].fill(0);
                assert_eq!(
                    &session_id[28..],
                    &boring::hash::hmac_sha1(PASSWORD.as_bytes(), &hello).unwrap()[..4]
                );
                assert!(seen.insert(session_id));
                task.abort();
                assert!(task.await.is_err_and(|error| error.is_cancelled()));
                assert_eq!(peer.read(&mut header).await.unwrap(), 0);
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_or_oversized_shadowtls_handshake_records_never_create_a_business_stream() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new("SHADOWTLS-STREAM", "invalid_record");
    tokio::time::timeout(Duration::from_secs(10), async {
        for record in [
            vec![],
            vec![22],
            vec![22, 3, 3, 0],
            vec![22, 3, 3, 0, 7, 2, 0],
            vec![22, 3, 3, 0, 0],
            vec![22, 3, 3, 0xff, 0xff],
            vec![22, 2, 0, 0, 1, 0],
            vec![23, 3, 3, 0, 4, 0, 0, 0, 0],
        ] {
            let client = ShadowTlsClient::new(&SecurityContext::new(), &options(None)).unwrap();
            let (io, mut peer) = tokio::io::duplex(65_536);
            let task = tokio::spawn(async move { client.connect(Box::new(io)).await });
            let mut header = [0; 5];
            peer.read_exact(&mut header).await.unwrap();
            let mut hello = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            peer.read_exact(&mut hello).await.unwrap();
            for byte in record {
                if peer.write_all(&[byte]).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            let _ = peer.shutdown().await;
            assert!(task.await.unwrap().is_err());
        }
    })
    .await
    .unwrap();
}
