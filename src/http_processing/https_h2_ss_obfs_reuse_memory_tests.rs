//! Actual SS/obfs beneath the existing authenticated H2 POST/cache fixture.
use super::*;
use crate::{config::ShadowsocksCipher, outbound::MemoryObfsFactory};

const CIPHERS: [ShadowsocksCipher; 3] = [
    ShadowsocksCipher::Aes128Gcm,
    ShadowsocksCipher::Aes256Gcm,
    ShadowsocksCipher::Chacha20Poly1305,
];

async fn run(cipher: ShadowsocksCipher, tls: bool, mode: PostReply) {
    run_with_factory(MemoryObfsFactory::new(cipher, tls, 4096), mode).await;
}

pub(super) async fn run_with_factory(factory: Arc<MemoryObfsFactory>, mode: PostReply) {
    run_with_factory_options(factory, mode, "", false).await;
}

#[cfg(target_vendor = "apple")]
pub(super) async fn run_scripted_with_factory(factory: Arc<MemoryObfsFactory>, extra: &str) {
    run_with_factory_options(factory, PostReply::Complete, extra, true).await;
}

async fn run_with_factory_options(
    factory: Arc<MemoryObfsFactory>,
    mode: PostReply,
    extra: &str,
    scripted: bool,
) {
    let (context, origin) = fixture_post(true, extra, mode);
    *origin.0.obfs.lock().unwrap() = Some(factory.clone());
    // The original helper drives real complete/partial POSTs and cleanup on
    // content error, timeout or panic. It does not replace the H2 session/cache.
    exercise_post_fixture(mode, scripted, false, context, origin.clone()).await;
    let r = factory.snapshot();
    // The original early-final helper retires the uncertain carrier and then
    // verifies a new GET on a second authenticated connection.
    let expected = if matches!(mode, PostReply::Early) {
        2
    } else {
        1
    };
    assert_eq!(r.owners, expected, "{r:?}");
    assert_eq!(r.opens, expected, "{r:?}");
    assert_eq!(r.target_handshakes, expected, "{r:?}");
    assert_eq!(r.cover_requests, expected, "{r:?}");
    assert_eq!(r.cover_responses, expected, "{r:?}");
    assert_eq!(
        r.client_drops, expected,
        "actual client IO survived H2 parent join: {r:?}"
    );
    assert_eq!(
        r.peer_drops, expected,
        "actual peer IO survived TLS peer join: {r:?}"
    );
    assert_eq!(r.owner_cancelled, expected, "{r:?}");
    assert_eq!(r.owner_closed, expected, "{r:?}");
    assert_eq!(r.owner_wait_returned, expected, "{r:?}");
    assert_eq!(origin.0.opens.load(Ordering::Acquire), expected);
    assert_eq!(origin.0.accepts.load(Ordering::Acquire), expected);
    assert_eq!(
        *origin.0.sni.lock().unwrap(),
        vec!["a.test".to_owned(); expected]
    );
    assert_eq!(origin.0.live.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn ss_obfs_https_h2_two_posts_share_one_authenticated_carrier() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, PostReply::Complete).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h2_submitted_second_post_is_not_replayed() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, PostReply::FailSecond).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h2_active_stop_drops_partial_upload() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, PostReply::Wait).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h2_early_final_retires_partial_upload() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, PostReply::Early).await;
        }
    }
}
