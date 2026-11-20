//! Genuine obfs/SS under the original authenticated TLS and H1 cache.
use super::*;
use crate::{
    config::ShadowsocksCipher,
    outbound::{MemoryObfsFactory, MemoryObfsReceipt},
};
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;

const CIPHERS: [ShadowsocksCipher; 3] = [
    ShadowsocksCipher::Aes128Gcm,
    ShadowsocksCipher::Aes256Gcm,
    ShadowsocksCipher::Chacha20Poly1305,
];

struct Closed {
    serving: Result<io::Result<()>, String>,
    failures: Vec<String>,
    receipt: MemoryObfsReceipt,
}

async fn close(running: Running, fixture: &Fixture, factory: &MemoryObfsFactory) -> Closed {
    // Keep downstream open until the actual HTTP parent has dropped its cache.
    running.cancellation.cancel();
    let serving = joined(running.serving).await;
    let mut failures = Vec::new();
    if AssertUnwindSafe(factory.shutdown())
        .catch_unwind()
        .await
        .is_err()
    {
        failures.push("actual obfs owner shutdown panicked".into());
    }
    let peers = std::mem::take(
        &mut *fixture
            .origin
            .0
            .peers
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    );
    for peer in peers {
        if let Err(error) = joined(peer).await {
            failures.push(error);
        }
    }
    drop(running.client);
    Closed {
        serving,
        failures,
        receipt: factory.snapshot(),
    }
}

fn closed_witness(closed: &Closed, fixture: &Fixture) {
    assert!(
        closed.serving.is_ok(),
        "HTTP parent did not join: {:?}",
        closed.serving
    );
    assert!(
        closed.failures.is_empty(),
        "peer owners did not join: {:?}",
        closed.failures
    );
    assert_eq!(fixture.origin.count(&fixture.origin.0.live), 0);
    assert_eq!(fixture.stats.snapshot().tcp_current, 0);
    assert_eq!(fixture.stats.snapshot().handshake_current, 0);
    let r = &closed.receipt;
    assert_eq!(r.owners, 1, "{r:?}");
    assert_eq!(r.opens, 1, "{r:?}");
    assert_eq!(r.target_handshakes, 1, "{r:?}");
    assert_eq!(r.cover_requests, 1, "{r:?}");
    assert_eq!(r.cover_responses, 1, "{r:?}");
    assert_eq!(
        r.client_drops, 1,
        "actual SS client IO survived parent join: {r:?}"
    );
    assert_eq!(
        r.peer_drops, 1,
        "actual SS peer IO survived peer join: {r:?}"
    );
    assert_eq!(r.owner_cancelled, 1, "{r:?}");
    assert_eq!(r.owner_closed, 1, "{r:?}");
    assert_eq!(r.owner_wait_returned, 1, "{r:?}");
}

async fn run(cipher: ShadowsocksCipher, tls: bool, reply: Reply) {
    run_with_factory(MemoryObfsFactory::new(cipher, tls, 4096), reply).await;
}

pub(super) async fn run_with_factory(factory: Arc<MemoryObfsFactory>, reply: Reply) {
    run_with_factory_options(factory, reply, "", false).await;
}

#[cfg(target_vendor = "apple")]
pub(super) async fn run_scripted_with_factory(factory: Arc<MemoryObfsFactory>, extra: &str) {
    run_with_factory_options(factory, Reply::Persistent, extra, true).await;
}

fn response_witness(result: io::Result<(String, Vec<u8>)>, scripted: bool) {
    if scripted {
        let (head, _) = result.as_ref().expect("scripted response must complete");
        assert!(
            head.to_ascii_lowercase()
                .contains("x-js-response: native-then-js"),
            "actual response script witness missing"
        );
    }
    let expected: &[u8] = if scripted { b"Changed" } else { b"origin" };
    native_response(result, expected);
}

async fn run_with_factory_options(
    factory: Arc<MemoryObfsFactory>,
    reply: Reply,
    extra: &str,
    scripted: bool,
) {
    let fixture = fixture(Some(b"http/1.1"), reply, scripted, extra);
    *fixture.origin.0.obfs.lock().unwrap() = Some(factory.clone());
    let mut running = start(&fixture);
    let result = AssertUnwindSafe(async {
        timeout(WAIT * 3, async {
            match reply {
                Reply::Persistent | Reply::FailSecond => {
                    let first = fixed_post(&mut running, "/one", b"original").await;
                    response_witness(first, scripted);
                    let second = fixed_post(&mut running, "/two", b"original").await;
                    if matches!(reply, Reply::FailSecond) {
                        if let Ok((head, body)) = second {
                            let response = framing::ResponseHead::parse(head.as_bytes())?;
                            assert!(matches!(response.status, 400 | 502));
                            assert!(body.is_empty());
                        }
                    } else {
                        response_witness(second, scripted);
                        // Stop a genuinely idle carrier while downstream stays open.
                        factory.begin_shutdown();
                    }
                }
                Reply::WaitPost | Reply::EarlyPost => {
                    running.client.get_mut().write_all(
                    b"POST /partial HTTP/1.1\r\nHost: a.test\r\nContent-Length: 65536\r\n\r\nx"
                ).await?;
                    if matches!(reply, Reply::WaitPost) {
                        timeout(WAIT, fixture.origin.0.partial.notified())
                            .await
                            .map_err(|_| {
                                io::Error::new(io::ErrorKind::TimedOut, "actual partial upload")
                            })?;
                        factory.begin_shutdown();
                    } else {
                        let head = framing::read_head(&mut running.client, 32768).await?;
                        let response = framing::ResponseHead::parse(&head)?;
                        let mut body = Vec::new();
                        framing::transfer_body(
                            &mut running.client,
                            &mut body,
                            response.body("POST"),
                            WAIT,
                            response.trailer_blocklist(),
                            false,
                        )
                        .await?;
                        let mut tail = [0; 1];
                        assert_eq!(running.client.read(&mut tail).await?, 0);
                        assert_eq!(body, b"origin");
                        assert!(
                            String::from_utf8(head)
                                .unwrap()
                                .to_ascii_lowercase()
                                .contains("connection: close")
                        );
                    }
                }
                _ => unreachable!("R4 uses the original completed/partial POST modes"),
            }
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "whole SS/H1 memory exchange"))?
    })
    .catch_unwind()
    .await;
    // Handshake/content/assertion errors and panics all reach the same cleanup.
    let closed = close(running, &fixture, &factory).await;
    closed_witness(&closed, &fixture);
    match result {
        Ok(result) => result.unwrap(),
        Err(panic) => std::panic::resume_unwind(panic),
    }
    assert_eq!(fixture.origin.count(&fixture.origin.0.opens), 1);
    assert_eq!(fixture.origin.count(&fixture.origin.0.accepts), 1);
    assert_eq!(
        *fixture.origin.0.sni.lock().unwrap(),
        vec!["a.test".to_owned()]
    );
    assert_eq!(
        *fixture.origin.0.negotiated.lock().unwrap(),
        vec![Some(b"http/1.1".to_vec())]
    );
    let expected_heads = if matches!(reply, Reply::Persistent | Reply::FailSecond) {
        2
    } else {
        1
    };
    assert_eq!(
        fixture.origin.count(&fixture.origin.0.prepares),
        expected_heads
    );
    let heads = fixture.origin.0.heads.lock().unwrap();
    assert_eq!(heads.len(), expected_heads);
    assert!(
        heads
            .iter()
            .all(|head| head.to_ascii_lowercase().contains("connection: keep-alive"))
    );
    if scripted {
        assert!(
            heads.iter().all(|head| {
                head.to_ascii_lowercase()
                    .contains("x-js-request: transformed")
            }),
            "actual request script witness missing at origin"
        );
    }
    let uploads = fixture.origin.0.uploads.lock().unwrap();
    let complete_body: &[u8] = if scripted {
        b"transformed"
    } else {
        b"original"
    };
    let expected = match reply {
        Reply::Persistent => vec![complete_body.to_vec(), complete_body.to_vec()],
        Reply::FailSecond => vec![complete_body.to_vec()],
        _ => vec![b"x".to_vec()],
    };
    assert_eq!(*uploads, expected);
    match reply {
        Reply::FailSecond => assert!(
            closed.serving.unwrap().is_err(),
            "submitted second POST did not reach its fault"
        ),
        Reply::WaitPost => {
            if let Err(error) = closed.serving.unwrap() {
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted,
                    "partial upload must finish normally or observe the explicit node cancellation"
                );
            }
        }
        _ => closed.serving.unwrap().expect("normal HTTP parent failed"),
    }
}

#[tokio::test]
async fn ss_obfs_https_h1_two_posts_share_one_authenticated_carrier() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, Reply::Persistent).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h1_submitted_second_post_is_not_replayed() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, Reply::FailSecond).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h1_active_stop_drops_partial_upload() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, Reply::WaitPost).await;
        }
    }
}
#[tokio::test]
async fn ss_obfs_https_h1_early_final_retires_partial_upload() {
    for cipher in CIPHERS {
        for tls in [false, true] {
            run(cipher, tls, Reply::EarlyPost).await;
        }
    }
}
