//! Actual plain VMess HTTP cover beneath the unchanged TLS/H2 POST parent.
//! Memory peer model only; no official server, full downstream MITM or performance claim.
use super::*;
use crate::outbound::{MemoryVmessHttpCoverFactory, vmess::BodyCipher};

const CIPHERS: [BodyCipher; 4] = [
    BodyCipher::Auto,
    BodyCipher::None,
    BodyCipher::Aes128Gcm,
    BodyCipher::Chacha20Poly1305,
];

async fn run(cipher: BodyCipher, mode: PostReply, extra: &str, scripted: bool) {
    let factory = MemoryVmessHttpCoverFactory::new(cipher, 4096);
    let weak = Arc::downgrade(&factory);
    let (context, origin) = fixture_post(true, extra, mode);
    *origin.0.vmess_http_cover.lock().unwrap() = Some(factory.clone());
    // The original helper retains its upload/response/no-replay/early-final
    // checks and really joins every parent, driver and peer on all exits.
    let result = AssertUnwindSafe(exercise_post_fixture(
        mode,
        scripted,
        false,
        context,
        origin.clone(),
    ))
    .catch_unwind()
    .await;
    let r = factory.snapshot();
    let opens = origin.0.opens.load(Ordering::Acquire);
    let accepts = origin.0.accepts.load(Ordering::Acquire);
    let sni = origin
        .0
        .sni
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let live = origin.0.live.load(Ordering::Acquire);
    drop(origin);
    drop(factory);
    // No fixture-held Arc or guard is permitted to conceal the real release.
    assert!(
        weak.upgrade().is_none(),
        "HTTP parent retained the actual VMess factory"
    );
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
    assert_eq!(r.owner_tasks_empty, expected, "{r:?}");
    assert_eq!(r.auth_failures, 0, "{r:?}");
    assert_eq!(opens, expected);
    assert_eq!(accepts, expected);
    assert_eq!(sni, vec!["a.test".to_owned(); expected]);
    assert_eq!(live, 0);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn vmess_http_cover_https_h2_two_posts_share_one_authenticated_carrier() {
    for cipher in CIPHERS {
        run(cipher, PostReply::Complete, "", false).await;
    }
}
#[tokio::test]
async fn vmess_http_cover_https_h2_submitted_second_post_is_not_replayed() {
    for cipher in CIPHERS {
        run(cipher, PostReply::FailSecond, "", false).await;
    }
}
#[tokio::test]
async fn vmess_http_cover_https_h2_active_stop_drops_partial_upload() {
    for cipher in CIPHERS {
        run(cipher, PostReply::Wait, "", false).await;
    }
}
#[tokio::test]
async fn vmess_http_cover_https_h2_early_final_retires_uncertain_upload() {
    for cipher in CIPHERS {
        run(cipher, PostReply::Early, "", false).await;
    }
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn vmess_http_cover_https_h2_native_then_js_reuses_one_authenticated_carrier() {
    const SCRIPTS: &str = r#"      - response:
          headers:
            - {set: {x-proof: before-js}}
      - name: actual-request-body
        request:
          js:
            body: text
            source: |
              function rewrite(input) {
                let found = false;
                for (let i = 0; i < input.request.headers.length; i++) {
                  let header = input.request.headers[i];
                  if (header.name === "x-request" && header.value === "native") found = true;
                }
                if (!found || input.body.data !== "original") return {type:"abort"};
                return {type:"modify",body:{kind:"text",data:"transformed"}};
              }
      - name: actual-response-proof
        response:
          js:
            body: text
            source: |
              function rewrite(input) {
                let found = false;
                for (let i = 0; i < input.response.headers.length; i++) {
                  let header = input.response.headers[i];
                  if (header.name === "x-proof" && header.value === "before-js") found = true;
                }
                if (!found || input.body.data !== "from_origin") return {type:"abort"};
                return {type:"modify",headers:[{op:"set",name:"x-proof",values:["native"]}],body:{kind:"text",data:input.body.data}};
              }
"#;
    for cipher in CIPHERS {
        run(cipher, PostReply::Complete, SCRIPTS, true).await;
    }
}
