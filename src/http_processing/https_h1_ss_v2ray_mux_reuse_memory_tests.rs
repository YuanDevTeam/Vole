//! Real SS2022/plain WS mux beneath the original authenticated TLS/HTTP cache.
//! Pure memory only; no official Go server, sockets or throughput claims.
use super::*;
use crate::{config::ShadowsocksCipher, outbound::MemoryObfsFactory};
async fn exercise(mode: Reply) {
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let factory = MemoryObfsFactory::new_v2ray_mux(cipher, 4096);
        let weak = Arc::downgrade(&factory);
        super::ss_obfs_reuse::run_with_factory(factory.clone(), mode).await;
        let receipt = factory.snapshot();
        assert!(receipt.owners > 0, "actual mux factory was not entered");
        assert_eq!(
            receipt.mux_new, receipt.owners,
            "one New per actual WS/SS carrier: {receipt:?}"
        );
        drop(factory);
        assert!(
            weak.upgrade().is_none(),
            "HTTP parent retained the carrier factory"
        );
    }
}

#[tokio::test]
async fn ss_v2ray_mux_https_h1_two_posts_share_one_authenticated_carrier() {
    exercise(Reply::Persistent).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h1_submitted_second_post_is_not_replayed() {
    exercise(Reply::FailSecond).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h1_active_stop_drops_partial_upload() {
    exercise(Reply::WaitPost).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h1_early_final_retires_uncertain_upload() {
    exercise(Reply::EarlyPost).await;
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn ss_v2ray_mux_https_h1_native_then_js_reuses_one_authenticated_carrier() {
    // Native sets the request header and response body first. Each script
    // checks that stage; a failure/rollback leaves bytes or headers that fail
    // the existing HTTP and independent origin-upload witnesses.
    const SCRIPTS: &str = r#"      - match: {url-regex: '^https://a\.test/'}
        request:
          headers:
            - {set: {x-native-request: before-js}}
      - match: {url-regex: '^https://a\.test/'}
        name: actual-request-body
        request:
          js:
            body: text
            source: |
              function rewrite(input) {
                let found = false;
                for (let i = 0; i < input.request.headers.length; i++) {
                  let header = input.request.headers[i];
                  if (header.name === "x-native-request" && header.value === "before-js") found = true;
                }
                if (!found || input.body.data !== "original") return {type:"abort"};
                return {type:"modify",headers:[{op:"set",name:"x-js-request",values:["transformed"]}],body:{kind:"text",data:"transformed"}};
              }
      - match: {url-regex: '^https://a\.test/'}
        name: actual-response-body
        response:
          js:
            body: text
            source: |
              function rewrite(input) {
                let found = false;
                for (let i = 0; i < input.response.headers.length; i++) {
                  let header = input.response.headers[i];
                  if (header.name === "x-native-proof" && header.value === "memory-tls") found = true;
                }
                if (!found || input.body.data !== "changed") return {type:"abort"};
                return {type:"modify",headers:[{op:"set",name:"x-js-response",values:["native-then-js"]}],body:{kind:"text",data:"Changed"}};
              }
"#;
    for cipher in [
        ShadowsocksCipher::Aes128Gcm,
        ShadowsocksCipher::Aes256Gcm,
        ShadowsocksCipher::Chacha20Poly1305,
    ] {
        let factory = MemoryObfsFactory::new_v2ray_mux(cipher, 4096);
        let weak = Arc::downgrade(&factory);
        super::ss_obfs_reuse::run_scripted_with_factory(factory.clone(), SCRIPTS).await;
        let receipt = factory.snapshot();
        assert_eq!((receipt.owners, receipt.mux_new), (1, 1), "{receipt:?}");
        drop(factory);
        assert!(
            weak.upgrade().is_none(),
            "scripted HTTP parent retained factory"
        );
    }
}
