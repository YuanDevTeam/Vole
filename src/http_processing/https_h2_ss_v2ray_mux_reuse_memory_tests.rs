//! Real SS2022/plain WS mux beneath the original authenticated TLS/HTTP cache.
//! Pure memory only; no official Go server, sockets or throughput claims.
use super::*;
use crate::{config::ShadowsocksCipher, outbound::MemoryObfsFactory};
async fn exercise(mode: PostReply) {
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
async fn ss_v2ray_mux_https_h2_two_posts_share_one_authenticated_carrier() {
    exercise(PostReply::Complete).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h2_submitted_second_post_is_not_replayed() {
    exercise(PostReply::FailSecond).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h2_active_stop_drops_partial_upload() {
    exercise(PostReply::Wait).await;
}

#[tokio::test]
async fn ss_v2ray_mux_https_h2_early_final_retires_uncertain_upload() {
    exercise(PostReply::Early).await;
}

#[cfg(target_vendor = "apple")]
#[tokio::test]
async fn ss_v2ray_mux_https_h2_native_then_js_reuses_one_authenticated_carrier() {
    // The extra native header is deliberately unacceptable to post_response.
    // Only the response script restores its required value after checking the
    // native body; request-script output is independently read by the origin.
    const SCRIPTS: &str = r#"    - {url: 'https://a.test/', match: prefix, action: response-header-set, header: x-proof, value: before-js}
http-scripts:
  enabled: true
  scripts:
    - name: actual-request-body
      phase: request
      url: https://a.test/
      match: prefix
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
      phase: response
      url: https://a.test/
      match: prefix
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
