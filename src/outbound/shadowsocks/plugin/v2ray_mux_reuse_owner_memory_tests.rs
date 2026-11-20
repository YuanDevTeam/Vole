//! Run the complete SS owner checks through the plain WS mux binding.
use super::obfs_reuse_owner_memory_tests::{
    Carrier, assert_pending_stop, assert_sibling_drop, assert_stop_before_bind,
};

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_complete_ss_stop_wakes_independent_pending_operations() {
    assert_pending_stop(Carrier::V2rayMux).await;
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_stop_before_bind_rejects_complete_ss_without_touching_raw() {
    assert_stop_before_bind(Carrier::V2rayMux).await;
}

#[tokio::test(flavor = "current_thread")]
async fn v2ray_mux_owned_child_drop_preserves_parent_and_sibling_until_parent_stop() {
    assert_sibling_drop(Carrier::V2rayMux).await;
}
