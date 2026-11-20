use super::*;
use crate::dispatch::tun_send_memory_test_support::{
    Packets, Probe, assert_untouched, completion_outcomes, packet,
};
use std::sync::{Arc, atomic::Ordering};

#[tokio::test]
async fn tun_owned_wrapper_preserves_both_payload_caps_and_closed_admission() {
    for (outer, inner) in [(2, 4), (4, 2)] {
        let probe = Arc::new(Probe::default());
        let mut packets = Packets::new(probe.clone());
        packets.budget = DatagramBudget::new(inner, inner);
        let mut transport = bounded(Box::new(packets), DatagramBudget::new(outer, outer));
        let original = packet(b"big");
        let Err(returned) = transport.try_begin_tun_send(original.clone(), Some(b"opaque")) else {
            panic!("oversized packet reached the inner owned seam");
        };
        assert_untouched(returned, &original);
        assert_eq!(probe.begins.load(Ordering::Relaxed), 0);
    }
    let probe = Arc::new(Probe::default());
    let mut transport = bounded(
        Box::new(Packets::new(probe.clone())),
        DatagramBudget::new(4, 4),
    );
    transport.close().await.unwrap();
    let original = packet(b"ok");
    let Err(returned) = transport.try_begin_tun_send(original.clone(), None) else {
        panic!("closed wrapper admitted an owned send");
    };
    assert_untouched(returned, &original);
    assert_eq!(probe.begins.load(Ordering::Relaxed), 0);
    assert_eq!(probe.closes.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn tun_owned_bounded_wrapper_forwards_identity_flow_metadata_and_all_outcomes() {
    let probe = Arc::new(Probe::default());
    let mut transport = bounded(
        Box::new(Packets::new(probe.clone())),
        DatagramBudget::new(4, 4),
    );
    completion_outcomes(transport.as_mut(), &probe).await;
}

#[test]
fn tun_owned_bounded_wrapper_returns_unsupported_packet_without_replay() {
    let probe = Arc::new(Probe::default());
    let mut packets = Packets::new(probe.clone());
    packets.accept = false;
    let mut transport = bounded(Box::new(packets), DatagramBudget::new(4, 4));
    let original = packet(b"ok");
    let Err(returned) = transport.try_begin_tun_send(original.clone(), Some(b"opaque")) else {
        panic!("unsupported inner path must decline");
    };
    assert_untouched(returned, &original);
    assert_eq!(probe.begins.load(Ordering::Relaxed), 1);
    assert_eq!(probe.legacy.load(Ordering::Relaxed), 0);
}
