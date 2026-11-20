use super::tun_send_memory_test_support::{
    Packets, Probe, assert_untouched, completion_outcomes, packet,
};
use super::*;
use std::sync::{Arc, atomic::Ordering};

#[tokio::test]
async fn tun_owned_observed_wrapper_forwards_identity_metadata_and_all_outcomes() {
    let probe = Arc::new(Probe::default());
    let stats = RuntimeResourceStats::new("tun_owned_wrapper");
    let mut transport = ObservedDatagramTransport {
        inner: Box::new(Packets::new(probe.clone())),
        _activity: stats.begin(ResourceActivity::UdpAssociation),
    };
    completion_outcomes(&mut transport, &probe).await;
}

#[test]
fn tun_owned_observed_wrapper_returns_unsupported_packet_without_legacy_send() {
    let probe = Arc::new(Probe::default());
    let mut packets = Packets::new(probe.clone());
    packets.accept = false;
    let stats = RuntimeResourceStats::new("tun_owned_wrapper");
    let mut transport = ObservedDatagramTransport {
        inner: Box::new(packets),
        _activity: stats.begin(ResourceActivity::UdpAssociation),
    };
    let original = packet(b"ok");
    let Err(returned) = transport.try_begin_tun_send(original.clone(), Some(b"opaque")) else {
        panic!("unsupported inner path must decline");
    };
    assert_untouched(returned, &original);
    assert_eq!(probe.begins.load(Ordering::Relaxed), 1);
    assert_eq!(probe.legacy.load(Ordering::Relaxed), 0);
}
