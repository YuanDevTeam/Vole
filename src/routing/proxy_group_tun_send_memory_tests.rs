use super::*;
use crate::dispatch::tun_send_memory_test_support::{
    Packets, Probe, assert_untouched, completion_outcomes, packet,
};
use crate::session::InboundKind;

struct NoOpen;
#[async_trait]
impl Dispatcher for NoOpen {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        panic!("owned admission must not open a stream");
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        panic!("owned admission must not select or open a leaf");
    }
}

fn wrapper(transport: Option<Box<dyn DatagramTransport>>) -> BalancedDatagrams {
    BalancedDatagrams {
        groups: ProxyGroups::new(&[], Vec::new(), Arc::new(NoOpen)).unwrap(),
        id: ProxyGroupId::new(0).unwrap(),
        session: DatagramSession::for_tun("192.0.2.2:1234".parse().unwrap(), 1400),
        transport,
    }
}

#[test]
fn tun_owned_balanced_cold_path_returns_original_packet_without_selecting() {
    let mut transport = wrapper(None);
    assert_eq!(transport.session.inbound, InboundKind::Tun);
    let original = packet(b"ok");
    let Err(returned) = transport.try_begin_tun_send(original.clone(), Some(b"opaque")) else {
        panic!("cold group must retain ordinary leaf selection");
    };
    assert_untouched(returned, &original);
    assert!(transport.transport.is_none());
}

#[tokio::test]
async fn tun_owned_balanced_open_leaf_forwards_identity_metadata_and_all_outcomes() {
    let probe = Arc::new(Probe::default());
    let mut transport = wrapper(Some(Box::new(Packets::new(probe.clone()))));
    completion_outcomes(&mut transport, &probe).await;
}

#[test]
fn tun_owned_balanced_unsupported_leaf_returns_original_packet() {
    let probe = Arc::new(Probe::default());
    let mut packets = Packets::new(probe.clone());
    packets.accept = false;
    let mut transport = wrapper(Some(Box::new(packets)));
    let original = packet(b"ok");
    let Err(returned) = transport.try_begin_tun_send(original.clone(), None) else {
        panic!("unsupported cached leaf must decline");
    };
    assert_untouched(returned, &original);
    assert_eq!(probe.begins.load(Ordering::Relaxed), 1);
    assert_eq!(probe.legacy.load(Ordering::Relaxed), 0);
}
