#![cfg(feature = "outbound-hysteria2")]
use async_trait::async_trait;
use bytes::Bytes;
use quinn::AsyncUdpSocket;
use std::{
    collections::VecDeque,
    future::poll_fn,
    io::IoSliceMut,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use vole::{
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};

// In-memory controlled datagrams, not a host network or a HY2 server substitute.
struct Packets {
    incoming: VecDeque<Datagram>,
    sent: tokio::sync::mpsc::Sender<Datagram>,
    closed: Arc<AtomicUsize>,
}
#[async_trait]
impl DatagramTransport for Packets {
    fn supports_shared_destinations(&self) -> bool {
        false
    }

    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(1400, 1400)
    }
    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        self.sent
            .send(packet)
            .await
            .map_err(|_| DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        match self.incoming.pop_front() {
            Some(packet) => Ok(packet),
            None => std::future::pending().await,
        }
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn controlled_path_maps_only_its_authorized_source_and_stops_without_replay() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "HYSTERIA2-UNIT",
        "controlled_path_maps_only_its_authorized_source_and_stops_without_replay",
    );
    let logical = "192.0.2.1:443".parse().unwrap();
    let physical = "192.0.2.1:8443".parse().unwrap();
    let packet = |remote, payload| Datagram {
        remote: Destination::Ip(remote),
        payload,
        sniffed_domain: None,
    };
    let (sent, mut observed) = tokio::sync::mpsc::channel(4);
    let closed = Arc::new(AtomicUsize::new(0));
    let raw = Packets {
        incoming: [
            packet(logical, Bytes::from_static(b"foreign-port")),
            packet(physical, vec![0; 1401].into()),
            packet(physical, Bytes::from_static(b"authorized")),
        ]
        .into(),
        sent,
        closed: closed.clone(),
    };
    let (socket, driver) = vole::transport::quic::attach_mapped(
        Box::new(raw),
        logical,
        physical,
        DatagramBudget::new(1400, 1400),
    )
    .unwrap();
    let request = quinn::udp::Transmit {
        destination: logical,
        ecn: None,
        contents: b"once",
        segment_size: None,
        src_ip: None,
    };
    socket.try_send(&request).unwrap();
    let outbound = observed.recv().await.unwrap();
    assert_eq!(outbound.remote, Destination::Ip(physical));
    assert_eq!(outbound.payload, b"once"[..]);
    let mut bytes = [0; 1400];
    let mut buffers = [IoSliceMut::new(&mut bytes)];
    let mut metadata = [quinn::udp::RecvMeta::default()];
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata))
        )
        .await
        .unwrap()
        .unwrap(),
        1
    );
    assert_eq!(metadata[0].addr, logical);
    assert_eq!(&bytes[..metadata[0].len], b"authorized");
    assert_eq!(socket.stats().rejected_source, 1);
    assert_eq!(socket.stats().rejected_oversize, 1);
    driver.stop().await.unwrap();
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(socket.try_send(&request).is_err());
    assert!(observed.recv().await.is_none());
}
