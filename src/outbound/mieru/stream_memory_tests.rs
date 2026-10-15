//! Exercise the actual delivery/read path with observable backing ownership.
use super::*;

#[tokio::test]
async fn mieru_standard_business_does_not_retain_lazy_handshake_state() {
    use super::super::{
        MieruOutbound,
        tests::{Peer, config, session},
    };
    use crate::{
        config::MieruHandshake,
        outbound::{EstablishContext, OutboundConnector, UpstreamPath},
        resources::observation::ResourceProbe,
    };

    let probe = ResourceProbe::default();
    let bytes = probe
        .scope(async {
            let peer = Peer::new(false);
            let node = MieruOutbound::new(
                &config(MieruHandshake::Standard),
                UpstreamPath::proxy(peer.clone()),
                32768,
            )
            .unwrap();
            let mut connected = node
                .connect_stream(
                    session(),
                    &EstablishContext::with_timeout(Duration::from_secs(3)),
                )
                .await
                .unwrap();
            let bytes = std::mem::size_of_val(connected.io.as_ref());
            connected.io.shutdown().await.unwrap();
            node.shutdown().await;
            drop((connected, node));
            peer.stop().await;
            bytes
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(
        bytes <= 64,
        "completed standard handshake retains {bytes} bytes of stream state"
    );
}

struct Payload {
    bytes: Vec<u8>,
    released: Arc<AtomicBool>,
}
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        self.released.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn mieru_tcp_delivery_does_not_pin_a_large_frame_for_its_small_tail() {
    const CAPACITY: usize = 8192;
    const TAIL: usize = 17;
    let probe = crate::resources::observation::ResourceProbe::default();
    let detached = probe
        .scope(async {
            let cancel = CancellationToken::new();
            let state = State::new(1, CAPACITY, &cancel, Arc::default());
            let released = Arc::new(AtomicBool::new(false));
            let payload = Bytes::from_owner(Payload {
                bytes: vec![0x5a; 2 * CAPACITY + TAIL],
                released: released.clone(),
            });
            let delivering = {
                let state = state.clone();
                tokio::spawn(async move { state.deliver(payload).await })
            };
            // The same read implementation serves RawStream and the packet
            // parser. Leave the last small chunk queued after delivery ends.
            for length in [CAPACITY, CAPACITY] {
                let mut bytes = vec![0; length];
                let mut buffer = ReadBuf::new(&mut bytes);
                tokio::time::timeout(
                    Duration::from_secs(1),
                    std::future::poll_fn(|cx| state.poll_read(cx, &mut buffer)),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(buffer.filled(), vec![0x5a; length]);
            }
            tokio::time::timeout(Duration::from_secs(1), delivering)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let detached = released.load(Ordering::Acquire);
            let mut bytes = [0; TAIL];
            let mut buffer = ReadBuf::new(&mut bytes);
            std::future::poll_fn(|cx| state.poll_read(cx, &mut buffer))
                .await
                .unwrap();
            assert_eq!(buffer.filled(), [0x5a; TAIL]);
            assert_eq!(state.receive_bytes.available_permits(), CAPACITY);
            state.close();
            drop(state);
            assert!(released.load(Ordering::Acquire));
            detached
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(detached, "queued tail still pins the entire received frame");
}
