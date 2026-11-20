//! New private-helper contracts, not a deterministic old-source RED.
//! The real Noise/stack fixture is shared with existing PendingIngress controls.
use super::*;
use futures_util::task::{ArcWake, waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl ArcWake for WakeCount {
    fn wake_by_ref(owner: &Arc<Self>) {
        owner.0.fetch_add(1, Ordering::Relaxed);
    }
}
#[derive(Default)]
struct ReceiveFacts {
    polls: usize,
    drops: usize,
    closes: usize,
    remaining: usize,
    original_context: bool,
}
struct ReceiveDrop(Arc<Mutex<ReceiveFacts>>);
impl Drop for ReceiveDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap().drops += 1;
    }
}
struct ReadyReceive {
    incoming: VecDeque<Datagram>,
    facts: Arc<Mutex<ReceiveFacts>>,
    expected_waker: Option<std::task::Waker>,
}
#[async_trait::async_trait]
impl DatagramTransport for ReadyReceive {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let _owner = ReceiveDrop(self.facts.clone());
        std::future::poll_fn(|context| {
            let mut facts = self.facts.lock().unwrap();
            facts.polls += 1;
            facts.original_context = self
                .expected_waker
                .as_ref()
                .is_none_or(|expected| context.waker().will_wake(expected));
            match self.incoming.pop_front() {
                Some(datagram) => Poll::Ready(Ok(datagram)),
                None => Poll::Pending,
            }
        })
        .await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        let mut facts = self.facts.lock().unwrap();
        facts.closes += 1;
        facts.remaining = self.incoming.len();
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wireguard_memory_ready_rx_single_poll_keeps_context_and_drops_pending() {
    let facts = Arc::new(Mutex::new(ReceiveFacts::default()));
    let wake_count = Arc::new(WakeCount::default());
    let original_waker = waker(wake_count.clone());
    let mut context = Context::from_waker(&original_waker);
    let mut transport: Box<dyn DatagramTransport> = Box::new(ReadyReceive {
        incoming: VecDeque::new(),
        facts: facts.clone(),
        expected_waker: Some(original_waker.clone()),
    });
    // Construction is not a poll. A single actual helper poll observes inner
    // Pending and drops that receive wrapper without waiting or self-waking.
    let unpolled = Box::pin(poll_ready_datagram(&mut transport));
    drop(unpolled);
    let before = facts.lock().unwrap().polls;
    let mut operation = Box::pin(poll_ready_datagram(&mut transport));
    let observed = operation.as_mut().poll(&mut context);
    drop(operation);
    let closed = transport.close().await.is_ok();
    drop(transport);
    let facts = facts.lock().unwrap();
    assert!(closed && matches!(observed, Poll::Ready(Poll::Pending)));
    assert_eq!(
        (before, facts.polls, facts.drops, facts.closes),
        (0, 1, 1, 1)
    );
    assert!(facts.original_context);
    assert_eq!(wake_count.0.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn wireguard_memory_ready_rx_real_noise_cap_and_ingress_cancel_boundaries() {
    let resource_probe = crate::resources::observation::ResourceProbe::default();
    let observed = resource_probe
        .scope(async {
            let mut fixture = saturated().await;
            let pending = fixture.state.ingress.take();
            let (mut client, mut server) = noise_pair();
            let endpoint: SocketAddr = "198.51.100.1:51820".parse().unwrap();
            let mut scratch = vec![0; 1440];
            let mut normalization = vec![0; 1440];
            let mut incoming = VecDeque::new();
            for sequence in 0_u8..5 {
                let mut raw = Vec::new();
                if sequence != 2 {
                    encode_udp_packet_into(
                        &UdpDatagram::new(
                            "10.0.0.1:53".parse().unwrap(),
                            SocketAddr::new("10.0.0.2".parse().unwrap(), fixture._udp_slot.port),
                            Bytes::from(vec![sequence]),
                        ),
                        1408,
                        &mut raw,
                    )
                    .unwrap();
                }
                let encrypted = network(server.encapsulate(&raw, &mut scratch));
                incoming.push_back(Datagram {
                    // Wrong endpoint and a genuine encrypted keepalive must both
                    // consume one slot of the same three-extra-packet quantum.
                    remote: Destination::Ip(if sequence == 1 {
                        "198.51.100.2:51820".parse().unwrap()
                    } else {
                        endpoint
                    }),
                    payload: Bytes::from(encrypted),
                    sniffed_domain: None,
                });
            }
            let first = incoming.pop_front().unwrap();
            let facts = Arc::new(Mutex::new(ReceiveFacts::default()));
            let mut transport: Box<dyn DatagramTransport> = Box::new(ReadyReceive {
                incoming,
                facts: facts.clone(),
                expected_waker: None,
            });
            let deadline = fixture.state.handshake_deadline;
            // Invoke the actual production first-packet handler, then its exact
            // extra-ready helper. This is a helper contract, not select RNG proof.
            let first_ok = handle_peer_datagram(
                &fixture.driver,
                &mut client,
                endpoint,
                &mut transport,
                &mut fixture.state,
                deadline,
                &mut scratch,
                &mut normalization,
                first,
            )
            .await
            .is_ok();
            let burst_ok = drain_ready_datagrams(
                &fixture.driver,
                &mut client,
                endpoint,
                &mut transport,
                &mut fixture.state,
                deadline,
                &mut scratch,
                &mut normalization,
            )
            .await
            .is_ok();
            let mut delivered = Vec::new();
            while let Ok(datagram) = fixture.udp.try_recv() {
                delivered.push(datagram.payload.to_vec());
            }
            let after_burst = facts.lock().unwrap().polls;
            fixture.state.ingress = pending;
            let blocked_ok = drain_ready_datagrams(
                &fixture.driver,
                &mut client,
                endpoint,
                &mut transport,
                &mut fixture.state,
                deadline,
                &mut scratch,
                &mut normalization,
            )
            .await
            .is_ok();
            let after_ingress = facts.lock().unwrap().polls;
            let retained = fixture.state.ingress.is_some();
            drop(fixture.state.ingress.take());
            fixture.state.established = false;
            let unestablished_ok = drain_ready_datagrams(
                &fixture.driver,
                &mut client,
                endpoint,
                &mut transport,
                &mut fixture.state,
                deadline,
                &mut scratch,
                &mut normalization,
            )
            .await
            .is_ok();
            let after_unestablished = facts.lock().unwrap().polls;
            fixture.state.established = true;
            fixture.cancel.cancel();
            let cancelled = matches!(
                drain_ready_datagrams(
                    &fixture.driver,
                    &mut client,
                    endpoint,
                    &mut transport,
                    &mut fixture.state,
                    deadline,
                    &mut scratch,
                    &mut normalization,
                )
                .await,
                Err(DispatchError::ConnectionRefused)
            );
            let closed = transport.close().await.is_ok();
            drop(transport);
            let original_closed = fixture.transport.close().await.is_ok();
            drop(fixture.pump);
            drop(fixture.connects);
            stop(&fixture.control).await;
            let facts = facts.lock().unwrap();
            (
                first_ok,
                burst_ok,
                blocked_ok,
                unestablished_ok,
                cancelled,
                closed && original_closed,
                retained,
                delivered,
                after_burst,
                after_ingress,
                after_unestablished,
                facts.polls,
                facts.drops,
                facts.closes,
                facts.remaining,
            )
        })
        .await;
    // Every semantic assertion is after carrier close and real stack Stop/join.
    assert!(resource_probe.snapshot().is_idle());
    assert!(
        observed.0
            && observed.1
            && observed.2
            && observed.3
            && observed.4
            && observed.5
            && observed.6
    );
    assert_eq!(observed.7, vec![vec![0], vec![3]]);
    assert_eq!(
        (observed.8, observed.9, observed.10, observed.11),
        (3, 3, 3, 3)
    );
    assert_eq!((observed.12, observed.13, observed.14), (3, 1, 1));
}
