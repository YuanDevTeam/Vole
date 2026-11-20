//! Focused cancellation control for the real private TUN association entry.
use super::*;

#[tokio::test]
async fn cancelled_tun_prepare_never_admits_a_send_after_its_await() {
    #[derive(Default)]
    struct Counts {
        sniff_calls: AtomicUsize,
        begins: AtomicUsize,
        legacy_sends: AtomicUsize,
        closes: AtomicUsize,
        entered_prepare: Notify,
        release_prepare: Notify,
    }
    struct GateDispatcher(Arc<Counts>);
    struct GateDatagrams(Arc<Counts>);

    #[async_trait]
    impl Dispatcher for GateDispatcher {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }
        async fn sniff_plan(
            &self,
            _: SocketAddr,
            _: &Destination,
        ) -> Result<Option<crate::sniffing::Plan>, DispatchError> {
            // Inbound classification is call one. ReadySend preparation is
            // call two, and must resume only after parent cancellation.
            if self.0.sniff_calls.fetch_add(1, Ordering::AcqRel) == 1 {
                self.0.entered_prepare.notify_one();
                self.0.release_prepare.notified().await;
            }
            Ok(None)
        }
        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            Ok(Box::new(GateDatagrams(self.0.clone())))
        }
    }
    #[async_trait]
    impl DatagramTransport for GateDatagrams {
        fn supports_shared_destinations(&self) -> bool {
            false
        }
        fn try_begin_tun_send(
            &mut self,
            _: Datagram,
            _: Option<&[u8]>,
        ) -> Result<crate::dispatch::TunPendingSend, Datagram> {
            self.0.begins.fetch_add(1, Ordering::AcqRel);
            Ok(crate::dispatch::TunPendingSend::new(Box::pin(async {
                Ok(())
            })))
        }
        async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
            self.0.legacy_sends.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            std::future::pending().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.0.closes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    let counts = Arc::new(Counts::default());
    let probe = observation::ResourceProbe::default();
    let (entered_prepare, association_joined) = probe
        .scope(async {
            let source = "192.0.2.10:12000".parse().unwrap();
            let destination = "198.51.100.20:80".parse().unwrap();
            let (input, inbound) = mpsc::channel(1);
            input
                .try_send(UdpDatagram::new(source, destination, b"x".as_slice()))
                .unwrap();
            let (responses, output) = mpsc::channel(1);
            let parent = CancellationToken::new();
            let stats = RuntimeResourceStats::new("tun_cancel_prepare_test");
            let activity = stats.begin(ResourceActivity::UdpAssociation);
            let context = UdpAssociationTaskContext {
                association_id: 1,
                source,
                responses,
                dispatcher: Arc::new(GateDispatcher(counts.clone())),
                resource_stats: stats,
                association_clock: AssociationClock::realtime(),
                last_activity: Arc::new(AtomicU64::new(0)),
                tun_mtu: TUN_MTU,
                udp_timeout: Duration::from_secs(30),
                sniffer: None,
                cancellation: parent.child_token(),
            };
            let mut task = tokio::spawn(observation::task(run_udp_association(
                inbound, activity, context,
            )));
            let entered = timeout(Duration::from_secs(1), counts.entered_prepare.notified())
                .await
                .is_ok();
            // This ordering is unconditional, including a failed entry witness.
            parent.cancel();
            counts.release_prepare.notify_one();
            drop(input);
            let joined = match timeout(Duration::from_secs(2), &mut task).await {
                Ok(Ok((_, _, result))) => result.is_ok(),
                Ok(Err(_)) => false,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    false
                }
            };
            drop(output);
            (entered, joined)
        })
        .await;
    let probe_idle = probe.snapshot().is_idle();
    // No verdict can skip parent cancellation, gate release, or the owner join.
    assert!(
        entered_prepare && association_joined && probe_idle,
        "TUN prepare cancellation fixture did not close"
    );
    assert_eq!(counts.sniff_calls.load(Ordering::Acquire), 2);
    assert_eq!(
        counts.begins.load(Ordering::Acquire),
        0,
        "cancelled preparation consumed a TUN send admission"
    );
    assert_eq!(
        counts.legacy_sends.load(Ordering::Acquire),
        0,
        "cancelled preparation reached legacy send"
    );
    assert_eq!(counts.closes.load(Ordering::Acquire), 1);
}
