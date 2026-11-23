// Typed GREEN controls for router admission, attribution and pin lifetime.
// Include inside the existing dispatcher tests module on Apple targets.
mod c11_tun_send_green {
    use super::*;
    use crate::dispatch::tun_send_memory_test_support::{Packets, Probe};
    use crate::dispatch::{TunPendingSend, TunSendOutcome};

    struct LeafCounters {
        io: Arc<Probe>,
        opens: AtomicUsize,
        receive_error: Arc<AtomicBool>,
    }
    struct LeafDispatcher {
        counters: Arc<LeafCounters>,
        shareable: bool,
        accept: bool,
    }
    struct Leaf {
        io: Packets,
        shareable: bool,
        receive_error: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Dispatcher for LeafDispatcher {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            panic!("router owned-send GREEN must not open TCP");
        }
        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.counters.opens.fetch_add(1, Ordering::Relaxed);
            let mut io = Packets::new(self.counters.io.clone());
            io.accept = self.accept;
            Ok(Box::new(Leaf {
                io,
                shareable: self.shareable,
                receive_error: self.counters.receive_error.clone(),
            }))
        }
    }

    #[async_trait]
    impl DatagramTransport for Leaf {
        fn supports_shared_destinations(&self) -> bool {
            self.shareable
        }
        fn try_begin_tun_send(
            &mut self,
            datagram: Datagram,
            flow_id: Option<&[u8]>,
        ) -> Result<TunPendingSend, Datagram> {
            self.io.try_begin_tun_send(datagram, flow_id)
        }
        async fn finish_tun_send(
            &mut self,
            completion: crate::dispatch::TunSendToken,
            outcome: TunSendOutcome,
        ) -> Result<(), DispatchError> {
            self.io.finish_tun_send(completion, outcome).await
        }
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            self.io.send(datagram).await
        }
        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            if self.receive_error.swap(false, Ordering::AcqRel) {
                return Err(DispatchError::ConnectionRefused);
            }
            self.io.receive().await
        }
        async fn close(&mut self) -> Result<(), DispatchError> {
            self.io.close().await
        }
    }

    fn fixture(
        tracked: bool,
        shareable: bool,
        accept: bool,
    ) -> (
        RoutedDatagramTransport,
        Arc<LeafCounters>,
        Arc<crate::connections::Registry>,
    ) {
        let config = crate::config::Config::parse_yaml(
            b"mixed-port: 1080\nproxies: [{name: edge, type: socks5, server: 192.0.2.1, port: 1080}]\nrules: ['MATCH,edge']\n"
        ).unwrap();
        let counters = Arc::new(LeafCounters {
            io: Arc::new(Probe::default()),
            opens: AtomicUsize::new(0),
            receive_error: Arc::new(AtomicBool::new(false)),
        });
        let leaf: Arc<dyn Dispatcher> = Arc::new(LeafDispatcher {
            counters: counters.clone(),
            shareable,
            accept,
        });
        let rules = RuleSet::compile(config.rules.clone()).unwrap();
        let registry = Arc::new(crate::connections::Registry::default());
        let mut router = RoutingDispatcher::new(
            ProxyDispatchers::new(vec![leaf]).unwrap(),
            Arc::new(RecordingDispatcher::default()),
            None,
            rules.clone(),
            Arc::new(EmptyGeoMatcher),
        );
        if tracked {
            router = router.with_diagnostics(Arc::new(
                crate::routing::diagnostics::Diagnostics::new(&config, &rules, registry.clone()),
            ));
        }
        (
            router.routed_datagrams(association(InboundKind::Tun)),
            counters,
            registry,
        )
    }

    fn snapshot(registry: &crate::connections::Registry) -> serde_json::Value {
        let mut value = serde_json::to_value(registry.snapshot()).unwrap();
        value.as_object_mut().unwrap().remove("memory");
        value
    }
    fn assert_packet(actual: Datagram, expected: &Datagram) {
        assert_eq!(actual.remote, expected.remote);
        assert_eq!(actual.sniffed_domain, expected.sniffed_domain);
        assert_eq!(actual.payload.as_ptr(), expected.payload.as_ptr());
        assert_eq!(actual.payload.len(), expected.payload.len());
    }
    fn begin(transport: &mut RoutedDatagramTransport, peer: SocketAddr) -> TunPendingSend {
        let Ok(pending) = transport.try_begin_tun_send(datagram(peer, b"io"), Some(b"stable"))
        else {
            panic!("eligible cached typed leaf was not admitted");
        };
        pending
    }
    async fn warm(transport: &mut RoutedDatagramTransport, peer: SocketAddr) {
        transport
            .send_with_flow_id(datagram(peer, b"warm"), b"stable")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cold_changed_identity_and_unsupported_admission_preserve_packet_and_state() {
        for tracked in [false, true] {
            let (mut transport, counters, registry) = fixture(tracked, false, false);
            let peer = "198.51.100.1:443".parse().unwrap();
            let packet = datagram(peer, b"io");
            let Err(returned) = transport.try_begin_tun_send(packet.clone(), Some(b"stable"))
            else {
                panic!("cold route must use ordinary preparation");
            };
            assert_packet(returned, &packet);
            assert_eq!(counters.opens.load(Ordering::Relaxed), 0);
            assert!(transport.pending_tun_send.is_none());

            warm(&mut transport, peer).await;
            let before = snapshot(&registry);
            let last_used = if tracked {
                transport
                    .managed_flows
                    .get(&packet.remote)
                    .unwrap()
                    .last_used
            } else {
                transport.flows.entries.get(&peer).unwrap().last_used
            };
            let Err(returned) = transport.try_begin_tun_send(packet.clone(), Some(b"changed"))
            else {
                panic!("changed authenticated identity must use ordinary routing");
            };
            assert_packet(returned, &packet);
            assert_eq!(counters.io.begins.load(Ordering::Relaxed), 0);

            let Err(returned) = transport.try_begin_tun_send(packet.clone(), Some(b"stable"))
            else {
                panic!("unsupported leaf must return the original packet");
            };
            assert_packet(returned, &packet);
            assert_eq!(counters.io.begins.load(Ordering::Relaxed), 1);
            assert_eq!(counters.opens.load(Ordering::Relaxed), 1);
            assert!(transport.pending_tun_send.is_none());
            let after_used = if tracked {
                transport
                    .managed_flows
                    .get(&packet.remote)
                    .unwrap()
                    .last_used
            } else {
                transport.flows.entries.get(&peer).unwrap().last_used
            };
            assert_eq!(last_used, after_used);
            assert_eq!(snapshot(&registry), before);
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn cached_untracked_admission_preserves_one_completion_identity() {
        let (mut transport, counters, _) = fixture(false, false, true);
        let peer = "198.51.100.1:443".parse().unwrap();
        warm(&mut transport, peer).await;
        let TunPendingSend {
            operation,
            completion,
        } = begin(&mut transport, peer);
        assert!(matches!(
            &transport.pending_tun_send.as_ref().unwrap().route,
            PendingTunRoute::Cached(_)
        ));
        operation.await.unwrap();
        transport
            .finish_tun_send(completion, TunSendOutcome::Completed(Ok(())))
            .await
            .unwrap();
        assert!(transport.pending_tun_send.is_none());
        assert_eq!(counters.io.finishes.load(Ordering::Relaxed), 1);
        assert_eq!(counters.opens.load(Ordering::Relaxed), 1);
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn managed_dedicated_and_shared_success_accounts_only_completed_send_once() {
        for shared in [false, true] {
            let (mut transport, counters, registry) = fixture(true, shared, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            warm(&mut transport, peer).await;
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            let duplicate = completion.clone();
            assert_eq!(snapshot(&registry)["connections"][0]["upload"], 4);
            operation.await.unwrap();
            transport
                .finish_tun_send(completion, TunSendOutcome::Completed(Ok(())))
                .await
                .unwrap();
            assert_eq!(snapshot(&registry)["connections"][0]["upload"], 6);
            assert!(matches!(
                transport
                    .finish_tun_send(duplicate, TunSendOutcome::Completed(Ok(())))
                    .await,
                Err(DispatchError::NotAllowed)
            ));
            assert_eq!(snapshot(&registry)["connections"][0]["upload"], 6);
            assert_eq!(counters.io.finishes.load(Ordering::Relaxed), 1);
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn managed_completed_error_keeps_original_dedicated_and_shared_failure_cleanup() {
        for shared in [false, true] {
            let (mut transport, counters, registry) = fixture(true, shared, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            warm(&mut transport, peer).await;
            if shared {
                warm(&mut transport, "198.51.100.2:443".parse().unwrap()).await;
            }
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            operation.await.unwrap();
            assert!(matches!(
                transport
                    .finish_tun_send(
                        completion,
                        TunSendOutcome::Completed(Err(DispatchError::ConnectionRefused))
                    )
                    .await,
                Err(DispatchError::ConnectionRefused)
            ));
            let result = snapshot(&registry);
            assert!(result["connections"].as_array().unwrap().is_empty());
            assert_eq!(
                result["errors"].as_array().unwrap().len(),
                if shared { 2 } else { 1 }
            );
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
            assert!(transport.pending_tun_send.is_none());
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn managed_remove_defers_pin_and_wire_close_until_operation_is_dropped() {
        for shared in [false, true] {
            let (mut transport, counters, registry) = fixture(true, shared, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            warm(&mut transport, peer).await;
            let sibling: SocketAddr = "198.51.100.2:443".parse().unwrap();
            if shared {
                warm(&mut transport, sibling).await;
            }
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            transport
                .remove_managed(&Destination::Ip(peer))
                .await
                .unwrap();
            assert!(transport.pending_tun_send.as_ref().unwrap().deferred_remove);
            assert!(transport.managed_flows.contains_key(&Destination::Ip(peer)));
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 0);
            if shared {
                transport
                    .remove_managed(&Destination::Ip(sibling))
                    .await
                    .unwrap();
                assert_eq!(transport.managed_shared.values().next().unwrap().members, 1);
                assert_eq!(counters.io.closes.load(Ordering::Relaxed), 0);
            }
            // The cancellation branch drops the lower owned operation before return.
            assert!(matches!(operation.await, Err(DispatchError::NotAllowed)));
            assert!(matches!(
                transport
                    .finish_tun_send(completion, TunSendOutcome::Cancelled)
                    .await,
                Err(DispatchError::NotAllowed)
            ));
            assert!(transport.pending_tun_send.is_none());
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
            assert!(snapshot(&registry)["errors"].as_array().unwrap().is_empty());
            assert!(
                snapshot(&registry)["connections"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn external_timeout_and_cancel_do_not_fabricate_transport_failure() {
        for timed_out in [false, true] {
            let (mut transport, counters, registry) = fixture(true, false, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            warm(&mut transport, peer).await;
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            drop(operation);
            let outcome = if timed_out {
                TunSendOutcome::TimedOut
            } else {
                TunSendOutcome::Cancelled
            };
            let result = transport.finish_tun_send(completion, outcome).await;
            if timed_out {
                assert!(matches!(result, Err(DispatchError::TimedOut)));
            } else {
                assert!(matches!(result, Err(DispatchError::NotAllowed)));
            }
            let view = snapshot(&registry);
            assert!(view["errors"].as_array().unwrap().is_empty());
            assert!(view["connections"].as_array().unwrap().is_empty());
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn foreign_completion_cannot_release_an_original_operation_pin() {
        let (mut transport, counters, registry) = fixture(true, false, true);
        let peer = "198.51.100.1:443".parse().unwrap();
        warm(&mut transport, peer).await;
        let TunPendingSend {
            operation,
            completion,
        } = begin(&mut transport, peer);
        let foreign = TunPendingSend::new(Box::pin(async { Ok(()) }));
        assert!(matches!(
            transport
                .finish_tun_send(foreign.completion, TunSendOutcome::Cancelled)
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(transport.pending_tun_send.is_some());
        assert!(transport.managed_flows.contains_key(&Destination::Ip(peer)));
        assert_eq!(counters.io.finishes.load(Ordering::Relaxed), 0);
        assert_eq!(counters.io.closes.load(Ordering::Relaxed), 0);
        assert_eq!(snapshot(&registry)["connections"][0]["upload"], 4);
        drop(operation);
        assert!(matches!(
            transport
                .finish_tun_send(completion, TunSendOutcome::Cancelled)
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
        transport.close().await.unwrap();
    }

    fn poll_receive_once(
        transport: &mut RoutedDatagramTransport,
    ) -> Poll<Result<Datagram, DispatchError>> {
        use std::future::Future as _;
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut receive = Box::pin(tokio::task::unconstrained(transport.receive()));
        receive.as_mut().poll(&mut context)
    }

    #[tokio::test]
    async fn cancelled_or_expired_pin_returns_receive_error_in_one_unconstrained_poll() {
        for expired in [false, true] {
            let (mut transport, counters, registry) = fixture(true, false, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            let key = Destination::Ip(peer);
            warm(&mut transport, peer).await;
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            if expired {
                let timeout = transport.router.tun_config.udp_timeout;
                transport.managed_flows.get_mut(&key).unwrap().last_used = Instant::now() - timeout;
                transport.managed_next_cleanup = Instant::now();
            } else {
                let view = snapshot(&registry);
                let id = view["connections"][0]["id"].as_str().unwrap();
                registry.close(id);
            }
            // No surrounding timeout or Tokio cooperative yield can manufacture
            // this readiness: the production receive future is polled once.
            assert!(matches!(
                poll_receive_once(&mut transport),
                Poll::Ready(Err(DispatchError::NotAllowed))
            ));
            let pending = transport.pending_tun_send.as_ref().unwrap();
            assert!(pending.completion.same(&completion));
            assert!(pending.deferred_remove);
            assert!(transport.managed_flows.contains_key(&key));
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 0);
            assert_eq!(counters.io.finishes.load(Ordering::Relaxed), 0);
            assert!(snapshot(&registry)["errors"].as_array().unwrap().is_empty());
            // Keep the owned operation alive throughout the receive assertion.
            drop(operation);
            assert!(matches!(
                transport
                    .finish_tun_send(completion, TunSendOutcome::Cancelled)
                    .await,
                Err(DispatchError::NotAllowed)
            ));
            assert!(transport.pending_tun_send.is_none());
            assert!(transport.managed_flows.iter().next().is_none());
            assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
            assert!(
                snapshot(&registry)["connections"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            transport.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn shared_receive_error_returns_original_error_in_one_poll_without_closing_pin() {
        let (mut transport, counters, registry) = fixture(true, true, true);
        let peer = "198.51.100.1:443".parse().unwrap();
        let key = Destination::Ip(peer);
        warm(&mut transport, peer).await;
        warm(&mut transport, "198.51.100.2:443".parse().unwrap()).await;
        let TunPendingSend {
            operation,
            completion,
        } = begin(&mut transport, peer);
        counters.receive_error.store(true, Ordering::Release);
        assert!(matches!(
            poll_receive_once(&mut transport),
            Poll::Ready(Err(DispatchError::ConnectionRefused))
        ));
        let pending = transport.pending_tun_send.as_ref().unwrap();
        assert!(pending.completion.same(&completion));
        assert!(pending.deferred_remove);
        assert!(transport.managed_flows.contains_key(&key));
        assert_eq!(transport.managed_shared.values().next().unwrap().members, 1);
        assert_eq!(counters.io.closes.load(Ordering::Relaxed), 0);
        assert_eq!(counters.io.finishes.load(Ordering::Relaxed), 0);
        assert_eq!(snapshot(&registry)["errors"].as_array().unwrap().len(), 2);
        drop(operation);
        assert!(matches!(
            transport
                .finish_tun_send(completion, TunSendOutcome::Cancelled)
                .await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(transport.pending_tun_send.is_none());
        assert!(transport.managed_flows.iter().next().is_none());
        assert!(transport.managed_shared.is_empty());
        assert_eq!(counters.io.closes.load(Ordering::Relaxed), 1);
        let view = snapshot(&registry);
        assert!(view["connections"].as_array().unwrap().is_empty());
        assert_eq!(view["errors"].as_array().unwrap().len(), 2);
        transport.close().await.unwrap();
    }

    #[tokio::test]
    async fn maintenance_due_declines_without_mutation_then_ordinary_send_maintains_cache() {
        for tracked in [false, true] {
            let (mut transport, counters, registry) = fixture(tracked, false, true);
            let peer = "198.51.100.1:443".parse().unwrap();
            let key = Destination::Ip(peer);
            warm(&mut transport, peer).await;
            let due = Instant::now();
            if tracked {
                transport.managed_next_cleanup = due;
            } else {
                transport.flows.next_cleanup = due;
            }
            let before = snapshot(&registry);
            let last_used = if tracked {
                transport.managed_flows.get(&key).unwrap().last_used
            } else {
                transport.flows.entries.get(&peer).unwrap().last_used
            };
            let original = datagram(peer, b"io");
            let Err(returned) = transport.try_begin_tun_send(original.clone(), Some(b"stable"))
            else {
                panic!("due maintenance must retain the ordinary path");
            };
            assert_packet(returned, &original);
            assert!(transport.pending_tun_send.is_none());
            assert_eq!(counters.io.begins.load(Ordering::Relaxed), 0);
            assert_eq!(counters.opens.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot(&registry), before);
            if tracked {
                assert_eq!(transport.managed_next_cleanup, due);
                assert_eq!(
                    transport.managed_flows.get(&key).unwrap().last_used,
                    last_used
                );
            } else {
                assert_eq!(transport.flows.next_cleanup, due);
                assert_eq!(
                    transport.flows.entries.get(&peer).unwrap().last_used,
                    last_used
                );
            }
            transport
                .send_with_flow_id(datagram(peer, b"more"), b"stable")
                .await
                .unwrap();
            let TunPendingSend {
                operation,
                completion,
            } = begin(&mut transport, peer);
            operation.await.unwrap();
            transport
                .finish_tun_send(completion, TunSendOutcome::Completed(Ok(())))
                .await
                .unwrap();
            assert!(transport.pending_tun_send.is_none());
            assert_eq!(counters.io.begins.load(Ordering::Relaxed), 1);
            assert_eq!(counters.opens.load(Ordering::Relaxed), 1);
            transport.close().await.unwrap();
        }
    }
}
