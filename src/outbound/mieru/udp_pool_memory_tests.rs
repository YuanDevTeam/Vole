//! Pool admission over the original Carrier FIFO, RawStream and byte permits.
//! No physical driver is started; done/permit retirement are explicit witnesses.
use super::super::tests::{Peer, config};
use super::*;
use crate::{config::MieruHandshake, resources::observation::ResourceProbe};

const CREDIT: usize = 16;

fn install(client: &Client, business: Business) -> (Arc<Carrier>, mpsc::Receiver<WriterCommand>) {
    let mut shared = Shared::output_test_shared(client.cancel.child_token());
    let settings = Arc::get_mut(&mut shared).unwrap();
    settings.udp = true;
    settings.business = client.pool(business);
    let state = State::new(1, CREDIT, &shared.cancel, shared.activity.clone());
    shared.sessions.lock().unwrap().insert(1, state);
    let (writer, receiver) = mpsc::channel(WRITER_COMMANDS);
    let carrier = Arc::new(Carrier {
        shared,
        writer,
        bytes: Arc::new(Semaphore::new(CREDIT)),
    });
    client
        .registry
        .lock()
        .unwrap()
        .carriers
        .insert(1, carrier.clone());
    (carrier, receiver)
}

fn pooled_stream(client: &Client, business: Business, id: u32) -> (RawStream, Arc<Carrier>) {
    let reservation = client.reserve_reusable(business, |_| 0).unwrap().unwrap();
    let carrier = reservation.0.clone();
    let state = State::new(
        id,
        CREDIT,
        &carrier.shared.cancel,
        carrier.shared.activity.clone(),
    );
    carrier
        .shared
        .sessions
        .lock()
        .unwrap()
        .insert(id, state.clone());
    drop(reservation); // Match Client::open: publish State before releasing admission.
    let raw = RawStream::new(carrier.clone(), state, CREDIT)
        .with_queued_writes(business == Business::UdpAssociate && client.queues_datagrams());
    (raw, carrier)
}

#[tokio::test]
async fn busy_tcp_credit_is_not_a_udp_business_carrier() {
    let probe = ResourceProbe::default();
    let (write_pending, full, excluded, tcp_active_reuse, cancelled, reclaimed, calls) = probe
        .scope(async {
            let peer = Peer::new(false);
            let mut settings = config(MieruHandshake::Standard);
            settings.transport = MieruTransport::Udp;
            settings.multiplexing = MieruMultiplexing::Low;
            let client = Client::new(&settings, UpstreamPath::proxy(peer.clone()), CREDIT).unwrap();
            let (carrier, mut commands) = install(&client, Business::TcpConnect);
            let credit = carrier.bytes.clone();
            let (mut raw, selected) = pooled_stream(&client, Business::TcpConnect, 2);
            drop(selected);
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            // Production classic TCP-business write owns all original permits
            // and is waiting for its command's first-send completion.
            let write_pending = Pin::new(&mut raw)
                .poll_write(&mut cx, b"0123456789ABCDEF")
                .is_pending();
            let command = commands.try_recv().unwrap();
            let full =
                credit.available_permits() == 0 && command.data.as_ref() == b"0123456789ABCDEF";
            // Before the fix the real picker returns this occupied TCP carrier.
            let udp = client
                .reserve_reusable(Business::UdpAssociate, |_| 0)
                .unwrap();
            let excluded = udp.is_none();
            drop(udp);
            // UDP carrier LOW must still reuse an active same-business carrier;
            // changing pool() alone would accidentally make TCP SID exclusive.
            let tcp = client
                .reserve_reusable(Business::TcpConnect, |_| 0)
                .unwrap();
            let tcp_active_reuse = tcp
                .as_ref()
                .is_some_and(|picked| Arc::ptr_eq(&picked.0, &carrier));
            drop(tcp);
            client.shutdown().await;
            let cancelled = matches!(Pin::new(&mut raw).poll_write(&mut cx, b"x"),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe);
            drop((raw, command, commands, carrier, client));
            let reclaimed = credit.available_permits();
            let calls = peer.calls.load(Ordering::Acquire);
            peer.stop().await;
            (
                write_pending,
                full,
                excluded,
                tcp_active_reuse,
                cancelled,
                reclaimed,
                calls,
            )
        })
        .await;
    assert!(probe.snapshot().is_idle());
    assert!(
        write_pending && full,
        "real TCP command must hold the complete byte credit"
    );
    assert!(
        excluded,
        "a UDP business must not reuse the busy TCP business carrier"
    );
    assert!(
        tcp_active_reuse,
        "UDP carrier must retain same-business active reuse"
    );
    assert!(cancelled);
    assert_eq!(reclaimed, CREDIT);
    assert_eq!(calls, 0, "pool admission must not open any physical IO");
}

#[tokio::test]
async fn udp_active_pool_keeps_the_original_fifo_credit_and_stop() {
    let probe = ResourceProbe::default();
    let outcome = probe
        .scope(async {
            let peer = Peer::new(false);
            let mut settings = config(MieruHandshake::Standard);
            settings.transport = MieruTransport::Udp;
            settings.multiplexing = MieruMultiplexing::Low;
            let client = Client::new(&settings, UpstreamPath::proxy(peer.clone()), CREDIT).unwrap();
            let (carrier, mut commands) = install(&client, Business::UdpAssociate);
            let credit = carrier.bytes.clone();
            let (mut first, first_carrier) = pooled_stream(&client, Business::UdpAssociate, 2);
            let (mut second, second_carrier) = pooled_stream(&client, Business::UdpAssociate, 3);
            let (mut third, third_carrier) = pooled_stream(&client, Business::UdpAssociate, 4);
            let same_carrier = Arc::ptr_eq(&first_carrier, &carrier)
                && Arc::ptr_eq(&second_carrier, &carrier)
                && Arc::ptr_eq(&third_carrier, &carrier);
            drop((first_carrier, second_carrier, third_carrier));
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            let first_admitted = matches!(
                Pin::new(&mut first).poll_write(&mut cx, b"AAAAAAAA"),
                Poll::Ready(Ok(8))
            );
            let second_admitted = matches!(
                Pin::new(&mut second).poll_write(&mut cx, b"BBBBBBBB"),
                Poll::Ready(Ok(8))
            );
            let full = credit.available_permits() == 0 && carrier.writer.capacity() == 0;
            let blocked = Pin::new(&mut third).poll_write(&mut cx, b"C").is_pending();
            let WriterCommand {
                state,
                data,
                done,
                _bytes,
                ..
            } = commands.try_recv().unwrap();
            let fifo_first = state.id == 2 && data.as_ref() == b"AAAAAAAA";
            done.send(Ok(())).unwrap(); // First send completes; retained payload credit does not.
            let first_flushed = matches!(
                Pin::new(&mut first).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            );
            let still_blocked = Pin::new(&mut third).poll_write(&mut cx, b"C").is_pending()
                && credit.available_permits() == 0;
            drop((_bytes, state, data)); // Simulated actor retirement / ACK, not a fake extra queue.
            let resumed = matches!(
                Pin::new(&mut third).poll_write(&mut cx, b"C"),
                Poll::Ready(Ok(1))
            );
            let queued_second = commands.try_recv().unwrap();
            let queued_third = commands.try_recv().unwrap();
            let fifo_rest = queued_second.state.id == 3
                && queued_second.data.as_ref() == b"BBBBBBBB"
                && queued_third.state.id == 4
                && queued_third.data.as_ref() == b"C"
                && credit.available_permits() == 7;
            let flush_pending = Pin::new(&mut second).poll_flush(&mut cx).is_pending();
            client.shutdown().await;
            let stop_error = matches!(Pin::new(&mut second).poll_flush(&mut cx),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe);
            drop((
                first,
                second,
                third,
                queued_second,
                queued_third,
                commands,
                carrier,
                client,
            ));
            let reclaimed = credit.available_permits();
            let calls = peer.calls.load(Ordering::Acquire);
            peer.stop().await;
            (
                same_carrier,
                first_admitted,
                second_admitted,
                full,
                blocked,
                fifo_first,
                first_flushed,
                still_blocked,
                resumed,
                fifo_rest,
                flush_pending,
                stop_error,
                reclaimed,
                calls,
            )
        })
        .await;
    assert!(probe.snapshot().is_idle());
    let (
        same_carrier,
        first_admitted,
        second_admitted,
        full,
        blocked,
        fifo_first,
        first_flushed,
        still_blocked,
        resumed,
        fifo_rest,
        flush_pending,
        stop_error,
        reclaimed,
        calls,
    ) = outcome;
    assert!(same_carrier && first_admitted && second_admitted);
    assert!(full && blocked && fifo_first);
    assert!(
        first_flushed && still_blocked,
        "first-send does not retire the original payload permits"
    );
    assert!(resumed && fifo_rest);
    assert!(flush_pending && stop_error);
    assert_eq!(reclaimed, CREDIT);
    assert_eq!(
        calls, 0,
        "the real pool seam must remain entirely in memory"
    );
}

// Two real registry carriers with controlled live State ownership; no IO or driver.
fn install_counted(
    client: &Client,
    carrier_id: u64,
    business: Business,
    active: u32,
) -> (Arc<Carrier>, mpsc::Receiver<WriterCommand>) {
    let mut shared = Shared::output_test_shared(client.cancel.child_token());
    let settings = Arc::get_mut(&mut shared).unwrap();
    settings.udp = client.factory.config.transport == MieruTransport::Udp;
    settings.business = client.pool(business);
    for id in 1..=active {
        let state = State::new(id, CREDIT, &shared.cancel, shared.activity.clone());
        state.opened.store(true, Ordering::Release);
        shared.sessions.lock().unwrap().insert(id, state);
    }
    let (writer, receiver) = mpsc::channel(WRITER_COMMANDS);
    let carrier = Arc::new(Carrier {
        shared,
        writer,
        bytes: Arc::new(Semaphore::new(CREDIT)),
    });
    client
        .registry
        .lock()
        .unwrap()
        .carriers
        .insert(carrier_id, carrier.clone());
    (carrier, receiver)
}

fn choose_bucket(
    client: &Client,
    business: Business,
    bucket: usize,
) -> (Option<Reservation>, usize) {
    let mut observed_weight = 0;
    let selected = client
        .reserve_reusable(business, |weight| {
            observed_weight = weight;
            bucket
        })
        .unwrap();
    (selected, observed_weight)
}

#[tokio::test]
async fn least_load_uses_live_sessions_in_both_udp_low_pools() {
    let probe = ResourceProbe::default();
    let observed = probe
        .scope(async {
            let mut observed = Vec::new();
            for business in [Business::TcpConnect, Business::UdpAssociate] {
                let peer = Peer::new(false);
                let mut settings = config(MieruHandshake::Standard);
                settings.transport = MieruTransport::Udp;
                settings.multiplexing = MieruMultiplexing::Low;
                let client =
                    Client::new(&settings, UpstreamPath::proxy(peer.clone()), CREDIT).unwrap();
                let (busy, busy_rx) = install_counted(&client, 1, business, 3);
                let (light, light_rx) = install_counted(&client, 2, business, 1);
                // The sole two eligible carriers occupy the original two reuse buckets.
                // Before GREEN, one bucket selects busy regardless of HashMap order.
                for bucket in 0..2 {
                    let (selected, weight) = choose_bucket(&client, business, bucket);
                    observed.push((
                        "selected fewer live sessions",
                        weight == 2 && selected.as_ref().is_some_and(|r| Arc::ptr_eq(&r.0, &light)),
                    ));
                    drop(selected);
                }
                client.shutdown().await;
                drop((client, busy, light, busy_rx, light_rx));
                observed.push(("no physical IO", peer.calls.load(Ordering::Acquire) == 0));
                peer.stop().await;
            }
            observed
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (name, passed) in observed {
        assert!(passed, "{name}");
    }
}

#[tokio::test]
async fn least_load_counts_reservations_until_state_publication() {
    let probe = ResourceProbe::default();
    let observed = probe
        .scope(async {
            let peer = Peer::new(false);
            let mut settings = config(MieruHandshake::Standard);
            settings.transport = MieruTransport::Udp;
            settings.multiplexing = MieruMultiplexing::Low;
            let client = Client::new(&settings, UpstreamPath::proxy(peer.clone()), CREDIT).unwrap();
            let (first, first_rx) = install_counted(&client, 1, Business::UdpAssociate, 1);
            let (second, second_rx) = install_counted(&client, 2, Business::UdpAssociate, 1);
            // Establish the pending owner through the production picker, not a fake counter.
            let (held, _) = choose_bucket(&client, Business::UdpAssociate, 0);
            let held = held.unwrap();
            let other = if Arc::ptr_eq(&held.0, &first) {
                second.clone()
            } else {
                first.clone()
            };
            let mut observed = Vec::new();
            for bucket in 0..2 {
                let (selected, weight) = choose_bucket(&client, Business::UdpAssociate, bucket);
                observed.push((
                    "pending reservation changes admission",
                    weight == 2 && selected.as_ref().is_some_and(|r| Arc::ptr_eq(&r.0, &other)),
                ));
                drop(selected);
            }
            // Match open(): publish a State before dropping the corresponding reservation.
            let published = State::new(
                2,
                CREDIT,
                &held.0.shared.cancel,
                held.0.shared.activity.clone(),
            );
            held.0.shared.sessions.lock().unwrap().insert(2, published);
            drop(held);
            for bucket in 0..2 {
                let (selected, weight) = choose_bucket(&client, Business::UdpAssociate, bucket);
                observed.push((
                    "published state keeps the load",
                    weight == 2 && selected.as_ref().is_some_and(|r| Arc::ptr_eq(&r.0, &other)),
                ));
                drop(selected);
            }
            client.shutdown().await;
            drop((client, first, second, first_rx, second_rx, other));
            observed.push(("no physical IO", peer.calls.load(Ordering::Acquire) == 0));
            peer.stop().await;
            observed
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (name, passed) in observed {
        assert!(passed, "{name}");
    }
}

#[tokio::test]
async fn least_load_keeps_random_ties_new_bucket_and_other_modes() {
    let probe = ResourceProbe::default();
    let observed = probe
        .scope(async {
            let mut observed = Vec::new();
            for (transport, level, business, tied) in [
                (
                    MieruTransport::Udp,
                    MieruMultiplexing::Low,
                    Business::UdpAssociate,
                    true,
                ),
                (
                    MieruTransport::Udp,
                    MieruMultiplexing::Low,
                    Business::TcpConnect,
                    true,
                ),
                (
                    MieruTransport::Tcp,
                    MieruMultiplexing::Low,
                    Business::UdpAssociate,
                    false,
                ),
                (
                    MieruTransport::Tcp,
                    MieruMultiplexing::Middle,
                    Business::TcpConnect,
                    false,
                ),
                (
                    MieruTransport::Tcp,
                    MieruMultiplexing::High,
                    Business::TcpConnect,
                    false,
                ),
                (
                    MieruTransport::Udp,
                    MieruMultiplexing::Middle,
                    Business::TcpConnect,
                    false,
                ),
                (
                    MieruTransport::Udp,
                    MieruMultiplexing::High,
                    Business::TcpConnect,
                    false,
                ),
                (
                    MieruTransport::Tcp,
                    MieruMultiplexing::Off,
                    Business::TcpConnect,
                    false,
                ),
                (
                    MieruTransport::Udp,
                    MieruMultiplexing::Off,
                    Business::TcpConnect,
                    false,
                ),
            ] {
                let peer = Peer::new(false);
                let mut settings = config(MieruHandshake::Standard);
                settings.transport = transport;
                settings.multiplexing = level;
                let client =
                    Client::new(&settings, UpstreamPath::proxy(peer.clone()), CREDIT).unwrap();
                let (first, first_rx) =
                    install_counted(&client, 1, business, if tied { 1 } else { 3 });
                let (second, second_rx) = install_counted(&client, 2, business, 1);
                // Both constructed carriers are eligible, with no disable/close flags.
                // Registry iteration gives the original bucket order; no sorting/filter copy.
                let order: Vec<_> = client
                    .registry
                    .lock()
                    .unwrap()
                    .carriers
                    .values()
                    .cloned()
                    .collect();
                if level == MieruMultiplexing::Off {
                    let (selected, weight) = choose_bucket(&client, business, 0);
                    observed.push(("OFF always new", weight == 0 && selected.is_none()));
                    drop(selected);
                } else {
                    for (index, expected) in order.iter().enumerate() {
                        let (selected, weight) =
                            choose_bucket(&client, business, index * client.factor);
                        observed.push((
                            "original tie or unaffected bucket",
                            weight == 2 * client.factor
                                && selected
                                    .as_ref()
                                    .is_some_and(|r| Arc::ptr_eq(&r.0, expected)),
                        ));
                        drop(selected);
                    }
                    let (selected, weight) = choose_bucket(&client, business, 2 * client.factor);
                    observed.push((
                        "original new-carrier bucket",
                        weight == 2 * client.factor && selected.is_none(),
                    ));
                    drop(selected);
                }
                client.shutdown().await;
                drop((client, first, second, first_rx, second_rx, order));
                observed.push(("no physical IO", peer.calls.load(Ordering::Acquire) == 0));
                peer.stop().await;
            }
            observed
        })
        .await;
    assert!(probe.snapshot().is_idle());
    for (name, passed) in observed {
        assert!(passed, "{name}");
    }
}
