//! QUIC metadata on a single already-protected DIRECT UDP socket.
//! No codecs or proxy hops delegate this lease.
use super::{DatagramBudget, PhysicalQuicLease, Shared, linux_udp::SocketState};
use quinn::{
    UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll, Wake, Waker, ready},
};
use tokio::{io::Interest, sync::Notify};
use tokio_util::sync::ReusableBoxFuture;

#[cfg(all(test, feature = "tun"))]
#[path = "physical_gate.rs"]
mod gate;

const MAX_SEGMENTS: usize = 10;
const MAX_BATCH_BYTES: usize = 65_507;
type Io = Arc<crate::dialer::PhysicalDatagram>;
pub(super) type Retirement = Arc<Lease<Io>>;

// Every retained socket/poller owns this revocable slot, never the fd itself.
// A generic value permits a memory-only destructor/registration regression.
pub(super) struct Lease<T> {
    value: RwLock<Option<T>>,
    ready: Arc<Ready>,
}
struct Ready(Notify);
impl Wake for Ready {
    fn wake(self: Arc<Self>) {
        self.0.notify_waiters();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_waiters();
    }
}
impl<T> Lease<T> {
    fn new(value: T) -> Arc<Self> {
        Arc::new(Self {
            value: RwLock::new(Some(value)),
            ready: Arc::new(Ready(Notify::new())),
        })
    }
    pub(super) fn retire(&self) {
        self.value.write().unwrap().take();
        self.ready.0.notify_waiters();
    }
}

pub(super) struct Socket {
    io: Retirement,
    state: SocketState,
    settings: crate::config::QuicSocketSettings,
    peer: SocketAddr,
    budget: DatagramBudget,
    shared: Arc<Shared>,
    // One reusable packet plus the same oversize-detection byte used by DIRECT.
    // Allocate only when the protected socket is actually readable.
    receive: Mutex<Vec<u8>>,
}
impl Socket {
    pub(super) fn new(
        lease: PhysicalQuicLease,
        peer: SocketAddr,
        budget: DatagramBudget,
        shared: Arc<Shared>,
    ) -> io::Result<Option<Self>> {
        let Some(state) = SocketState::new(&lease.socket, lease.settings)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            io: Lease::new(lease.socket),
            state,
            settings: lease.settings,
            peer,
            budget,
            shared,
            receive: Mutex::new(Vec::new()),
        }))
    }
    pub(super) fn retirement(&self) -> Retirement {
        self.io.clone()
    }
    fn check_open(&self) -> io::Result<()> {
        let state = self.shared.state.lock().unwrap();
        if state.closed {
            Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into())
        } else {
            Ok(())
        }
    }
    pub(super) fn transmit_segments(&self) -> usize {
        if self.settings.disable_gso {
            1
        } else {
            self.state
                .max_gso_segments()
                .clamp(1, MAX_SEGMENTS)
                .min((MAX_BATCH_BYTES / usize::from(self.budget.transmit())).max(1))
        }
    }
    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io
            .value
            .read()
            .unwrap()
            .as_ref()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .local_addr()
    }
    pub(super) fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
    pub(super) fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.check_open()?;
        let count = validate_transmit(
            self.peer,
            self.budget.transmit(),
            if self.settings.disable_gso {
                1
            } else {
                MAX_SEGMENTS.min((MAX_BATCH_BYTES / usize::from(self.budget.transmit())).max(1))
            },
            transmit,
        )?;
        let transmit = Transmit {
            destination: transmit.destination,
            ecn: if self.settings.disable_ecn {
                None
            } else {
                transmit.ecn
            },
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            // Explicit source overrides never escape physical binding policy.
            src_ip: None,
        };
        // PMTU probe failures and unambiguous GSO-capability failures are
        // accepted as packet losses for Quinn's normal ACK/retransmit logic.
        // Never replay a possibly accepted prefix or hide address/policy/ECN errors.
        let lease = self.io.value.read().unwrap();
        let io = lease.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        match io.try_io(Interest::WRITABLE, || self.state.try_send(io, &transmit)) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {}
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP)
                ) && transmit.segment_size.is_some()
                    && transmit.ecn.is_none()
                    && self.state.max_gso_segments() == 1 => {}
            Err(error) => return Err(error),
        }
        self.shared.state.lock().unwrap().stats.sent += count;
        Ok(())
    }
    pub(super) fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || metadata.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        self.shared.reader.register(cx.waker());
        for _ in 0..crate::limits::IO_POLL_BUDGET {
            self.check_open()?;
            let lease = self.io.value.read().unwrap();
            let io = lease.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
            ready!(io.poll_recv_ready(cx))?;
            let mut scratch = self.receive.lock().unwrap();
            let required = usize::from(self.budget.receive()) + 1;
            if scratch.len() < required {
                scratch.resize(required, 0);
            }
            let mut meta = [RecvMeta::default()];
            match io.try_io(Interest::READABLE, || {
                self.state
                    .recv(io, &mut [IoSliceMut::new(&mut scratch)], &mut meta)
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
                Ok(0) => continue,
                Ok(_) => {}
            }
            let mut meta = meta[0];
            if meta.addr != self.peer {
                self.shared.state.lock().unwrap().stats.rejected_source += 1;
                continue;
            }
            if !valid_receive(self.peer, self.budget.receive(), &meta) {
                self.shared.state.lock().unwrap().stats.rejected_oversize += 1;
                continue;
            }
            if buffers[0].len() < meta.len {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            buffers[0][..meta.len].copy_from_slice(&scratch[..meta.len]);
            if self.settings.disable_ecn {
                meta.ecn = None;
            }
            metadata[0] = meta;
            self.shared.state.lock().unwrap().stats.received += 1;
            return Poll::Ready(Ok(1));
        }
        // Source/oversize floods cannot monopolize the endpoint or defer Stop.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    pub(super) fn create_io_poller(&self) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            io: self.io.clone(),
            shared: self.shared.clone(),
            future: Mutex::new(ReusableBoxFuture::new(writable(
                self.io.clone(),
                self.shared.clone(),
                |io, cx| io.poll_send_ready(cx),
            ))),
        })
    }
}
fn validate_transmit(
    peer: SocketAddr,
    budget: u16,
    maximum: usize,
    transmit: &Transmit<'_>,
) -> io::Result<usize> {
    if transmit.destination != peer || transmit.src_ip.is_some() || transmit.contents.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let segment = transmit.segment_size.unwrap_or(transmit.contents.len());
    if segment == 0
        || segment > usize::from(budget)
        || (transmit.segment_size.is_some() && maximum == 1)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let count = transmit.contents.len().div_ceil(segment);
    // A non-segmented IPv6 datagram keeps its existing directional budget
    // (65,527 bytes). The conservative aggregate bound applies only to GSO.
    if count > maximum.clamp(1, MAX_SEGMENTS)
        || (transmit.segment_size.is_some()
            && transmit.contents.len() > (usize::from(budget) * MAX_SEGMENTS).min(MAX_BATCH_BYTES))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(count)
}
fn valid_receive(peer: SocketAddr, maximum: u16, meta: &RecvMeta) -> bool {
    meta.addr == peer && meta.len > 0 && meta.len <= usize::from(maximum) && meta.stride == meta.len
}

async fn writable<T: Send + Sync>(
    io: Arc<Lease<T>>,
    shared: Arc<Shared>,
    poll: fn(&T, &mut Context<'_>) -> Poll<io::Result<()>>,
) -> io::Result<()> {
    // Every poller owns shutdown and readiness waiters. Neither future retains
    // the physical IO across Pending; Stop wakes all of them.
    let changed = shared.changed.notified();
    tokio::pin!(changed);
    changed.as_mut().enable();
    {
        let state = shared.state.lock().unwrap();
        if state.closed {
            return Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into());
        }
    }
    loop {
        // All pollers register first. Tokio retains one common broadcast
        // waker, containing only this Notify and no physical socket reference.
        let ready = io.ready.0.notified();
        tokio::pin!(ready);
        ready.as_mut().enable();
        let result = {
            let value = io.value.read().unwrap();
            let value = value.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
            let waker = Waker::from(io.ready.clone());
            poll(value, &mut Context::from_waker(&waker))
        };
        if let Poll::Ready(result) = result {
            return result;
        }
        tokio::select! {
            () = changed.as_mut() => return Err(io::ErrorKind::BrokenPipe.into()),
            () = ready => {},
        }
    }
}
struct Writable {
    io: Retirement,
    shared: Arc<Shared>,
    future: Mutex<ReusableBoxFuture<'static, io::Result<()>>>,
}
impl std::fmt::Debug for Writable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PhysicalQuicWritable")
    }
}
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.writer.register(cx.waker());
        let state = self.shared.state.lock().unwrap();
        if state.closed {
            return Poll::Ready(Err(state.error.unwrap_or(io::ErrorKind::BrokenPipe).into()));
        }
        drop(state);
        let mut future = self.future.lock().unwrap();
        let result = future.poll(cx);
        if result.is_ready() {
            future.set(writable(self.io.clone(), self.shared.clone(), |io, cx| {
                io.poll_send_ready(cx)
            }));
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use quinn::udp::EcnCodepoint;
    use std::{
        future::Future,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    struct Probe {
        _owner: Arc<()>,
        ready: Arc<AtomicBool>,
        registered: Arc<Mutex<Option<Waker>>>,
        notify_during_registration: AtomicBool,
    }
    fn poll_probe(probe: &Probe, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        *probe.registered.lock().unwrap() = Some(cx.waker().clone());
        if probe
            .notify_during_registration
            .swap(false, Ordering::Relaxed)
        {
            probe.ready.store(true, Ordering::Relaxed);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if probe.ready.load(Ordering::Relaxed) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[tokio::test]
    async fn physical_quic_memory_revocation_releases_io_with_retained_broadcast_pollers() {
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let ready = Arc::new(AtomicBool::new(false));
        let registered = Arc::new(Mutex::new(None));
        let lease = Lease::new(Probe {
            _owner: owner,
            ready: ready.clone(),
            registered: registered.clone(),
            notify_during_registration: AtomicBool::new(false),
        });
        let shared = Arc::new(Shared::default());
        let first_wake = Arc::new(WakeCount::default());
        let second_wake = Arc::new(WakeCount::default());
        let first_waker = Waker::from(first_wake.clone());
        let second_waker = Waker::from(second_wake.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);
        let mut first = Box::pin(writable(lease.clone(), shared.clone(), poll_probe));
        let mut second = Box::pin(writable(lease.clone(), shared.clone(), poll_probe));
        assert!(first.as_mut().poll(&mut first_cx).is_pending());
        assert!(second.as_mut().poll(&mut second_cx).is_pending());
        ready.store(true, Ordering::Relaxed);
        registered.lock().unwrap().as_ref().unwrap().wake_by_ref();
        assert!(first_wake.0.load(Ordering::Relaxed) > 0);
        assert!(second_wake.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            first.as_mut().poll(&mut first_cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            second.as_mut().poll(&mut second_cx),
            Poll::Ready(Ok(()))
        ));

        // Pending waiters retain only the revocable slot, not its physical IO.
        ready.store(false, Ordering::Relaxed);
        let mut first = Box::pin(writable(lease.clone(), shared.clone(), poll_probe));
        let mut second = Box::pin(writable(lease.clone(), shared.clone(), poll_probe));
        assert!(first.as_mut().poll(&mut first_cx).is_pending());
        assert!(second.as_mut().poll(&mut second_cx).is_pending());
        lease.retire();
        assert!(weak.upgrade().is_none());
        for (future, cx) in [(&mut first, &mut first_cx), (&mut second, &mut second_cx)] {
            assert!(
                matches!(future.as_mut().poll(cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
        }

        // An immediate reactor wake between registration and Pending is kept.
        let lease = Lease::new(Probe {
            _owner: Arc::new(()),
            ready: Arc::new(AtomicBool::new(false)),
            registered: Arc::new(Mutex::new(None)),
            notify_during_registration: AtomicBool::new(true),
        });
        let mut waiter = Box::pin(writable(lease.clone(), shared.clone(), poll_probe));
        assert!(matches!(
            waiter.as_mut().poll(&mut first_cx),
            Poll::Ready(Ok(()))
        ));
        lease.retire();

        // A retained real poller may be polled repeatedly after retirement.
        let retired = Arc::new(Lease::<Io> {
            value: RwLock::new(None),
            ready: Arc::new(Ready(Notify::new())),
        });
        let mut poller = Box::pin(Writable {
            io: retired.clone(),
            shared: shared.clone(),
            future: Mutex::new(ReusableBoxFuture::new(writable(
                retired.clone(),
                shared.clone(),
                |io, cx| io.poll_send_ready(cx),
            ))),
        });
        for _ in 0..3 {
            assert!(
                matches!(poller.as_mut().poll_writable(&mut first_cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
        }
        let notification = retired.ready.0.notified();
        tokio::pin!(notification);
        assert!(notification.as_mut().poll(&mut first_cx).is_pending());
        let driver = super::super::DatagramDriver {
            shared,
            cancel: tokio_util::sync::CancellationToken::new(),
            task: None,
            physical: Some(retired.clone()),
        };
        drop(driver);
        assert!(notification.as_mut().poll(&mut first_cx).is_ready());
    }
    #[test]
    fn physical_quic_memory_concurrent_read_leases_delay_retirement_until_both_release() {
        use std::sync::mpsc::{RecvTimeoutError, sync_channel};

        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
        const STILL_HELD: std::time::Duration = std::time::Duration::from_millis(25);
        struct DropRecord {
            _owner: Arc<()>,
            dropped: Arc<AtomicUsize>,
        }
        impl Drop for DropRecord {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }

        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        let dropped = Arc::new(AtomicUsize::new(0));
        let lease = Lease::new(DropRecord {
            _owner: owner,
            dropped: dropped.clone(),
        });
        std::thread::scope(|scope| {
            let (entered_tx, entered_rx) = sync_channel(2);
            let (left_tx, left_rx) = sync_channel(2);
            let mut releases = Vec::with_capacity(2);
            let mut readers = Vec::with_capacity(2);
            for _ in 0..2 {
                let held = lease.clone();
                let entered = entered_tx.clone();
                let left = left_tx.clone();
                let (release_tx, release_rx) = sync_channel(1);
                releases.push(release_tx);
                readers.push(scope.spawn(move || {
                    let guard = held.value.read().unwrap();
                    assert!(guard.is_some());
                    entered.try_send(()).unwrap();
                    // A failed parent assertion drops the release sender;
                    // timeout/disconnection also releases the actual guard.
                    let release = release_rx.recv_timeout(DEADLINE);
                    drop(guard);
                    left.try_send(()).unwrap();
                    release.expect("read lease release deadline");
                }));
            }
            // Both notifications occur while the actual read guards are held.
            // This would time out if the lease still serialized its readers.
            entered_rx.recv_timeout(DEADLINE).unwrap();
            entered_rx.recv_timeout(DEADLINE).unwrap();
            assert!(matches!(
                lease.value.try_write(),
                Err(std::sync::TryLockError::WouldBlock)
            ));

            let (attempt_tx, attempt_rx) = sync_channel(1);
            let (done_tx, done_rx) = sync_channel(1);
            let retiring = lease.clone();
            let writer = scope.spawn(move || {
                attempt_tx.try_send(()).unwrap();
                retiring.retire();
                done_tx.try_send(()).unwrap();
            });
            attempt_rx.recv_timeout(DEADLINE).unwrap();
            assert!(matches!(
                done_rx.recv_timeout(STILL_HELD),
                Err(RecvTimeoutError::Timeout)
            ));
            assert_eq!(dropped.load(Ordering::SeqCst), 0);

            releases[0].try_send(()).unwrap();
            left_rx.recv_timeout(DEADLINE).unwrap();
            assert!(matches!(
                lease.value.try_write(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert!(matches!(
                done_rx.recv_timeout(STILL_HELD),
                Err(RecvTimeoutError::Timeout)
            ));
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            assert_eq!(weak.strong_count(), 1);

            releases[1].try_send(()).unwrap();
            left_rx.recv_timeout(DEADLINE).unwrap();
            done_rx.recv_timeout(DEADLINE).unwrap();
            for reader in readers {
                reader.join().unwrap();
            }
            writer.join().unwrap();
        });
        assert!(lease.value.read().unwrap().is_none());
        assert!(weak.upgrade().is_none());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        lease.retire();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn physical_quic_memory_transmit_limits_each_segment_peer_and_source_without_queues() {
        let peer = "192.0.2.1:443".parse().unwrap();
        let mut packet = Transmit {
            destination: peer,
            contents: &[1; 1201],
            ecn: Some(EcnCodepoint::Ect0),
            segment_size: Some(1200),
            src_ip: None,
        };
        assert_eq!(validate_transmit(peer, 1200, 8, &packet).unwrap(), 2);
        assert!(validate_transmit(peer, 1200, 1, &packet).is_err());
        packet.contents = &[1; 10 * 1200];
        assert_eq!(validate_transmit(peer, 1200, 64, &packet).unwrap(), 10);
        packet.contents = &[1; 10 * 1200 + 1];
        assert!(validate_transmit(peer, 1200, 64, &packet).is_err());
        packet.contents = &[1; 1200];
        packet.segment_size = None;
        assert_eq!(validate_transmit(peer, 1200, 1, &packet).unwrap(), 1);
        packet.src_ip = Some("192.0.2.2".parse().unwrap());
        assert!(validate_transmit(peer, 1200, 8, &packet).is_err());
        packet.src_ip = None;
        packet.destination.set_port(444);
        assert!(validate_transmit(peer, 1200, 8, &packet).is_err());
        packet.destination = peer;
        packet.segment_size = Some(0);
        assert!(validate_transmit(peer, 1200, 8, &packet).is_err());
    }
    #[test]
    fn physical_quic_memory_unsegmented_ipv6_preserves_directional_budget() {
        let peer = "[2001:db8::1]:443".parse().unwrap();
        let bytes = vec![1; 65_527];
        let mut packet = Transmit {
            destination: peer,
            contents: &bytes,
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        assert_eq!(validate_transmit(peer, 65_527, 1, &packet).unwrap(), 1);
        assert!(validate_transmit(peer, 65_507, 1, &packet).is_err());
        // The same payload is too large when advertised as an aggregate.
        packet.segment_size = Some(32_768);
        assert!(validate_transmit(peer, 65_527, 8, &packet).is_err());
        packet.contents = &bytes[..65_507];
        assert_eq!(validate_transmit(peer, 65_527, 8, &packet).unwrap(), 2);
    }
    #[test]
    fn physical_quic_memory_receive_requires_exact_peer_complete_packet_and_no_gro() {
        let peer = "[2001:db8::1]:443".parse().unwrap();
        let mut meta = RecvMeta {
            addr: peer,
            len: 1200,
            stride: 1200,
            ecn: Some(EcnCodepoint::Ce),
            dst_ip: Some("2001:db8::2".parse().unwrap()),
        };
        assert!(valid_receive(peer, 1200, &meta));
        meta.len += 1;
        assert!(!valid_receive(peer, 1200, &meta));
        meta.len = 1200;
        meta.stride = 600;
        assert!(!valid_receive(peer, 1200, &meta));
        meta.stride = 1200;
        meta.addr.set_port(444);
        assert!(!valid_receive(peer, 1200, &meta));
        meta.addr = peer;
        meta.len = 0;
        meta.stride = 0;
        assert!(!valid_receive(peer, 1200, &meta));
    }
}
