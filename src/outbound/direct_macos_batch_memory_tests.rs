use super::*;
use bytes::Bytes;
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Waker,
};

#[derive(Clone, Copy)]
enum Step {
    Accept,
    Pending,
    Error(io::ErrorKind),
    Short(usize),
}
#[derive(Default)]
struct Boundary {
    steps: VecDeque<Step>,
    attempts: Vec<(SocketAddr, usize, usize)>,
    emitted: Vec<u8>,
    waiter: Option<Waker>,
}
fn packets(peer: SocketAddr) -> Vec<Datagram> {
    (1..=4)
        .map(|marker| Datagram {
            remote: peer.into(),
            payload: Bytes::from(vec![marker; 1200]),
            sniffed_domain: None,
        })
        .collect()
}
fn operation(
    packets: Vec<Datagram>,
    boundary: Arc<Mutex<Boundary>>,
) -> crate::dispatch::OwnedDatagramBatchSend {
    send_with(packets, move |cx, payload, peer| {
        let mut boundary = boundary.lock().unwrap();
        boundary
            .attempts
            .push((peer, payload.as_ptr() as usize, payload.len()));
        match boundary.steps.pop_front().unwrap_or(Step::Accept) {
            Step::Accept => {
                boundary.emitted.push(payload[0]);
                Poll::Ready(Ok(payload.len()))
            }
            Step::Pending => {
                boundary.waiter = Some(cx.waker().clone());
                Poll::Pending
            }
            Step::Error(kind) => Poll::Ready(Err(kind.into())),
            Step::Short(length) => Poll::Ready(Ok(length)),
        }
    })
    .unwrap_or_else(|_| panic!("valid production-seam batch refused"))
}
fn poll(operation: &mut crate::dispatch::OwnedDatagramBatchSend) -> Poll<io::Result<usize>> {
    operation
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn macos_public_send_memory_full_four_keep_whole_payloads_and_ipv6_scope() {
    for peer in [
        "192.0.2.1:443".parse().unwrap(),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            123,
            7,
        )),
    ] {
        let packets = packets(peer);
        let expected: Vec<_> = packets
            .iter()
            .map(|packet| (peer, packet.payload.as_ptr() as usize, packet.payload.len()))
            .collect();
        let boundary = Arc::new(Mutex::new(Boundary::default()));
        let mut operation = operation(packets, boundary.clone());
        assert!(matches!(poll(&mut operation), Poll::Ready(Ok(4))));
        drop(operation);
        let state = boundary.lock().unwrap();
        assert_eq!(state.attempts, expected);
        assert_eq!(state.emitted, [1, 2, 3, 4]);
    }
}

#[test]
fn macos_public_send_memory_zero_prefix_pending_keeps_waker_and_never_replays() {
    let boundary = Arc::new(Mutex::new(Boundary {
        steps: [Step::Pending, Step::Pending].into(),
        ..Default::default()
    }));
    let mut operation = operation(packets("192.0.2.1:443".parse().unwrap()), boundary.clone());
    for _ in 0..2 {
        assert!(poll(&mut operation).is_pending());
        let state = boundary.lock().unwrap();
        assert!(state.emitted.is_empty());
        assert!(state.waiter.is_some());
        state.waiter.as_ref().unwrap().wake_by_ref();
    }
    assert!(matches!(poll(&mut operation), Poll::Ready(Ok(4))));
    drop(operation);
    let state = boundary.lock().unwrap();
    assert_eq!(state.attempts.len(), 6);
    assert_eq!(state.emitted, [1, 2, 3, 4]);
}

#[test]
fn macos_public_send_memory_positive_prefix_returns_before_pending_and_preserves_suffix() {
    for prefix in [1, 2] {
        let mut packets = packets("192.0.2.1:443".parse().unwrap());
        let mut steps = VecDeque::new();
        steps.extend(std::iter::repeat_n(Step::Accept, prefix));
        steps.push_back(Step::Pending);
        let boundary = Arc::new(Mutex::new(Boundary {
            steps,
            ..Default::default()
        }));
        let mut first = operation(packets.clone(), boundary.clone());
        assert!(matches!(poll(&mut first), Poll::Ready(Ok(actual)) if actual == prefix));
        drop(first);
        assert_eq!(boundary.lock().unwrap().emitted.len(), prefix);
        drop(packets.drain(..prefix));
        let mut suffix = operation(packets, boundary.clone());
        assert!(matches!(poll(&mut suffix), Poll::Ready(Ok(actual)) if actual == 4 - prefix));
        drop(suffix);
        assert_eq!(boundary.lock().unwrap().emitted, [1, 2, 3, 4]);
    }
}

#[test]
fn macos_public_send_memory_fatal_or_short_after_a_prefix_never_replays_or_hides_error() {
    for prefix in [0, 1, 2] {
        for last in [
            Step::Error(io::ErrorKind::Interrupted),
            Step::Error(io::ErrorKind::PermissionDenied),
            Step::Error(io::ErrorKind::ConnectionReset),
            Step::Short(0),
            Step::Short(1199),
            Step::Short(1201),
        ] {
            let mut steps = VecDeque::new();
            steps.extend(std::iter::repeat_n(Step::Accept, prefix));
            steps.push_back(last);
            let boundary = Arc::new(Mutex::new(Boundary {
                steps,
                ..Default::default()
            }));
            let mut operation =
                operation(packets("192.0.2.1:443".parse().unwrap()), boundary.clone());
            let Poll::Ready(Err(error)) = poll(&mut operation) else {
                panic!("a real fatal/short boundary must remain a terminal error");
            };
            let expected = match last {
                Step::Error(kind) => kind,
                _ => io::ErrorKind::InvalidData,
            };
            assert_eq!(error.kind(), expected);
            drop(operation);
            let state = boundary.lock().unwrap();
            assert_eq!(state.attempts.len(), prefix + 1);
            assert_eq!(state.emitted.len(), prefix);
        }
    }
}

struct CaptureLease(Arc<AtomicUsize>);
impl Drop for CaptureLease {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn macos_public_send_memory_pending_drop_releases_owned_capture_without_more_io() {
    let drops = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let lease = CaptureLease(drops.clone());
    let observed_calls = calls.clone();
    let mut operation = send_with(packets("192.0.2.1:443".parse().unwrap()), move |_, _, _| {
        let _held = &lease;
        observed_calls.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    })
    .unwrap_or_else(|_| panic!("valid production-seam batch refused"));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(poll(&mut operation).is_pending());
    drop(operation);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn macos_public_send_memory_invalid_admission_returns_untouched_packets_without_io() {
    let peer = "192.0.2.1:443".parse().unwrap();
    let mut cases = vec![Vec::new(), packets(peer).into_iter().take(1).collect()];
    let mut mixed = packets(peer);
    mixed[1].remote = "192.0.2.2:443".parse::<SocketAddr>().unwrap().into();
    cases.push(mixed);
    let mut oversized = packets(peer);
    oversized[0].payload = Bytes::from(vec![0; 8193]);
    cases.push(oversized);
    let mut too_many = packets(peer);
    too_many.push(packets(peer).remove(0));
    cases.push(too_many);
    let mut empty = packets(peer);
    empty[0].payload = Bytes::new();
    cases.push(empty);
    let mut sniffed = packets(peer);
    sniffed[0].sniffed_domain = Some("invalid.example".into());
    cases.push(sniffed);
    cases.push(packets("0.0.0.0:443".parse().unwrap()));
    cases.push(packets("192.0.2.1:0".parse().unwrap()));
    cases.push(packets("224.0.0.1:443".parse().unwrap()));
    let calls = Arc::new(AtomicUsize::new(0));
    for batch in cases {
        let expected: Vec<_> = batch
            .iter()
            .map(|packet| {
                (
                    packet.remote.clone(),
                    packet.payload.as_ptr(),
                    packet.payload.len(),
                )
            })
            .collect();
        let observed = calls.clone();
        let Err(returned) = send_with(batch, move |_, _, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(1200))
        }) else {
            panic!("invalid batch reached a physical operation");
        };
        let actual: Vec<_> = returned
            .iter()
            .map(|packet| {
                (
                    packet.remote.clone(),
                    packet.payload.as_ptr(),
                    packet.payload.len(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[cfg(any(
    feature = "outbound-masque",
    feature = "outbound-wireguard",
    feature = "outbound-tuic"
))]
fn connected_operation(
    packets: Vec<Datagram>,
    peer: SocketAddr,
    boundary: Arc<Mutex<Boundary>>,
) -> crate::dispatch::OwnedDatagramBatchSend {
    send_connected_with(packets, peer, move |cx, payload| {
        let mut boundary = boundary.lock().unwrap();
        boundary
            .attempts
            .push((peer, payload.as_ptr() as usize, payload.len()));
        match boundary.steps.pop_front().unwrap_or(Step::Accept) {
            Step::Accept => {
                boundary.emitted.push(payload[0]);
                Poll::Ready(Ok(payload.len()))
            }
            Step::Pending => {
                boundary.waiter = Some(cx.waker().clone());
                Poll::Pending
            }
            Step::Error(kind) => Poll::Ready(Err(kind.into())),
            Step::Short(length) => Poll::Ready(Ok(length)),
        }
    })
    .unwrap_or_else(|_| panic!("valid connected production batch refused"))
}

#[cfg(any(
    feature = "outbound-masque",
    feature = "outbound-wireguard",
    feature = "outbound-tuic"
))]
#[test]
fn macos_public_send_memory_connected_prefix_whole_payload_and_terminal_errors() {
    for peer in [
        "192.0.2.1:443".parse().unwrap(),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            123,
            7,
        )),
    ] {
        for prefix in 0..4 {
            for last in [
                Step::Pending,
                Step::Error(io::ErrorKind::PermissionDenied),
                Step::Short(1199),
            ] {
                let batch = packets(peer);
                let expected: Vec<_> = batch
                    .iter()
                    .take(prefix + 1)
                    .map(|packet| (peer, packet.payload.as_ptr() as usize, packet.payload.len()))
                    .collect();
                let mut steps = VecDeque::new();
                steps.extend(std::iter::repeat_n(Step::Accept, prefix));
                steps.push_back(last);
                let boundary = Arc::new(Mutex::new(Boundary {
                    steps,
                    ..Default::default()
                }));
                let mut operation = connected_operation(batch.clone(), peer, boundary.clone());
                match last {
                    Step::Pending if prefix == 0 => {
                        assert!(poll(&mut operation).is_pending());
                        assert!(boundary.lock().unwrap().waiter.is_some());
                    }
                    Step::Pending => assert!(
                        matches!(poll(&mut operation), Poll::Ready(Ok(actual)) if actual == prefix)
                    ),
                    Step::Error(kind) => assert!(
                        matches!(poll(&mut operation), Poll::Ready(Err(error)) if error.kind() == kind)
                    ),
                    Step::Short(_) => assert!(
                        matches!(poll(&mut operation), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData)
                    ),
                    Step::Accept => unreachable!(),
                }
                {
                    let state = boundary.lock().unwrap();
                    assert_eq!(state.attempts, expected);
                    assert_eq!(state.emitted.len(), prefix);
                }
                drop(operation);
                if matches!(last, Step::Pending) {
                    let mut suffix = batch;
                    drop(suffix.drain(..prefix));
                    if suffix.len() == 1 {
                        let original_pointer = suffix[0].payload.as_ptr();
                        let returned = send_connected_with(suffix, peer, |_, _| {
                            panic!(
                                "the generic owner must send a singleton through its original path"
                            )
                        })
                        .err()
                        .unwrap();
                        assert_eq!(returned[0].payload.as_ptr(), original_pointer);
                        assert_eq!(boundary.lock().unwrap().emitted, [1, 2, 3]);
                    } else {
                        let mut operation = connected_operation(suffix, peer, boundary.clone());
                        assert!(
                            matches!(poll(&mut operation), Poll::Ready(Ok(actual)) if actual == 4 - prefix)
                        );
                        drop(operation);
                        assert_eq!(boundary.lock().unwrap().emitted, [1, 2, 3, 4]);
                    }
                }
            }
        }
    }
}

#[cfg(any(
    feature = "outbound-masque",
    feature = "outbound-wireguard",
    feature = "outbound-tuic"
))]
#[test]
fn macos_public_send_memory_connected_peer_rejection_and_pending_capture_drop() {
    let peer = SocketAddr::V6(std::net::SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        443,
        123,
        7,
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    for other in [
        "192.0.2.1:443".parse().unwrap(),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            123,
            8,
        )),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            124,
            7,
        )),
    ] {
        let batch = packets(other);
        let pointers: Vec<_> = batch.iter().map(|packet| packet.payload.as_ptr()).collect();
        let observed = calls.clone();
        let Err(returned) = send_connected_with(batch, peer, move |_, _| {
            observed.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(1200))
        }) else {
            panic!("mismatched connected peer reached IO");
        };
        assert_eq!(
            returned
                .iter()
                .map(|packet| packet.payload.as_ptr())
                .collect::<Vec<_>>(),
            pointers
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let drops = Arc::new(AtomicUsize::new(0));
    let held = CaptureLease(drops.clone());
    let mut operation = send_connected_with(packets(peer), peer, move |_, _| {
        let _held = &held;
        Poll::Pending
    })
    .unwrap_or_else(|_| panic!("valid connected batch refused"));
    assert!(poll(&mut operation).is_pending());
    drop(operation);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
