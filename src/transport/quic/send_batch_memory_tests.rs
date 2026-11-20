//! Real generic owner with an injected physical send boundary; no sockets.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Semaphore, mpsc};

struct Control {
    batches: Mutex<Vec<Vec<u8>>>,
    emitted: Mutex<Vec<u8>>,
    outcomes: Mutex<VecDeque<Result<usize, io::ErrorKind>>>,
    credit: Semaphore,
    active: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
    singles: AtomicUsize,
    close_error: AtomicBool,
    pointers: Mutex<Vec<(u8, usize)>>,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            batches: Mutex::default(),
            emitted: Mutex::default(),
            outcomes: Mutex::default(),
            credit: Semaphore::new(0),
            active: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            singles: AtomicUsize::new(0),
            close_error: AtomicBool::new(false),
            pointers: Mutex::default(),
        }
    }
}
struct SendLease(Arc<Control>);
impl Drop for SendLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}
struct MemoryPhysical {
    control: Arc<Control>,
    input: mpsc::Receiver<Datagram>,
}
impl Drop for MemoryPhysical {
    fn drop(&mut self) {
        self.control.drops.fetch_add(1, Ordering::Relaxed);
    }
}
#[async_trait::async_trait]
impl DatagramTransport for MemoryPhysical {
    fn supports_shared_destinations(&self) -> bool {
        false
    }
    fn send_batch_owned(
        &mut self,
        packets: Vec<Datagram>,
    ) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
        let control = self.control.clone();
        control.active.fetch_add(1, Ordering::Relaxed);
        let lease = SendLease(control.clone());
        Ok(Box::pin(async move {
            let _lease = lease;
            let sequence: Vec<_> = packets.iter().map(|packet| packet.payload[0]).collect();
            control.batches.lock().unwrap().push(sequence.clone());
            control.pointers.lock().unwrap().extend(
                packets
                    .iter()
                    .map(|packet| (packet.payload[0], packet.payload.as_ptr() as usize)),
            );
            control.credit.acquire().await.unwrap().forget();
            let count = control
                .outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(sequence.len()))
                .map_err(io::Error::from)?;
            if count <= sequence.len() {
                control
                    .emitted
                    .lock()
                    .unwrap()
                    .extend_from_slice(&sequence[..count]);
            }
            Ok(count)
        }))
    }
    fn send_owned(
        &mut self,
        packet: Datagram,
    ) -> Result<crate::dispatch::OwnedDatagramSend, Datagram> {
        let control = self.control.clone();
        control.active.fetch_add(1, Ordering::Relaxed);
        let lease = SendLease(control.clone());
        Ok(Box::pin(async move {
            let _lease = lease;
            control.singles.fetch_add(1, Ordering::Relaxed);
            control.credit.acquire().await.unwrap().forget();
            control.emitted.lock().unwrap().push(packet.payload[0]);
            Ok(())
        }))
    }
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        panic!("already open memory path")
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.input
            .recv()
            .await
            .ok_or(DispatchError::ConnectionRefused)
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        assert_eq!(
            self.control.active.load(Ordering::Relaxed),
            0,
            "send lease survived close"
        );
        self.control.closes.fetch_add(1, Ordering::Relaxed);
        if self.control.close_error.load(Ordering::Relaxed) {
            Err(DispatchError::TimedOut)
        } else {
            Ok(())
        }
    }
}
fn fixture() -> (
    Arc<DatagramSocket>,
    DatagramDriver,
    Arc<Control>,
    mpsc::Sender<Datagram>,
) {
    let control = Arc::new(Control::default());
    let (input, receive) = mpsc::channel(4);
    let (socket, driver) = attach(
        Box::new(MemoryPhysical {
            control: control.clone(),
            input: receive,
        }),
        "192.0.2.1:443".parse().unwrap(),
        DatagramBudget::new(1400, 1400),
    )
    .unwrap();
    (socket, driver, control, input)
}
fn enqueue(socket: &DatagramSocket, sequence: u8) -> io::Result<()> {
    socket.try_send(&quinn::udp::Transmit {
        destination: socket.peer,
        ecn: None,
        contents: &[sequence; 1200],
        segment_size: None,
        src_ip: None,
    })
}
async fn until(mut predicate: impl FnMut() -> bool) -> io::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut.into())
}

#[tokio::test]
async fn macos_quic_batch_memory_partial_prefix_is_emitted_once_in_fifo_order() {
    let (socket, driver, control, _input) = fixture();
    control
        .outcomes
        .lock()
        .unwrap()
        .extend([Ok(2), Ok(1), Ok(2)]);
    for sequence in 0..5 {
        enqueue(&socket, sequence).unwrap();
    }
    let pointers: Vec<_> = socket
        .shared
        .state
        .lock()
        .unwrap()
        .outgoing
        .iter()
        .map(|payload| payload.as_ptr() as usize)
        .collect();
    control.credit.add_permits(5);
    let result = until(|| socket.stats().sent == 5).await;
    let stopped = driver.stop().await;
    result.unwrap();
    stopped.unwrap();
    assert_eq!(*control.emitted.lock().unwrap(), [0, 1, 2, 3, 4]);
    assert_eq!(
        *control.batches.lock().unwrap(),
        [vec![0, 1, 2, 3], vec![2, 3, 4], vec![3, 4]]
    );
    assert_eq!(control.singles.load(Ordering::Relaxed), 0);
    assert_eq!(control.closes.load(Ordering::Relaxed), 1);
    assert_eq!(control.drops.load(Ordering::Relaxed), 1);
    for &(sequence, pointer) in control.pointers.lock().unwrap().iter() {
        assert_eq!(
            pointer,
            pointers[usize::from(sequence)],
            "batch copied a queued payload"
        );
    }
}

#[tokio::test]
async fn macos_quic_batch_memory_pending_prefix_keeps_queue_capacity_and_rx_live() {
    let (socket, driver, control, input) = fixture();
    for sequence in 0..32 {
        enqueue(&socket, sequence).unwrap();
    }
    let result = async {
        until(|| {
            control.singles.load(Ordering::Relaxed) > 0
                || !control.batches.lock().unwrap().is_empty()
        })
        .await?;
        let full = enqueue(&socket, 32).err().map(|error| error.kind());
        control.outcomes.lock().unwrap().push_back(Ok(2));
        control.credit.add_permits(1);
        until(|| socket.stats().sent >= 1).await?;
        let sent_prefix = socket.stats().sent;
        let first_slot = enqueue(&socket, 32).is_ok();
        let second_slot = enqueue(&socket, 33).is_ok();
        let still_full = enqueue(&socket, 34).err().map(|error| error.kind());
        input
            .send(Datagram {
                remote: socket.peer.into(),
                payload: Bytes::from_static(b"reply"),
                sniffed_domain: None,
            })
            .await
            .unwrap();
        until(|| socket.stats().received == 1).await?;
        let context = &mut Context::from_waker(std::task::Waker::noop());
        let prefix_done = socket.poll_transmitted(context, 2).is_ready();
        let suffix_pending = socket.poll_transmitted(context, 3).is_pending();
        Ok::<_, io::Error>((
            full,
            still_full,
            sent_prefix,
            first_slot,
            second_slot,
            prefix_done,
            suffix_pending,
        ))
    }
    .await;
    let stopped = driver.stop().await;
    let (full, still_full, sent_prefix, first_slot, second_slot, prefix_done, suffix_pending) =
        result.unwrap();
    stopped.unwrap();
    assert_eq!(
        (full, still_full),
        (
            Some(io::ErrorKind::WouldBlock),
            Some(io::ErrorKind::WouldBlock)
        )
    );
    assert_eq!(sent_prefix, 2);
    assert!(first_slot && second_slot);
    assert!(prefix_done && suffix_pending);
    assert_eq!(control.active.load(Ordering::Relaxed), 0);
    assert_eq!(control.closes.load(Ordering::Relaxed), 1);
    assert_eq!(control.drops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn macos_quic_batch_memory_fatal_and_invalid_counts_close_without_single_replay() {
    for outcome in [
        Err(io::ErrorKind::ConnectionReset),
        Err(io::ErrorKind::PermissionDenied),
        Ok(0),
        Ok(5),
    ] {
        let (socket, driver, control, _input) = fixture();
        control.outcomes.lock().unwrap().push_back(outcome);
        for sequence in 0..4 {
            enqueue(&socket, sequence).unwrap();
        }
        control.credit.add_permits(1);
        let completed =
            until(|| socket.stats().sent > 0 || control.closes.load(Ordering::Relaxed) == 1).await;
        let stopped = driver.stop().await;
        completed.unwrap();
        let expected = outcome.err().unwrap_or(io::ErrorKind::InvalidData);
        assert_eq!(stopped.unwrap_err().kind(), expected);
        assert_eq!(control.singles.load(Ordering::Relaxed), 0);
        assert!(control.emitted.lock().unwrap().is_empty());
        assert_eq!(control.active.load(Ordering::Relaxed), 0);
        assert_eq!(control.drops.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn macos_quic_batch_memory_stop_and_cleared_queue_release_pending_leases() {
    let (socket, driver, control, _input) = fixture();
    for sequence in 0..4 {
        enqueue(&socket, sequence).unwrap();
    }
    let started = until(|| {
        control.singles.load(Ordering::Relaxed) > 0 || !control.batches.lock().unwrap().is_empty()
    })
    .await;
    socket.shared.finish(None);
    control.credit.add_permits(1);
    let stopped = driver.stop().await;
    started.unwrap();
    stopped.unwrap();
    assert_eq!(control.active.load(Ordering::Relaxed), 0);
    assert_eq!(control.closes.load(Ordering::Relaxed), 1);
    assert_eq!(control.drops.load(Ordering::Relaxed), 1);
    assert!(!control.batches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn macos_quic_batch_memory_original_io_error_survives_close_failure() {
    let (socket, driver, control, _input) = fixture();
    control.close_error.store(true, Ordering::Relaxed);
    control
        .outcomes
        .lock()
        .unwrap()
        .push_back(Err(io::ErrorKind::PermissionDenied));
    for sequence in 0..4 {
        enqueue(&socket, sequence).unwrap();
    }
    control.credit.add_permits(1);
    let completed = until(|| control.closes.load(Ordering::Relaxed) == 1).await;
    let stopped = driver.stop().await;
    completed.unwrap();
    assert_eq!(stopped.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(control.active.load(Ordering::Relaxed), 0);
    assert_eq!(control.closes.load(Ordering::Relaxed), 1);
    assert_eq!(control.drops.load(Ordering::Relaxed), 1);
}
