//! XHTTP Downlink over real Quinn/H3 and bounded memory datagrams.
//! Server FIN acknowledgement is a wire-ready barrier, not an application read.
use super::*;
use crate::transport::quinn_h3::{
    Client,
    tests::{Pair, settle},
};
use futures_util::{FutureExt, future::poll_fn};
use std::{
    panic::{AssertUnwindSafe, resume_unwind},
    sync::atomic::{AtomicUsize, Ordering},
    task::{Wake, Waker},
};
use tokio::{sync::oneshot, time::timeout};

const LIMIT: Duration = Duration::from_secs(5);
type Server = h3::server::Connection<h3_quinn::Connection, Bytes>;
// QPACK Required Insert Count=0, Delta Base=0, indexed static :status=200.
// This independent fixture is also used by quinn_h3_wire_tests.rs.
const RESPONSE: &[u8] = &[1, 3, 0, 0, 0xd9];

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn sender(pair: &Pair, requests: Client) -> SendRequest {
    SendRequest::H3(h3_driver::Sender {
        requests,
        runtime: pair.client_runtime.clone(),
        #[cfg(feature = "interop-test")]
        observation: pair.client.clone(),
    })
}

async fn open(sender: &mut SendRequest, path: &str) -> Downlink {
    let request = Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let (response, upload) = sender.send_request(request, true).await.unwrap();
    drop(upload); // Request FIN is already finished by the real H3 sender.
    Downlink::pending(response, "memory H3 download", false)
}

fn data(wire: &mut Vec<u8>, payload: &[u8]) {
    assert!(payload.len() < 16_384);
    wire.push(0); // HTTP/3 DATA.
    if payload.len() < 64 {
        wire.push(payload.len() as u8);
    } else {
        wire.extend_from_slice(&(0x4000_u16 | payload.len() as u16).to_be_bytes());
    }
    wire.extend_from_slice(payload);
}

fn buffered_response(
    pair: &mut Pair,
    server_control: Server,
    wire: Vec<u8>,
) -> oneshot::Receiver<()> {
    let server = pair.server.clone();
    let (sent, acknowledged) = oneshot::channel();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        assert_eq!(send.stopped().await.unwrap(), None);
        sent.send(()).unwrap();
        // Keep the official H3 control/QPACK streams alive until synchronized Stop.
        std::future::pending::<()>().await;
    });
    acknowledged
}

async fn read(download: &mut Downlink, bytes: &mut [u8]) -> io::Result<usize> {
    let mut output = ReadBuf::new(bytes);
    poll_fn(|cx| {
        let result = download.poll_read(cx, &mut output);
        if result.is_pending() {
            assert!(
                output.filled().is_empty(),
                "Pending must not hide copied bytes"
            );
        }
        result
    })
    .await?;
    Ok(output.filled().len())
}

async fn drain(download: &mut Downlink) -> io::Result<Vec<u8>> {
    let mut all = Vec::new();
    let mut storage = [0; 16 * 1024];
    loop {
        let n = read(download, &mut storage).await?;
        if n == 0 {
            return Ok(all);
        }
        all.extend_from_slice(&storage[..n]);
        assert!(all.len() <= 64 * 1024);
    }
}

#[tokio::test]
async fn xhttp_h3_ready_read_batches_wire_data_and_preserves_fin() {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, server) = pair.h3().await;
    let mut sender = sender(&pair, client);
    let expected: Vec<u8> = (0..7_000).map(|n| (n % 251) as u8).collect();
    let mut wire = RESPONSE.to_vec();
    for part in expected.chunks(1_000) {
        data(&mut wire, part);
    }
    let acknowledged = buffered_response(&mut pair, server, wire);
    let mut download = open(&mut sender, "/ready").await;
    settle(pair, async move {
        acknowledged.await.unwrap();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count);
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0; 16 * 1024];
        let mut output = ReadBuf::new(&mut storage);
        output.put_slice(b"prefix");
        assert!(matches!(
            download.poll_read(&mut cx, &mut output),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(&output.filled()[..6], b"prefix");
        // No DATA frame exceeds 1000 bytes; a larger read proves real aggregation.
        assert!(output.filled().len() - 6 > 1_000);
        let mut received = output.filled()[6..].to_vec();
        received.extend_from_slice(&drain(&mut download).await.unwrap());
        assert_eq!(received, expected);
        assert_eq!(read(&mut download, &mut [0; 1]).await.unwrap(), 0);
    })
    .await;
}

#[tokio::test]
async fn xhttp_h3_ready_read_budget_returns_progress_without_self_wake() {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, server) = pair.h3().await;
    let mut sender = sender(&pair, client);
    let expected: Vec<u8> = (0..64).collect();
    let mut wire = RESPONSE.to_vec();
    for byte in &expected {
        data(&mut wire, &[*byte]);
    }
    let acknowledged = buffered_response(&mut pair, server, wire);
    let mut download = open(&mut sender, "/budget").await;
    settle(pair, async move {
        acknowledged.await.unwrap();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0; 1024];
        let mut output = ReadBuf::new(&mut storage);
        assert!(matches!(
            download.poll_read(&mut cx, &mut output),
            Poll::Ready(Ok(()))
        ));
        // Many complete wire DATA frames fit in one native packet, but one call
        // must stop before exhausting all of them despite spare caller capacity.
        assert!(output.filled().len() > 1 && output.filled().len() < expected.len());
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        let mut received = output.filled().to_vec();
        received.extend_from_slice(&drain(&mut download).await.unwrap());
        assert_eq!(received, expected);
    })
    .await;
}

#[tokio::test]
async fn xhttp_h3_ready_read_preserves_owned_bytes_before_real_reset() {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, server_control) = pair.h3().await;
    let mut sender = sender(&pair, client);
    let native = pair.client.clone();
    let server = pair.server.clone();
    let reset_before = native.stats().frame_rx.reset_stream;
    let (release, released) = oneshot::channel();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        let mut wire = RESPONSE.to_vec();
        data(&mut wire, b"owned-chunk");
        send.write_all(&wire).await.unwrap();
        released.await.unwrap();
        send.reset(0x42_u32.into()).unwrap();
        std::future::pending::<()>().await;
    });
    let mut download = open(&mut sender, "/reset").await;
    settle(pair, async move {
        let mut first = [0; 1];
        assert_eq!(read(&mut download, &mut first).await.unwrap(), 1);
        assert_eq!(&first, b"o");
        // This remainder came from the real native stream; it was not installed
        // by the test. Hold it while the peer's RESET clears its own QUIC buffers.
        assert!(download.current.has_remaining());
        release.send(()).unwrap();
        timeout(LIMIT, async {
            while native.stats().frame_rx.reset_stream == reset_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut storage = [0; 128];
        let mut output = ReadBuf::new(&mut storage);
        output.put_slice(b"keep");
        assert!(matches!(
            download.poll_read(&mut cx, &mut output),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(output.filled(), b"keepwned-chunk");
        let mut empty = ReadBuf::new(&mut []);
        assert!(matches!(
            download.poll_read(&mut cx, &mut empty),
            Poll::Ready(Ok(()))
        ));
        assert!(read(&mut download, &mut [0; 1]).await.is_err());
        assert!(native.close_reason().is_none());
    })
    .await;
}

#[tokio::test]
async fn xhttp_h3_ready_read_partial_pending_drop_preserves_sibling_and_stop() {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, server_control) = pair.h3().await;
    let mut sender = sender(&pair, client);
    let native = pair.client.clone();
    let server = pair.server.clone();
    let (observed, stopped) = oneshot::channel();
    let (continue_send, continued) = oneshot::channel();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        let mut wire = RESPONSE.to_vec();
        data(&mut wire, b"partial");
        send.write_all(&wire).await.unwrap();
        // Pause without FIN so the real app-facing receive becomes Pending.
        continued.await.unwrap();
        let mut late = Vec::new();
        data(&mut late, b"late");
        send.write_all(&late).await.unwrap();
        observed.send(send.stopped().await.unwrap()).unwrap();
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        let mut wire = RESPONSE.to_vec();
        data(&mut wire, b"sibling");
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        assert_eq!(send.stopped().await.unwrap(), None);
        std::future::pending::<()>().await;
    });
    let mut download = open(&mut sender, "/partial").await;
    settle(pair, async move {
        let mut storage = [0; 128];
        let n = read(&mut download, &mut storage).await.unwrap();
        assert_eq!(&storage[..n], b"partial");
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut output = ReadBuf::new(&mut storage);
        assert!(download.poll_read(&mut cx, &mut output).is_pending());
        assert!(output.filled().is_empty());
        continue_send.send(()).unwrap();
        timeout(LIMIT, async {
            while count.0.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let n = read(&mut download, &mut storage).await.unwrap();
        assert_eq!(&storage[..n], b"late");
        let mut output = ReadBuf::new(&mut storage);
        assert!(download.poll_read(&mut cx, &mut output).is_pending());
        assert!(output.filled().is_empty());
        drop(download); // Exercise the official h3-quinn Pending ownership guard.
        assert_eq!(stopped.await.unwrap(), Some(0_u8.into()));
        assert!(native.close_reason().is_none());
        let mut sibling = open(&mut sender, "/sibling").await;
        assert_eq!(drain(&mut sibling).await.unwrap(), b"sibling");
    })
    .await; // Cancels and joins H3 control and both Core-owned native runtimes.
}

#[tokio::test]
async fn xhttp_h3_ready_read_native_stop_wakes_retained_pending_reader() {
    let mut pair = Pair::new(64 * 1024).await;
    let (client, server_control) = pair.h3().await;
    let mut sender = sender(&pair, client);
    let server = pair.server.clone();
    pair.spawn(async move {
        let _server_control = server_control;
        let (mut send, mut receive) = server.accept_bi().await.unwrap();
        assert!(!receive.read_to_end(16 * 1024).await.unwrap().is_empty());
        let mut wire = RESPONSE.to_vec();
        data(&mut wire, b"active");
        send.write_all(&wire).await.unwrap();
        let _send = send;
        std::future::pending::<()>().await;
    });
    let count = Arc::new(WakeCount::default());
    let observer = count.clone();
    let result = AssertUnwindSafe(timeout(LIMIT, async move {
        let mut download = open(&mut sender, "/stop").await;
        let mut storage = [0; 128];
        let n = read(&mut download, &mut storage).await.unwrap();
        assert_eq!(&storage[..n], b"active");
        let waker = Waker::from(count);
        let mut cx = Context::from_waker(&waker);
        let mut output = ReadBuf::new(&mut storage);
        assert!(download.poll_read(&mut cx, &mut output).is_pending());
        assert!(output.filled().is_empty());
        download
    }))
    .catch_unwind()
    .await;
    // Stop while the app-facing receive half is still retained and Pending.
    // This is the native OwnedRuntime barrier, not a claim of Invoke/device Stop.
    pair.stop().await;
    let mut download = match result {
        Ok(result) => result.expect("memory H3 preparation timed out"),
        Err(panic) => resume_unwind(panic),
    };
    assert!(observer.0.load(Ordering::Relaxed) > 0);
    assert!(
        timeout(LIMIT, read(&mut download, &mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
}
