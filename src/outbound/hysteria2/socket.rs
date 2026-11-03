//! Receive ownership across a bounded physical-path handover.
use quinn::{AsyncUdpSocket, UdpPoller, udp::RecvMeta};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

#[derive(Debug)]
pub(super) struct WindowSocket {
    current: Arc<dyn AsyncUdpSocket>,
    previous: Mutex<Option<Arc<dyn AsyncUdpSocket>>>,
    previous_first: AtomicBool,
}
impl WindowSocket {
    pub fn new(
        current: Arc<dyn AsyncUdpSocket>,
        previous: Option<Arc<dyn AsyncUdpSocket>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            current,
            previous: Mutex::new(previous),
            previous_first: AtomicBool::new(false),
        })
    }
    pub fn retire_previous(&self) {
        self.previous.lock().unwrap().take();
    }
}
impl AsyncUdpSocket for WindowSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.current.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.current.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Quinn retires its previous socket after the first packet on the new
        // one. Keep the whole grace window behind its *current* socket so late
        // old-path datagrams are still read, not merely buffered until Drop.
        let previous = self.previous.lock().unwrap().clone();
        let first = self.previous_first.fetch_xor(true, Ordering::Relaxed);
        for old in [first, !first] {
            let socket = if old {
                let Some(socket) = previous.as_deref() else {
                    continue;
                };
                socket
            } else {
                &*self.current
            };
            match socket.poll_recv(cx, buffers, meta) {
                Poll::Pending => {}
                Poll::Ready(Err(_)) if old => self.retire_previous(),
                ready => return ready,
            }
        }
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.current.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.current.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use tokio::sync::mpsc;

    // External datagram IO is in memory; no host socket or TLS server exists.
    #[derive(Debug)]
    struct MemorySocket(Mutex<mpsc::Receiver<Bytes>>);
    #[derive(Debug)]
    struct ReadyPoller;
    impl UdpPoller for ReadyPoller {
        fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncUdpSocket for MemorySocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(ReadyPoller)
        }
        fn try_send(&self, _: &quinn::udp::Transmit<'_>) -> io::Result<()> {
            Ok(())
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            buffers: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let Some(packet) = std::task::ready!(self.0.lock().unwrap().poll_recv(cx)) else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            buffers[0][..packet.len()].copy_from_slice(&packet);
            meta[0] = RecvMeta {
                addr: "192.0.2.1:443".parse().unwrap(),
                len: packet.len(),
                stride: packet.len(),
                ecn: None,
                dst_ip: None,
            };
            Poll::Ready(Ok(1))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("0.0.0.0:0".parse().unwrap())
        }
    }
    fn memory_socket() -> (mpsc::Sender<Bytes>, Arc<MemorySocket>) {
        let (tx, rx) = mpsc::channel(4);
        (tx, Arc::new(MemorySocket(Mutex::new(rx))))
    }
    async fn receive(socket: &dyn AsyncUdpSocket) -> Bytes {
        let mut bytes = [0; 64];
        let mut meta = [RecvMeta::default()];
        let count = futures_util::future::poll_fn(|cx| {
            socket.poll_recv(cx, &mut [IoSliceMut::new(&mut bytes)], &mut meta)
        })
        .await
        .unwrap();
        assert_eq!(count, 1);
        Bytes::copy_from_slice(&bytes[..meta[0].len])
    }
    #[tokio::test]
    async fn a_new_path_packet_does_not_end_the_old_receive_window() {
        let (old_tx, old) = memory_socket();
        let (new_tx, new) = memory_socket();
        let socket = WindowSocket::new(new, Some(old));
        new_tx.send(Bytes::from_static(b"new")).await.unwrap();
        assert_eq!(receive(&*socket).await, b"new"[..]);
        // A delayed old-path datagram can arrive after the first new-path ACK.
        old_tx.send(Bytes::from_static(b"old-late")).await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(50), receive(&*socket))
                .await
                .expect("old receive path ended before its grace window"),
            b"old-late"[..]
        );
        // A continuously ready path cannot starve the other during handover.
        for _ in 0..2 {
            old_tx.send(Bytes::from_static(b"old")).await.unwrap();
            new_tx.send(Bytes::from_static(b"new")).await.unwrap();
        }
        for expected in [b"new", b"old", b"new", b"old"] {
            assert_eq!(receive(&*socket).await, expected[..]);
        }
        // Exercise a pending reader, rather than only pre-buffered datagrams.
        for (sender, expected) in [(&old_tx, b"old"), (&new_tx, b"new")] {
            let reading = socket.clone();
            let reader = tokio::spawn(async move { receive(&*reading).await });
            tokio::task::yield_now().await;
            sender.send(Bytes::from_static(expected)).await.unwrap();
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_millis(50), reader)
                    .await
                    .expect("path did not wake the pending reader")
                    .unwrap(),
                expected[..]
            );
        }
        socket.retire_previous();
        assert!(old_tx.send(Bytes::from_static(b"retired")).await.is_err());
        new_tx.send(Bytes::from_static(b"new-again")).await.unwrap();
        assert_eq!(receive(&*socket).await, b"new-again"[..]);
    }
}
