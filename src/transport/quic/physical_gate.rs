//! Explicit isolated Linux/TUN resource gate; creates no server or listener.
use super::super::{DatagramDriver, DatagramSocket, attach_quinn};
use crate::{
    ResourceLimits, TunFraming,
    dialer::{Dialer, PhysicalDatagram},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError, Dispatcher},
    outbound::DirectOutbound,
    platform::{TunFd, TunIo},
    resources::observation::{ResourceKind, ResourceProbe},
    session::{Datagram, DatagramSession, Destination, StreamSession},
    tun_runtime::TunRuntime,
};
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use serde::Deserialize;
use std::{
    fs,
    future::poll_fn,
    io::{self, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker, ready},
    time::Duration,
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
struct Spec {
    peer: SocketAddr,
    mode: String,
}
struct Held {
    socket: Arc<DatagramSocket>,
    pollers: Vec<Pin<Box<dyn UdpPoller>>>,
    driver: Option<DatagramDriver>,
    weak: Weak<PhysicalDatagram>,
    fd: i32,
    inode: u64,
}
struct Gate {
    dialer: Dialer,
    peer: SocketAddr,
    held: Arc<Mutex<Option<Held>>>,
}
struct Bridge {
    socket: Arc<DatagramSocket>,
    peer: SocketAddr,
    poller: Pin<Box<dyn UdpPoller>>,
}

#[async_trait]
impl Dispatcher for Gate {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        assert!(
            self.held.lock().unwrap().is_none(),
            "one finite TUN flow only"
        );
        let direct = DirectOutbound::new(self.dialer.clone());
        let raw = direct.open_datagram(session).await?;
        let (socket, driver) =
            attach_quinn(raw, self.peer, DatagramBudget::new(1500, 1500)).await?;
        let (fd, inode, weak) = {
            let native = socket.physical.as_ref().expect("native DIRECT socket");
            let lease = native.io.value.lock().unwrap();
            let io = lease.as_ref().unwrap();
            let fd = io.as_raw_fd();
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
            (fd, unsafe { stat.assume_init() }.st_ino, Arc::downgrade(io))
        };
        let mut pollers = vec![
            socket.clone().create_io_poller(),
            socket.clone().create_io_poller(),
        ];
        for poller in &mut pollers {
            assert!(matches!(
                poller
                    .as_mut()
                    .poll_writable(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(())) | Poll::Pending
            ));
        }
        let bridge = Bridge {
            poller: socket.clone().create_io_poller(),
            socket: socket.clone(),
            peer: self.peer,
        };
        *self.held.lock().unwrap() = Some(Held {
            socket,
            pollers,
            driver: Some(driver),
            weak,
            fd,
            inode,
        });
        Ok(Box::new(bridge))
    }
}
#[async_trait]
impl DatagramTransport for Bridge {
    fn supports_shared_destinations(&self) -> bool {
        // This retirement fixture accepts exactly the configured peer.
        false
    }

    async fn send(&mut self, packet: Datagram) -> Result<(), DispatchError> {
        if packet.remote != Destination::Ip(self.peer) {
            return Err(DispatchError::NotAllowed);
        }
        poll_fn(|cx| {
            match self.socket.try_send(&Transmit {
                destination: self.peer,
                contents: &packet.payload,
                ecn: None,
                segment_size: None,
                src_ip: None,
            }) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poller.as_mut().poll_writable(cx))?;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                result => Poll::Ready(result),
            }
        })
        .await
        .map_err(DispatchError::from)
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        let mut bytes = [0; 1501];
        let mut meta = [RecvMeta::default()];
        poll_fn(|cx| {
            self.socket
                .poll_recv(cx, &mut [IoSliceMut::new(&mut bytes)], &mut meta)
        })
        .await?;
        Ok(Datagram {
            remote: Destination::Ip(meta[0].addr),
            payload: Bytes::copy_from_slice(&bytes[..meta[0].len]),
            sniffed_domain: None,
        })
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an explicitly owned isolated Linux container and real TUN"]
async fn real_tun_native_udp_retirement_gate() {
    assert_eq!(std::env::var("VOLE_INTEROP_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("VOLE_D05_GATE_DIR").unwrap());
    let fd: i32 = std::env::var("VOLE_D05_TUN_FD").unwrap().parse().unwrap();
    let spec: Spec = serde_json::from_slice(&fs::read(root.join("spec.json")).unwrap()).unwrap();
    assert!(matches!(spec.mode.as_str(), "stop" | "drop"));
    assert!(!spec.peer.ip().is_loopback() && spec.peer.port() == 24541);
    let config = crate::config::Config::parse_yaml(
        b"routing-mark: 42\nexperimental: {quic-go-disable-gso: true, quic-go-disable-ecn: true}\n",
    )
    .unwrap();
    let dialer = Dialer::default()
        .with_egress(&config.egress)
        .with_connections(config.connections);
    let held = Arc::new(Mutex::new(None));
    let gate = Arc::new(Gate {
        dialer: dialer.clone(),
        peer: spec.peer,
        held: held.clone(),
    });
    let tun = TunIo::new(TunFd::duplicate(fd).unwrap(), TunFraming::RawIp).unwrap();
    let runtime = TunRuntime::new(
        tun,
        ResourceLimits::default(),
        gate,
        None,
        false,
        false,
        None,
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let probe = ResourceProbe::default();
    let task_probe = probe.clone();
    let task_cancel = cancellation.clone();
    let mut running = tokio::spawn(async move { task_probe.scope(runtime.run(task_cancel)).await });
    fs::write(root.join("ready"), b"real-tun-runtime-created").unwrap();
    timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                result = &mut running => panic!("TUN ended before explicit stop: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {
                    if root.join("stop").exists() { break; }
                }
            }
        }
    })
    .await
    .expect("explicit gate stop not requested");
    let mut held = held
        .lock()
        .unwrap()
        .take()
        .expect("actual TUN UDP flow established");
    assert_eq!(probe.snapshot().current(ResourceKind::Socket), 1);
    let mut driver = held.driver.take().unwrap();
    timeout(Duration::from_secs(2), async {
        if spec.mode == "stop" {
            driver.stop().await.unwrap();
        } else {
            // Retain the private task handle solely to witness its actual join.
            let task = driver.task.take().unwrap();
            drop(driver);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    })
    .await
    .expect("native UDP owner did not join");
    // No file/report is opened between retirement and these descriptor checks.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let fd_closed = unsafe { libc::fstat(held.fd, stat.as_mut_ptr()) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
        && unsafe { libc::fcntl(held.fd, libc::F_GETFD) } == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    assert!(
        fd_closed,
        "retained QUIC handles kept the physical fd alive"
    );
    assert!(held.weak.upgrade().is_none());
    assert_eq!(probe.snapshot().current(ResourceKind::Socket), 0);
    assert_eq!(
        held.socket.local_addr().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    for poller in &mut held.pollers {
        for _ in 0..3 {
            assert!(
                matches!(poller.as_mut().poll_writable(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
            );
        }
    }
    cancellation.cancel();
    timeout(Duration::from_secs(2), async {
        running.await.unwrap().unwrap();
        dialer.shutdown().await;
    })
    .await
    .unwrap();
    fs::write(
        root.join("events.json"),
        serde_json::to_vec(&serde_json::json!({
            "mode": spec.mode, "fd": held.fd, "inode": held.inode,
            "fd_closed": fd_closed, "weak_dropped": true, "sockets_after_stop": 0,
            "retained_pollers": held.pollers.len(), "stop_joined": true,
        }))
        .unwrap(),
    )
    .unwrap();
    // Keep the closed socket and pollers live until all Stop assertions finish.
    drop(held);
}
