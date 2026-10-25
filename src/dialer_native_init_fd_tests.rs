//! Root-only Linux FD prechecks. Require an inherited REAL owned TUN FD;
//! these are deliberately ignored and are NOT memory tests or TUN data signoff.
use super::*;
use crate::resources::observation::ResourceProbe;
use std::{future::Future, os::fd::AsRawFd, task::Poll};

fn require_owned_real_tun() {
    assert_eq!(std::env::var("BENCHMARK_ISOLATED").as_deref(), Ok("1"));
    let fd: i32 = std::env::var("VOLE_NATIVE_INIT_TEST_TUN_FD")
        .expect("Root must inherit the owned Linux guest's real TUN FD")
        .parse()
        .unwrap();
    assert!(fd > 2);
    // Read-only UAPI check; never open/configure a TUN or alter owner flags.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) }, 0);
    assert_ne!(
        i32::from(unsafe { request.ifr_ifru.ifru_flags }) & libc::IFF_TUN,
        0
    );
    // This does not independently prove raw-IP framing, routing or business IO;
    // Root's existing real-TUN environment and later data check own those facts.
}

struct OccupiedBlockingWorker {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl OccupiedBlockingWorker {
    fn start() -> Self {
        let (ready, started) = std::sync::mpsc::channel();
        let (release, held) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = ready.send(());
            // Sender Drop also releases the fixture on panic; no stuck worker.
            let _ = held.recv();
        });
        started.recv().unwrap();
        Self {
            release: Some(release),
            task: Some(task),
        }
    }
    async fn finish(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.task.take().unwrap().await.unwrap();
    }
}
impl Drop for OccupiedBlockingWorker {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

fn closed_fd(fd: i32) {
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}

#[test]
#[ignore = "Root-owned Linux real TUN only; actual sockets, not a memory filter"]
fn plain_native_tcp_udp_do_not_wait_for_the_blocking_worker() {
    require_owned_real_tun();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let probe = ResourceProbe::default();
    let (tcp_ready, udp_ready) = runtime.block_on(probe.scope(async {
        let dialer = Dialer::default();
        let destination: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let held = OccupiedBlockingWorker::start();
        let mut preparing = Box::pin(dialer.prepare_tcp_socket(destination));
        let first = std::future::poll_fn(|cx| Poll::Ready(preparing.as_mut().poll(cx))).await;
        let tcp_ready = first.is_ready();
        // Original blocking source is allowed to finish after releasing its
        // worker; intended RED occurs only after all cleanup, not at a timeout.
        held.finish().await;
        let (socket, guard, address) = match first {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => preparing.await.unwrap(),
        };
        assert_eq!(address, destination);
        let raw = socket.as_raw_fd();
        let options = socket2::SockRef::from(&socket);
        assert!(options.nonblocking().unwrap());
        assert!(options.tcp_nodelay().unwrap());
        assert!(options.keepalive().unwrap());
        drop(options);
        drop(socket);
        drop(guard);
        closed_fd(raw);

        let held = OccupiedBlockingWorker::start();
        let mut binding = Box::pin(dialer.bind_udp_for(destination));
        let first = std::future::poll_fn(|cx| Poll::Ready(binding.as_mut().poll(cx))).await;
        let udp_ready = first.is_ready();
        held.finish().await;
        let socket = match first {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => binding.await.unwrap(),
        };
        let raw = socket.as_raw_fd();
        assert!(socket.local_addr().unwrap().port() > 0);
        assert!(socket2::SockRef::from(&*socket).nonblocking().unwrap());
        drop(socket);
        closed_fd(raw);
        dialer.shutdown().await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
        (tcp_ready, udp_ready)
    }));
    println!(
        "native FD first-poll progress: TCP={tcp_ready}, UDP={udp_ready}; all sockets and jobs closed"
    );
    assert!(
        tcp_ready && udp_ready,
        "plain native socket setup waited for an unrelated blocking worker"
    );
}

#[test]
#[ignore = "Root-owned Linux real TUN only; actual sockets, not a memory filter"]
fn custom_factory_and_host_protector_stay_on_the_blocking_worker() {
    require_owned_real_tun();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let probe = ResourceProbe::default();
    runtime.block_on(probe.scope(async {
        let caller = std::thread::current().id();
        let destination: SocketAddr = "192.0.2.10:443".parse().unwrap();
        let dialer = Dialer::default();
        let factory_thread = Arc::new(Mutex::new(None));
        let record = factory_thread.clone();
        let held = OccupiedBlockingWorker::start();
        let mut preparing = Box::pin(dialer.prepare_tcp_socket_with(destination, move |ipv6| {
            *record.lock().unwrap() = Some(std::thread::current().id());
            if ipv6 {
                TcpSocket::new_v6()
            } else {
                TcpSocket::new_v4()
            }
        }));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(preparing.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert!(factory_thread.lock().unwrap().is_none());
        held.finish().await;
        drop(preparing.await.unwrap());
        assert_ne!(factory_thread.lock().unwrap().unwrap(), caller);
        dialer.shutdown().await;

        struct Protector(Arc<Mutex<Option<std::thread::ThreadId>>>);
        impl SocketProtector for Protector {
            fn protect(&self, _: i32) -> io::Result<()> {
                *self.0.lock().unwrap() = Some(std::thread::current().id());
                Ok(())
            }
        }
        let protector_thread = Arc::new(Mutex::new(None));
        let dialer =
            Dialer::default().with_protector(Arc::new(Protector(protector_thread.clone())));
        let held = OccupiedBlockingWorker::start();
        let mut binding = Box::pin(dialer.bind_udp_for(destination));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(binding.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert!(protector_thread.lock().unwrap().is_none());
        held.finish().await;
        drop(binding.await.unwrap());
        assert_ne!(protector_thread.lock().unwrap().unwrap(), caller);
        dialer.shutdown().await;
        assert!(probe.snapshot().is_idle(), "{:?}", probe.snapshot());
    }));
}
