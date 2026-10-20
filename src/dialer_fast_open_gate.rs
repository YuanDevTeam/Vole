//! Explicitly ignored Linux-container/TUN driver for the private TFO API.
//! No listener or server is created by this Rust test.
use std::{
    fs, io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use crate::{
    ResourceLimits, TunFraming,
    dialer::{Dialer, SocketProtector},
    dispatch::{BoxStream, DatagramTransport, DispatchError, Dispatcher},
    platform::{TunFd, TunIo},
    session::{DatagramSession, StreamSession},
    tun_runtime::TunRuntime,
};

#[derive(Deserialize)]
struct Spec {
    #[serde(default = "tfo")]
    transport: String,
    #[serde(default)]
    protect_fail: bool,
    #[serde(default)]
    source_ip: Option<IpAddr>,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    routing_mark: i64,
    peer: SocketAddr,
    mode: String,
    deadline_ms: u64,
    delay_ms: u64,
}

fn tfo() -> String {
    "tfo".into()
}

#[derive(Default, Serialize)]
struct Record {
    phase: &'static str,
    initially_pending: bool,
    accepted_prefix_bytes: usize,
    prepare_ms: u128,
    tasks_after_prepare: usize,
    tasks_after_stop: usize,
    protector_calls: usize,
    error_kind: Option<String>,
    stop_joined: bool,
    mptcp_paths: Vec<(SocketAddr, SocketAddr)>,
}

struct Protect {
    calls: AtomicUsize,
    reject: bool,
}
impl SocketProtector for Protect {
    fn protect(&self, _fd: i32) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

struct Gate {
    dialer: Dialer,
    spec: Spec,
    record: Arc<Mutex<Record>>,
    root: PathBuf,
}

impl Gate {
    fn save(&self) {
        fs::write(
            self.root.join("events.json"),
            serde_json::to_vec(&*self.record.lock().unwrap()).unwrap(),
        )
        .unwrap();
    }

    async fn open(&self) -> io::Result<BoxStream> {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(self.spec.deadline_ms);
        if self.spec.transport == "mptcp" {
            let stream = self
                .dialer
                .connect_mptcp_gate(self.spec.peer, deadline)
                .await?;
            loop {
                let paths = super::super::mptcp_gate::paths(&*stream)?;
                if self.record.lock().unwrap().mptcp_paths.len() != paths.len() {
                    self.record.lock().unwrap().mptcp_paths = paths.clone();
                    self.save();
                }
                if paths.len() >= 2 {
                    self.record.lock().unwrap().mptcp_paths = paths;
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "two actual MPTCP subflows were not established",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            self.record.lock().unwrap().phase = "published";
            self.save();
            return Ok(Box::new(stream));
        }
        let (mut stream, actual_address) = self
            .dialer
            .prepare_tcp_fast_open(self.spec.peer, deadline)
            .await?;
        assert_eq!(actual_address, self.spec.peer);
        {
            let mut record = self.record.lock().unwrap();
            record.phase = "prepared";
            record.initially_pending = stream.handshake.result.get().is_none();
            record.prepare_ms = start.elapsed().as_millis();
            record.tasks_after_prepare = self.dialer.initialization.tasks.len();
        }
        self.save();
        if self.spec.mode == "dormant-stop" {
            // Keep the original stream live while Stop revokes its pending
            // physical connection and joins the separately tracked owner.
            self.dialer.initialization.cancellation.cancelled().await;
            return Err(io::ErrorKind::Interrupted.into());
        }
        tokio::time::sleep(Duration::from_millis(self.spec.delay_ms)).await;
        if matches!(
            self.spec.mode.as_str(),
            "first-write" | "late-write" | "connecting-stop" | "rejected"
        ) {
            let prefix = b"vole-tfo-one-delivery\n";
            stream.write_all(prefix).await?;
            self.record.lock().unwrap().accepted_prefix_bytes = prefix.len();
            self.save();
            stream.flush().await?;
        } else if self.spec.mode == "empty-write" {
            assert_eq!(stream.write(&[]).await?, 0);
        } else if self.spec.mode == "flush" {
            stream.flush().await?;
        } else if !matches!(self.spec.mode.as_str(), "server-first" | "half-close") {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.record.lock().unwrap().phase = "published";
        self.save();
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl Dispatcher for Gate {
    async fn connect_tcp(&self, _session: StreamSession) -> Result<BoxStream, DispatchError> {
        match self.open().await {
            Ok(stream) => Ok(stream),
            Err(error) => {
                self.record.lock().unwrap().error_kind = Some(format!("{:?}", error.kind()));
                self.save();
                Err(error.into())
            }
        }
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[tokio::test]
#[ignore = "requires an explicitly owned isolated Linux container and real TUN"]
async fn real_tun_private_tfo_gate() {
    assert_eq!(std::env::var("VOLE_INTEROP_ISOLATED").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("VOLE_D03_GATE_DIR").expect("gate directory"));
    let fd: i32 = std::env::var("VOLE_D03_TUN_FD")
        .expect("borrowed real TUN fd")
        .parse()
        .unwrap();
    let spec: Spec = serde_json::from_slice(&fs::read(root.join("spec.json")).unwrap()).unwrap();
    assert!((50..=5_000).contains(&spec.deadline_ms));
    assert!(spec.delay_ms <= 6_000);
    assert!(matches!(spec.transport.as_str(), "tfo" | "mptcp"));
    if spec.transport == "tfo" {
        assert!(spec.peer.ip().is_loopback());
    }
    let protected = Arc::new(Protect {
        calls: AtomicUsize::new(0),
        reject: spec.protect_fail,
    });
    let source = spec
        .source_ip
        .or_else(|| (spec.transport == "tfo").then(|| "127.0.0.2".parse().unwrap()));
    let egress_yaml = serde_json::to_vec(&serde_json::json!({
        "interface-name": spec.interface.as_str(),
        "routing-mark": spec.routing_mark,
    }))
    .unwrap();
    let egress = crate::config::Config::parse_yaml(&egress_yaml)
        .unwrap()
        .egress;
    let mut dialer = Dialer::default()
        .with_protector(protected.clone())
        .with_egress(&egress);
    if let Some(source) = source {
        dialer = dialer.with_source_ip(source);
    }
    let record = Arc::new(Mutex::new(Record::default()));
    let gate = Arc::new(Gate {
        dialer: dialer.clone(),
        spec,
        record: record.clone(),
        root: root.clone(),
    });
    let tun = TunIo::new(TunFd::duplicate(fd).unwrap(), TunFraming::RawIp).unwrap();
    let runtime = TunRuntime::new(
        tun,
        ResourceLimits::default(),
        gate.clone(),
        None,
        false,
        false,
        None,
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let mut running = tokio::spawn(runtime.run(cancellation.clone()));
    fs::write(root.join("ready"), b"real-tun-runtime-created").unwrap();
    let wait = timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                result = &mut running => panic!("TUN driver ended before explicit stop: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(10)) => {
                    if root.join("stop").exists() { break; }
                }
            }
        }
    }).await;
    // Stop registration and cancellation use the same owner as regular Dialer.
    dialer.begin_shutdown();
    cancellation.cancel();
    let shutdown = timeout(Duration::from_secs(2), async {
        dialer.shutdown().await;
        running.await.unwrap().unwrap();
    })
    .await;
    {
        let mut result = record.lock().unwrap();
        result.phase = "stopped";
        result.tasks_after_stop = dialer.initialization.tasks.len();
        result.protector_calls = protected.calls.load(Ordering::Relaxed);
        result.stop_joined = shutdown.is_ok();
    }
    gate.save();
    wait.expect("explicit gate stop was not requested");
    shutdown.expect("TFO Stop did not join");
    assert_eq!(record.lock().unwrap().tasks_after_stop, 0);
    assert_eq!(record.lock().unwrap().protector_calls, 1);
}
