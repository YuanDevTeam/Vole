//! Stream plugins are below SS2022; UDP stays native unless UoT is configured.
use crate::{
    config::{SecurityConfig, ShadowsocksPlugin, StreamTransport},
    dispatch::{BoxStream, DispatchError},
    outbound::{EstablishContext, UpstreamPath, owned_stream::OwnedStream},
    security::{SecurityClient, SecurityContext},
    session::{Destination, StreamSession},
    transport::{self, ss_framed},
};
use futures_util::task::AtomicWaker;
use shadowsocks::crypto::CipherKind;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
enum Kind {
    Security(SecurityClient),
    ShadowTls(SecurityClient),
    Obfs {
        tls: bool,
        host: String,
        port: u16,
    },
    WebSocket {
        security: Option<SecurityClient>,
        transport: StreamTransport,
        gost: bool,
        mux: bool,
    },
}
pub(super) struct Owner {
    kind: Kind,
    cancel: CancellationToken,
    tasks: TaskTracker,
    closed: Mutex<bool>,
}
impl Owner {
    pub(super) fn new(
        config: &ShadowsocksPlugin,
        context: &SecurityContext,
        sessions: usize,
        buffer: usize,
        port: u16,
    ) -> io::Result<Self> {
        let kind = match config {
            ShadowsocksPlugin::ShadowTls(config) => {
                Kind::ShadowTls(SecurityClient::from_security_with_context(
                    &SecurityConfig::ShadowTls(config.clone()),
                    context,
                    0,
                    buffer,
                )?)
            }
            ShadowsocksPlugin::Jls(config) => {
                Kind::Security(SecurityClient::from_security_with_context(
                    &SecurityConfig::Jls(config.clone()),
                    context,
                    0,
                    buffer,
                )?)
            }
            ShadowsocksPlugin::Obfs { tls, host } => Kind::Obfs {
                tls: *tls,
                host: host.clone(),
                port,
            },
            ShadowsocksPlugin::WebSocket {
                gost,
                mux,
                transport,
                tls,
            } => Kind::WebSocket {
                security: tls
                    .as_ref()
                    .map(|config| {
                        SecurityClient::from_security_with_context(
                            &SecurityConfig::Tls(config.clone()),
                            context,
                            sessions,
                            buffer,
                        )
                    })
                    .transpose()?,
                transport: transport.clone(),
                gost: *gost,
                mux: *mux,
            },
        };
        Ok(Self {
            kind,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            closed: Mutex::new(false),
        })
    }
    // Immutable factory shapes, independent of HTTP features and liveness.
    // Binding must still use the same shape after a Stop race.
    fn has_static_obfs_kind(&self) -> bool {
        matches!(&self.kind, Kind::Obfs { .. })
    }

    fn has_static_v2ray_mux_kind(&self) -> bool {
        matches!(
            &self.kind,
            Kind::WebSocket {
                security: None,
                transport: StreamTransport::WebSocket {
                    handshake: crate::config::WebSocketHandshake::WebSocket,
                    max_early_data: 0,
                    ..
                },
                gost: false,
                mux: true,
            }
        )
    }

    #[cfg(feature = "inbound-http")]
    pub(super) fn permits_http_tcp_reuse(&self) -> bool {
        !self.cancel.is_cancelled()
            && !*self.closed.lock().unwrap()
            && (self.has_static_obfs_kind()
                || self.has_static_v2ray_mux_kind()
                || matches!(&self.kind, Kind::ShadowTls(client)
                    if client.permits_ss_shadowtls_http_reuse()))
    }

    pub(super) fn bind_stream(&self, stream: BoxStream) -> BoxStream {
        if matches!(&self.kind, Kind::ShadowTls(_))
            || (cfg!(feature = "inbound-http")
                && (self.has_static_obfs_kind() || self.has_static_v2ray_mux_kind()))
        {
            Box::new(ShadowTlsOwned::new(stream, self.cancel.child_token()))
        } else {
            stream
        }
    }

    // These exact carrier shapes need the official codec's complete first
    // response prefix even across mux Data or WS Message boundaries. This is
    // protocol I/O in every feature combination, separate from HTTP reuse.
    pub(super) fn prepare_ss_response(
        &self,
        raw: BoxStream,
        method: CipherKind,
    ) -> io::Result<BoxStream> {
        if self.has_static_obfs_kind() || self.has_static_v2ray_mux_kind() {
            Ok(Box::new(super::response_header::HeaderIo::new(
                raw, method,
            )?))
        } else {
            Ok(raw)
        }
    }

    pub(super) async fn open(
        &self,
        upstream: &UpstreamPath,
        server: &Destination,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        tokio::select! {biased;
            ()=self.cancel.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                let raw=upstream.connect_server(session,server,context).await?.io;
                match &self.kind {
                    Kind::Security(security)|Kind::ShadowTls(security)=>context.run_io("Shadowsocks plugin identity",security.connect_with_context(raw,context)).await,
                    Kind::Obfs {tls,host,port}=>Ok(ss_framed::wrap(raw,if *tls{ss_framed::Kind::Tls {host:host.clone()}}else{ss_framed::Kind::Http {host:host.clone(),port:*port}})),
                    Kind::WebSocket {security,transport,gost,mux}=>{
                        let raw=if let Some(security)=security {context.run_io("Shadowsocks plugin TLS",security.connect_with_context(raw,context)).await?}else{raw};
                        let options=transport.websocket_options()?.expect("validated WebSocket plugin");
                        let raw=transport::connect_websocket(raw,&options,&[],context.deadline()).await?;
                        if !mux {return Ok(raw);}
                        if !gost{return Ok(ss_framed::wrap(raw,ss_framed::Kind::V2rayMux));}
                        let cancel=self.cancel.child_token();let guard=cancel.clone().drop_guard();
                        let (client,driver)=transport::smux::new(raw);
                        let stopped=cancel.clone();
                        let observation=crate::resources::observation::track(crate::resources::observation::ResourceKind::Task);
                        {
                            let closed=self.closed.lock().unwrap();
                            if *closed { return Err(DispatchError::NotAllowed); }
                            self.tasks.spawn(crate::resources::observation::bind(async move {let _observation=observation;tokio::select!{biased;()=stopped.cancelled()=>{},_=driver=>{}}stopped.cancel();}));
                        }
                        let raw=context.run_io("Shadowsocks Gost smux",client.open()).await?;
                        guard.disarm();
                        Ok(Box::new(OwnedStream::new(raw,cancel))as BoxStream)
                    }
                }
            }=>result,
        }
    }
    pub(super) fn begin_shutdown(&self) {
        self.cancel.cancel();
        let mut closed = self.closed.lock().unwrap();
        *closed = true;
        self.tasks.close();
    }
    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }
}

// A ShadowTLS owner cancels a child per established SS stream. All underlying
// operations use one stable wake, preserving independently pending read/write
// callers even when OwnedStream's cancellation future records a newer poll.
struct ShadowTlsWake {
    reader: AtomicWaker,
    writer: AtomicWaker,
}
impl ShadowTlsWake {
    fn wake_all(&self) {
        self.reader.wake();
        self.writer.wake();
    }
}
impl Wake for ShadowTlsWake {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}
struct ShadowTlsOwned {
    inner: OwnedStream,
    wake: Arc<ShadowTlsWake>,
}
impl ShadowTlsOwned {
    fn new(stream: BoxStream, child: CancellationToken) -> Self {
        Self {
            inner: OwnedStream::new(stream, child),
            wake: Arc::new(ShadowTlsWake {
                reader: AtomicWaker::new(),
                writer: AtomicWaker::new(),
            }),
        }
    }
    fn poll_io<T>(
        &mut self,
        cx: &mut Context<'_>,
        reader: bool,
        operation: impl FnOnce(Pin<&mut OwnedStream>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let slot = if reader {
            &self.wake.reader
        } else {
            &self.wake.writer
        };
        slot.register(cx.waker());
        let waker = Waker::from(self.wake.clone());
        let result = operation(Pin::new(&mut self.inner), &mut Context::from_waker(&waker));
        if result.is_ready() {
            drop(slot.take());
        }
        result
    }
}
impl AsyncRead for ShadowTlsOwned {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, true, |inner, cx| inner.poll_read(cx, out))
    }
}
impl AsyncWrite for ShadowTlsOwned {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |inner, cx| inner.poll_write(cx, bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |inner, cx| inner.poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |inner, cx| inner.poll_shutdown(cx))
    }
}
impl Drop for ShadowTlsOwned {
    fn drop(&mut self) {
        self.wake.wake_all();
    }
}

#[cfg(all(test, feature = "inbound-http", feature = "shadow-tls-v3"))]
mod shadowtls_reuse_owner_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Default)]
    struct State {
        ready_read: bool,
        block_write: bool,
        dropped: bool,
        read_waker: Option<Waker>,
        write_waker: Option<Waker>,
    }
    struct Raw(Arc<Mutex<State>>);
    impl Drop for Raw {
        fn drop(&mut self) {
            let mut s = self.0.lock().unwrap();
            s.read_waker.take();
            s.write_waker.take();
            s.dropped = true;
        }
    }
    impl AsyncRead for Raw {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let mut s = self.0.lock().unwrap();
            if s.ready_read {
                out.put_slice(&[42]);
                Poll::Ready(Ok(()))
            } else {
                s.read_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
    impl AsyncWrite for Raw {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut s = self.0.lock().unwrap();
            if s.block_write {
                s.write_waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(bytes.len()))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut s = self.0.lock().unwrap();
            if s.block_write {
                s.write_waker = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn owner() -> Owner {
        Owner::new(
            &ShadowsocksPlugin::ShadowTls(crate::config::ShadowTlsConfig {
                server_name: "cover.invalid".into(),
                password: "synthetic-relay".into(),
                alpn: vec![],
                required_alpn: None,
                identity: None,
                certificate: Default::default(),
                client_fingerprint: None,
            }),
            &SecurityContext::new(),
            0,
            16384,
            443,
        )
        .unwrap()
    }
    #[test]
    fn shadowtls_owner_stop_wakes_independent_pending_callers_across_raw_operations() {
        // 0: flush pending then read ready; 1/2: read pending then raw
        // flush/shutdown ready; 3: read AND actual write pending under
        // distinct outer wakers; 4: read pending then actual write ready.
        // No raw event is externally fired in any case.
        for operation in 0..5 {
            let owner = owner();
            let state = Arc::new(Mutex::new(State {
                ready_read: operation == 0,
                block_write: operation == 0 || operation == 3,
                ..Default::default()
            }));
            let raw_weak = Arc::downgrade(&state);
            let mut io = owner.bind_stream(Box::new(Raw(state.clone())));
            let a = Arc::new(Count(AtomicUsize::new(0)));
            let b = Arc::new(Count(AtomicUsize::new(0)));
            let a_weak = Arc::downgrade(&a);
            let b_weak = Arc::downgrade(&b);
            let wa = Waker::from(a.clone());
            let wb = Waker::from(b.clone());
            let mut bytes = [0];
            let pending = if operation == 0 {
                Pin::new(&mut *io)
                    .poll_flush(&mut Context::from_waker(&wa))
                    .is_pending()
            } else {
                let mut out = ReadBuf::new(&mut bytes);
                Pin::new(&mut *io)
                    .poll_read(&mut Context::from_waker(&wa), &mut out)
                    .is_pending()
                    && out.filled().is_empty()
            };
            let independent_callers = !wa.will_wake(&wb);
            let payload = b"guard-write";
            let other_operation_ok = if operation == 0 {
                let mut out = ReadBuf::new(&mut bytes);
                matches!(
                    Pin::new(&mut *io).poll_read(&mut Context::from_waker(&wb), &mut out),
                    Poll::Ready(Ok(()))
                ) && out.filled() == &[42]
            } else if operation == 1 {
                matches!(
                    Pin::new(&mut *io).poll_flush(&mut Context::from_waker(&wb)),
                    Poll::Ready(Ok(()))
                )
            } else if operation == 2 {
                matches!(
                    Pin::new(&mut *io).poll_shutdown(&mut Context::from_waker(&wb)),
                    Poll::Ready(Ok(()))
                )
            } else if operation == 3 {
                Pin::new(&mut *io)
                    .poll_write(&mut Context::from_waker(&wb), payload)
                    .is_pending()
            } else {
                matches!(Pin::new(&mut *io).poll_write(&mut Context::from_waker(&wb), payload),
                    Poll::Ready(Ok(count)) if count == payload.len())
            };
            let raw_both_registered = {
                let s = state.lock().unwrap();
                s.read_waker.is_some() && s.write_waker.is_some()
            };
            let before_b = b.0.load(Ordering::SeqCst);
            let before = a.0.load(Ordering::SeqCst);
            owner.begin_shutdown();
            // Snapshot cancellation BEFORE stream Drop can wake waiter slots.
            let at_cancel = a.0.load(Ordering::SeqCst);
            let b_at_cancel = b.0.load(Ordering::SeqCst);
            let parent_cancelled = owner.cancel.is_cancelled();
            let revoked = !owner.permits_http_tcp_reuse();
            let stopped = if operation == 0 {
                Pin::new(&mut *io).poll_flush(&mut Context::from_waker(&wa))
            } else {
                Pin::new(&mut *io)
                    .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut bytes))
            };
            let aborted = matches!(&stopped, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            let other_aborted = operation != 3
                || matches!(
                Pin::new(&mut *io).poll_write(&mut Context::from_waker(&wb), payload),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
            drop(io);
            drop(owner);
            drop(wa);
            drop(wb);
            drop(a);
            drop(b);
            let raw_closed = {
                let s = state.lock().unwrap();
                s.dropped && s.read_waker.is_none() && s.write_waker.is_none()
            };
            drop(state);
            let all_closed = raw_weak.upgrade().is_none()
                && a_weak.upgrade().is_none()
                && b_weak.upgrade().is_none();
            assert!(raw_closed && all_closed);
            assert!(
                independent_callers
                    && pending
                    && other_operation_ok
                    && parent_cancelled
                    && revoked
                    && aborted
                    && other_aborted
            );
            if operation == 3 {
                assert!(raw_both_registered);
                assert_eq!(before_b, 0);
                assert!(b_at_cancel > before_b, "stop stranded the pending writer");
            }
            assert_eq!(before, 0, "prerequisite caller was already notified");
            assert!(
                at_cancel > before,
                "parent stop stranded an independent pending caller"
            );
        }
    }
    #[test]
    fn shadowtls_stream_drop_cancels_only_its_child_and_parent_stop_retires_sibling() {
        let owner = owner();
        let first = Arc::new(Mutex::new(State::default()));
        let second = Arc::new(Mutex::new(State::default()));
        let first_weak = Arc::downgrade(&first);
        let second_weak = Arc::downgrade(&second);
        let a = Arc::new(Count(AtomicUsize::new(0)));
        let a_weak = Arc::downgrade(&a);
        let wa = Waker::from(a.clone());
        let first_io = owner.bind_stream(Box::new(Raw(first.clone())));
        let mut second_io = owner.bind_stream(Box::new(Raw(second.clone())));
        drop(first_io);
        let owner_open = !owner.cancel.is_cancelled() && owner.permits_http_tcp_reuse();
        let mut bytes = [0];
        let pending = Pin::new(&mut *second_io)
            .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut bytes))
            .is_pending();
        let before = a.0.load(Ordering::SeqCst);
        owner.begin_shutdown();
        let at_cancel = a.0.load(Ordering::SeqCst);
        let stopped = Pin::new(&mut *second_io)
            .poll_read(&mut Context::from_waker(&wa), &mut ReadBuf::new(&mut bytes));
        let aborted = matches!(&stopped, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionAborted);
        let revoked = !owner.permits_http_tcp_reuse();
        drop(second_io);
        drop(owner);
        drop(wa);
        drop(a);
        let raw_closed = first.lock().unwrap().dropped && second.lock().unwrap().dropped;
        drop(first);
        drop(second);
        let all_closed = first_weak.upgrade().is_none()
            && second_weak.upgrade().is_none()
            && a_weak.upgrade().is_none();
        assert!(raw_closed && all_closed);
        assert!(owner_open && pending && revoked && aborted);
        assert_eq!(before, 0);
        assert!(at_cancel > before);
    }
}

#[cfg(all(test, feature = "inbound-http"))]
#[path = "obfs_reuse_owner_memory_tests.rs"]
mod obfs_reuse_owner_memory_tests;

#[cfg(all(test, feature = "inbound-http"))]
pub(super) mod obfs_reuse_memory_tests;

#[cfg(all(test, feature = "inbound-http"))]
mod v2ray_mux_reuse_owner_memory_tests;

#[cfg(all(test, feature = "inbound-http"))]
pub(super) mod v2ray_mux_reuse_memory_tests;
