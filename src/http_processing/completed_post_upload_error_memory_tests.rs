//! Completed-upload admission and retirement over actual memory IO.
//! This private exchange test uses actual Hyper/H2 framing over duplex IO.
//! The input owner is an HTTP/1 body with a declared eight-byte length which
//! really ends after one byte. It is not a synthetic completion boolean.
//! The downstream has one byte of response credit, so a valid final response
//! cannot finish before the upload error has actually propagated upstream.
use super::*;
use crate::{
    dispatch::{DatagramTransport, DispatchError, Dispatcher, HttpTcpReuseKey},
    http_processing::config::Document,
    security::SecurityContext,
    session::{DatagramSession, Destination, InboundKind, InboundMetadata},
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    collections::VecDeque,
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{io::AsyncWriteExt, task::JoinHandle};

const WAIT: Duration = Duration::from_secs(3);
const REPLY: &[u8] = b"origin";

#[derive(Clone)]
struct UploadErrorWitness {
    count: Arc<AtomicUsize>,
    observed: Arc<tokio::sync::Notify>,
}
tokio::task_local! {
    static UPLOAD_ERROR_WITNESS: UploadErrorWitness;
}
pub(super) fn observe_late_upload_error() {
    let _ = UPLOAD_ERROR_WITNESS.try_with(|witness| {
        witness.count.fetch_add(1, Ordering::AcqRel);
        witness.observed.notify_one();
    });
}
struct Empty;
impl hyper::body::Body for Empty {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        Poll::Ready(None)
    }
    fn is_end_stream(&self) -> bool {
        true
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(0)
    }
}
struct UnusedDispatcher;
#[async_trait]
impl Dispatcher for UnusedDispatcher {
    async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}
fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(443),
        inbound: InboundKind::Tun,
        source: "198.18.0.2:30000".parse().unwrap(),
        destination: Destination::Ip("203.0.113.1:443".parse().unwrap()),
        sniffed_domain: Some("a.test".into()),
    }
}
fn error<E>(_: E) -> io::Error {
    failed()
}

fn origin_pair(
    stop: CancellationToken,
    incomplete: Arc<tokio::sync::Notify>,
    received: Arc<AtomicUsize>,
    phase: Arc<AtomicUsize>,
) -> (BoxStream, JoinHandle<io::Result<()>>) {
    let (client, peer) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move {
        let operation = async {
            phase.store(1, Ordering::Release);
            let mut connection = h2::server::handshake::<_>(peer).await.map_err(error)?;
            phase.store(2, Ordering::Release);
            let mut exchange: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>> = None;
            loop {
                tokio::select! {biased;
                    result=async { exchange.as_mut().expect("guarded exchange").await },if exchange.is_some()=>{
                        result?;
                        exchange = None;
                    },
                    accepted=connection.accept()=>match accepted {
                        Some(Ok((request, mut response)))=>{
                            phase.store(3, Ordering::Release);
                            if exchange.is_some() { return Err(failed()); }
                            let incomplete = incomplete.clone();
                            let received = received.clone();
                            let phase = phase.clone();
                            exchange = Some(Box::pin(async move {
                                let mut input = request.into_body();
                                let prefix = input.data().await.ok_or_else(failed)?.map_err(error)?;
                                if prefix.as_ref() != b"x" { return Err(failed()); }
                                received.fetch_add(prefix.len(), Ordering::AcqRel);
                                phase.store(4, Ordering::Release);
                                input.flow_control().release_capacity(prefix.len()).map_err(error)?;
                                let mut body = response.send_response(Response::builder().header("content-length", REPLY.len()).body(()).map_err(error)?, false).map_err(error)?;
                                body.send_data(Bytes::from_static(REPLY), true).map_err(error)?;
                                phase.store(5, Ordering::Release);
                                // A completed download cannot drop this upload:
                                // the downstream deliberately withholds credit.
                                // Only real truncated-source propagation ends it.
                                match input.data().await {
                                    Some(Ok(_)) => return Err(failed()),
                                    Some(Err(_)) | None => incomplete.notify_one(),
                                }
                                phase.store(6, Ordering::Release);
                                Ok::<_, io::Error>(())
                            }) as Pin<Box<dyn Future<Output=io::Result<()>> + Send>>);
                        },
                        Some(Err(_)) | None => return Ok(()),
                    }
                }
            }
        };
        tokio::select! {biased; ()=stop.cancelled()=>Ok(()), result=operation=>result}
    });
    (Box::new(client), task)
}

#[tokio::test]
async fn completed_post_h2_upload_error_after_final_headers_preserves_reply_and_retires() {
    let stop = CancellationToken::new();
    let close_source = CancellationToken::new();
    let incomplete = Arc::new(tokio::sync::Notify::new());
    let received = Arc::new(AtomicUsize::new(0));
    let opens = AtomicUsize::new(0);
    let witness = UploadErrorWitness {
        count: Arc::new(AtomicUsize::new(0)),
        observed: Arc::new(tokio::sync::Notify::new()),
    };
    let phase = AtomicUsize::new(0);
    let source_driver_phase = Arc::new(AtomicUsize::new(0));
    let origin_phases: [Arc<AtomicUsize>; 2] =
        std::array::from_fn(|_| Arc::new(AtomicUsize::new(0)));
    let mut tasks: Vec<JoinHandle<io::Result<()>>> = Vec::new();
    let result = AssertUnwindSafe(async {
        timeout(WAIT * 3, async {
            phase.store(1, Ordering::Release);
            let (source_client, mut source_peer) = tokio::io::duplex(8192);
            let source_stop = stop.clone();
            let source_close = close_source.clone();
            tasks.push(tokio::spawn(async move {
                tokio::select! {biased;
                    ()=source_stop.cancelled()=>Ok(()),
                    result=async {
                        let mut head = Vec::new();
                        while !head.ends_with(b"\r\n\r\n") && head.len() < 32768 {
                            head.push(tokio::io::AsyncReadExt::read_u8(&mut source_peer).await?);
                        }
                        source_peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nx").await?;
                        source_peer.flush().await?;
                        source_close.cancelled().await;
                        // Drop with a genuine Content-Length deficit.
                        Ok::<_, io::Error>(())
                    }=>result,
                }
            }));
            let (mut source_sender, source_driver) = hyper::client::conn::http1::handshake::<_, Empty>(hyper_util::rt::TokioIo::new(source_client)).await.map_err(error)?;
            let source_stop = stop.clone();
            let driver_phase = source_driver_phase.clone();
            tasks.push(tokio::spawn(async move {
                // Its framing failure is the explicit fault under test.
                driver_phase.store(1, Ordering::Release);
                tokio::select! {biased;
                    ()=source_stop.cancelled()=>{driver_phase.store(4, Ordering::Release);},
                    result=source_driver=>{driver_phase.store(if result.is_err() {3} else {2}, Ordering::Release);}
                }
                Ok(())
            }));
            phase.store(10, Ordering::Release);
            let source_response = source_sender.send_request(Request::builder().uri("/source").body(Empty).map_err(error)?).await.map_err(error)?;
            phase.store(11, Ordering::Release);
            drop(source_sender);
            let source = h2_body::Source::h1(source_response.into_body());

            let mut origins = VecDeque::new();
            for origin_phase in &origin_phases {
                let (io, owner) = origin_pair(stop.clone(), incomplete.clone(), received.clone(), origin_phase.clone());
                origins.push_back(io);
                tasks.push(owner);
            }
            let (sessions, mut parent) = h2_reuse::new();
            let parent_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                loop { tokio::select! {biased; ()=parent_stop.cancelled()=>return Ok(()), ()=parent.progress()=>{}} }
            }));
            let url = url::Url::parse("https://a.test/upload").map_err(error)?;
            let identity = || h2_reuse::Identity::new(HttpTcpReuseKey::new(1_u8), &url);
            let first_io = origins.pop_front().ok_or_else(failed)?;
            let open_count = &opens;
            phase.store(20, Ordering::Release);
            let lease = match sessions.acquire(identity(), Instant::now()+SETUP, move || async move {
                open_count.fetch_add(1, Ordering::AcqRel);
                Ok((first_io, Some(b"h2".to_vec())))
            }).await? {
                h2_reuse::Acquired::Shared(lease)=>lease,
                _=>return Err(failed()),
            };
            phase.store(21, Ordering::Release);

            let (down_client, down_server) = tokio::io::duplex(8192);
            let mut builder = h2::client::Builder::new();
            builder.initial_window_size(1);
            let (mut down_sender, down_driver) = builder.handshake::<_, Bytes>(down_client).await.map_err(error)?;
            let down_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                tokio::select! {biased; ()=down_stop.cancelled()=>Ok(()), result=down_driver=>result.map_err(error)}
            }));
            phase.store(30, Ordering::Release);
            let mut down_connection = h2::server::handshake::<_>(down_server).await.map_err(error)?;
            phase.store(31, Ordering::Release);
            let (down_response, _) = down_sender.send_request(Request::builder().uri("https://a.test/upload").body(()).map_err(error)?, true).map_err(error)?;
            phase.store(32, Ordering::Release);
            let (_, response) = down_connection.accept().await.ok_or_else(failed)?.map_err(error)?;
            phase.store(33, Ordering::Release);
            let down_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                loop { tokio::select! {biased;
                    ()=down_stop.cancelled()=>return Ok(()),
                    accepted=down_connection.accept()=>match accepted {
                        Some(Ok(_))=>return Err(failed()),
                        Some(Err(_))|None=>return Ok(()),
                    }
                }}
            }));
            let response = ResponseSlot(Arc::new(Mutex::new(ResponseState { response, infos:0, final_started:false, upstream_final_received:false })));
            let policy = Document::parse("{}").map_err(error)?.compile(&std::collections::BTreeMap::new()).map_err(error)?.bind_ca(None).map_err(error)?;
            let context = HttpContext::new(policy, Arc::new(UnusedDispatcher), SecurityContext::default());
            let target = Target { original:url.clone(), url:url.clone(), session:session(), logical_destination:Destination::domain("a.test",443).map_err(error)?, strip_origin_credentials:false };
            let metadata = MessageMeta { original:OriginalRequestMeta::new("POST", &vec![]), length:Some(8), asterisk:false, script:None };
            let request = Request::builder().method("POST").uri(url.as_str()).header("content-length",8).body(source).map_err(error)?;
            let exchange = UPLOAD_ERROR_WITNESS.scope(witness.clone(), context.h2_exchange(UpstreamSender::Shared(&lease), request, &response, target, metadata));
            phase.store(40, Ordering::Release);
            let observe = async {
                phase.store(41, Ordering::Release);
                let response = down_response.await.map_err(error)?;
                phase.store(42, Ordering::Release);
                if response.status()!=StatusCode::OK { return Err(failed()); }
                // This is the actual downstream receipt of final headers.
                close_source.cancel();
                phase.store(43, Ordering::Release);
                // Observe the actual upload-error-after-final-head branch.
                // Dropping SendStream alone need not reset the request while
                // its response owner remains alive; that is not a valid gate.
                witness.observed.notified().await;
                phase.store(44, Ordering::Release);
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while let Some(frame) = body.data().await {
                    let frame = frame.map_err(error)?;
                    bytes.extend_from_slice(&frame);
                    body.flow_control().release_capacity(frame.len()).map_err(error)?;
                }
                if bytes != REPLY { return Err(failed()); }
                phase.store(45, Ordering::Release);
                Ok::<_, io::Error>(())
            };
            let (exchange, observed) = tokio::join!(exchange, observe);
            phase.store(50, Ordering::Release);
            exchange?;
            observed?;
            if witness.count.load(Ordering::Acquire)!=1 { return Err(io::Error::other("late upload error branch was not observed exactly once")); }
            if received.load(Ordering::Acquire)!=1 { return Err(failed()); }
            drop(lease);
            let second_io = origins.pop_front().ok_or_else(failed)?;
            let open_count = &opens;
            phase.store(60, Ordering::Release);
            let next = sessions.acquire(identity(), Instant::now()+SETUP, move || async move {
                open_count.fetch_add(1, Ordering::AcqRel);
                Ok((second_io, Some(b"h2".to_vec())))
            }).await?;
            drop(next);
            phase.store(61, Ordering::Release);
            drop((down_sender, sessions));
            if opens.load(Ordering::Acquire)!=2 {
                return Err(io::Error::other("upload failure after final headers retained admission"));
            }
            Ok::<_, io::Error>(())
        }).await.map_err(|_| io::Error::other(format!(
            "controlled POST exchange deadline: phase={}, sourceDriver={}, originPhases={:?}, received={}, opens={}, lateUploadErrors={}",
            phase.load(Ordering::Acquire), source_driver_phase.load(Ordering::Acquire),
            origin_phases.each_ref().map(|value| value.load(Ordering::Acquire)),
            received.load(Ordering::Acquire), opens.load(Ordering::Acquire), witness.count.load(Ordering::Acquire)
        )))?
    }).catch_unwind().await;
    stop.cancel();
    close_source.cancel();
    let mut join_errors = Vec::new();
    for mut task in tasks {
        match timeout(WAIT, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(other) => join_errors.push(format!("owned duplex task: {other:?}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                join_errors.push("owned duplex task required abort".into());
            }
        }
    }
    assert!(join_errors.is_empty(), "{join_errors:?}");
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(result.is_ok(), "{result:?}");
}

// Track the physical IO owners while a sibling keeps a retired session alive.
struct DropOwnedIo {
    io: tokio::io::DuplexStream,
    live: Arc<AtomicUsize>,
}
impl DropOwnedIo {
    fn new(io: tokio::io::DuplexStream, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self {
            io,
            live: live.clone(),
        }
    }
}
impl Drop for DropOwnedIo {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}
impl tokio::io::AsyncRead for DropOwnedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, bytes)
    }
}
impl tokio::io::AsyncWrite for DropOwnedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn drop_origin_pair(
    stop: CancellationToken,
    dropped_request_started: CancellationToken,
    sibling_started: CancellationToken,
    release_sibling: CancellationToken,
    live: &Arc<AtomicUsize>,
) -> (BoxStream, JoinHandle<io::Result<()>>) {
    let (client, peer) = tokio::io::duplex(8192);
    let client = DropOwnedIo::new(client, live);
    let peer = DropOwnedIo::new(peer, live);
    let owner = tokio::spawn(async move {
        let operation = async {
            let mut connection = h2::server::handshake::<_>(peer).await.map_err(error)?;
            let mut exchanges = FuturesUnordered::new();
            loop {
                tokio::select! {biased;
                    result=exchanges.next(),if !exchanges.is_empty()=>{ if let Some(result) = result { result?; } },
                    accepted=connection.accept()=>match accepted {
                        Some(Ok((request, mut response)))=>{
                            let dropped_request_started = dropped_request_started.clone();
                            let sibling_started = sibling_started.clone();
                            let release_sibling = release_sibling.clone();
                            exchanges.push(async move {
                                if request.uri().path()=="/drop" {
                                    let mut input = request.into_body();
                                    let prefix = input.data().await.ok_or_else(failed)?.map_err(error)?;
                                    if prefix.as_ref()!=b"x" { return Err(failed()); }
                                    input.flow_control().release_capacity(prefix.len()).map_err(error)?;
                                    dropped_request_started.cancel();
                                    // No response and no upload EOS: the actual
                                    // request future remains in flight until Drop.
                                    if let Some(Ok(_)) = input.data().await { return Err(failed()); }
                                    return Ok::<_,io::Error>(());
                                }
                                if request.uri().path()!="/sibling" || !request.body().is_end_stream() { return Err(failed()); }
                                sibling_started.cancel();
                                release_sibling.cancelled().await;
                                let mut body = response.send_response(Response::builder().header("content-length",REPLY.len()).body(()).map_err(error)?, false).map_err(error)?;
                                body.send_data(Bytes::from_static(REPLY),true).map_err(error)?;
                                Ok(())
                            });
                        },
                        Some(Err(_))|None=>return Ok::<_,io::Error>(()),
                    }
                }
            }
        };
        tokio::select! {biased; ()=stop.cancelled()=>Ok(()), result=operation=>result}
    });
    (Box::new(client), owner)
}
fn drop_target(path: &str) -> io::Result<Target> {
    let url = url::Url::parse(&format!("https://a.test/{path}")).map_err(error)?;
    Ok(Target {
        original: url.clone(),
        url,
        session: session(),
        logical_destination: Destination::domain("a.test", 443).map_err(error)?,
        strip_origin_credentials: false,
    })
}
fn drop_metadata(method: &str, length: Option<u64>) -> MessageMeta {
    MessageMeta {
        original: OriginalRequestMeta::new(method, &vec![]),
        length,
        asterisk: false,
        script: None,
    }
}

#[tokio::test]
async fn completed_post_h2_dropped_exchange_retires_admission_without_cancelling_sibling() {
    let stop = CancellationToken::new();
    let drop_started = CancellationToken::new();
    let sibling_started = CancellationToken::new();
    let release_sibling = CancellationToken::new();
    let live = Arc::new(AtomicUsize::new(0));
    let opens = AtomicUsize::new(0);
    let phase = AtomicUsize::new(0);
    let mut tasks: Vec<JoinHandle<io::Result<()>>> = Vec::new();
    let result = AssertUnwindSafe(async {
        timeout(WAIT*3, async {
            let mut origins = VecDeque::new();
            for _ in 0..2 {
                let (io, owner) = drop_origin_pair(stop.clone(),drop_started.clone(),sibling_started.clone(),release_sibling.clone(),&live);
                origins.push_back(io);
                tasks.push(owner);
            }
            let (sessions,mut parent) = h2_reuse::new();
            let parent_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                loop { tokio::select! {biased; ()=parent_stop.cancelled()=>return Ok(()), ()=parent.progress()=>{}} }
            }));
            let url = url::Url::parse("https://a.test/").map_err(error)?;
            let identity = || h2_reuse::Identity::new(HttpTcpReuseKey::new(2_u8),&url);
            phase.store(10,Ordering::Release);
            let first = sessions.acquire(identity(),Instant::now()+SETUP,|| {
                opens.fetch_add(1,Ordering::AcqRel);
                let io = origins.pop_front();
                async move { Ok((io.ok_or_else(failed)?,Some(b"h2".to_vec()))) }
            }).await?;
            let h2_reuse::Acquired::Shared(first_lease) = first else {return Err(failed());};
            let sibling = sessions.acquire(identity(),Instant::now()+SETUP,|| {
                opens.fetch_add(1,Ordering::AcqRel);
                let io = origins.pop_front();
                async move { Ok((io.ok_or_else(failed)?,Some(b"h2".to_vec()))) }
            }).await?;
            let h2_reuse::Acquired::Shared(sibling_lease) = sibling else {return Err(failed());};
            if opens.load(Ordering::Acquire)!=1 {return Err(io::Error::other("sibling did not acquire the same initial physical owner"));}

            let (client,server) = tokio::io::duplex(8192);
            let (mut sender,driver) = h2::client::handshake::<_>(client).await.map_err(error)?;
            let client_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                tokio::select! {biased; ()=client_stop.cancelled()=>Ok(()), result=driver=>result.map_err(error)}
            }));
            let mut connection = h2::server::handshake::<_>(server).await.map_err(error)?;
            let (first_response,mut first_input) = sender.send_request(Request::builder().method("POST").uri("https://a.test/drop").header("content-length",8).body(()).map_err(error)?,false).map_err(error)?;
            first_input.send_data(Bytes::from_static(b"x"),false).map_err(error)?;
            let (first_request,first_response_owner) = connection.accept().await.ok_or_else(failed)?.map_err(error)?;
            let (sibling_response,_) = sender.send_request(Request::builder().uri("https://a.test/sibling").body(()).map_err(error)?,true).map_err(error)?;
            let (sibling_request,sibling_response_owner) = connection.accept().await.ok_or_else(failed)?.map_err(error)?;
            let server_stop = stop.clone();
            tasks.push(tokio::spawn(async move {
                loop {tokio::select! {biased;
                    ()=server_stop.cancelled()=>return Ok(()),
                    accepted=connection.accept()=>match accepted {Some(Ok(_))=>return Err(failed()),Some(Err(_))|None=>return Ok(())}
                }}
            }));
            let first_slot = ResponseSlot(Arc::new(Mutex::new(ResponseState {response:first_response_owner,infos:0,final_started:false,upstream_final_received:false})));
            let sibling_slot = ResponseSlot(Arc::new(Mutex::new(ResponseState {response:sibling_response_owner,infos:0,final_started:false,upstream_final_received:false})));
            let policy = Document::parse("{}").map_err(error)?.compile(&std::collections::BTreeMap::new()).map_err(error)?.bind_ca(None).map_err(error)?;
            let context = HttpContext::new(policy,Arc::new(UnusedDispatcher),SecurityContext::default());
            let first_request = Request::builder().method("POST").uri("https://a.test/drop").header("content-length",8).body(h2_body::Source::h2(first_request.into_body())).map_err(error)?;
            let sibling_request = Request::builder().uri("https://a.test/sibling").body(h2_body::Source::h2(sibling_request.into_body())).map_err(error)?;
            let mut first_exchange = Box::pin(context.h2_exchange(UpstreamSender::Shared(&first_lease),first_request,&first_slot,drop_target("drop")?,drop_metadata("POST",Some(8))));
            let mut sibling_exchange = Box::pin(context.h2_exchange(UpstreamSender::Shared(&sibling_lease),sibling_request,&sibling_slot,drop_target("sibling")?,drop_metadata("GET",None)));
            phase.store(20,Ordering::Release);
            tokio::select! {biased;
                _=&mut first_exchange=>return Err(io::Error::other("first exchange completed before Drop")),
                _=&mut sibling_exchange=>return Err(io::Error::other("sibling completed before admission check")),
                ()=async {drop_started.cancelled().await;sibling_started.cancelled().await;}=>{},
            }
            // Drop just this in-flight future. Sessions, Parent, the sibling
            // lease, downstream connection and normal runtime remain alive.
            drop(first_exchange);
            drop(first_lease);
            drop((first_response,first_input,first_slot));
            phase.store(30,Ordering::Release);
            let next = sessions.acquire(identity(),Instant::now()+SETUP,|| {
                opens.fetch_add(1,Ordering::AcqRel);
                let io = origins.pop_front();
                async move { Ok((io.ok_or_else(failed)?,Some(b"h2".to_vec()))) }
            }).await?;
            let changed = opens.load(Ordering::Acquire)==2;
            drop(next);
            phase.store(40,Ordering::Release);
            release_sibling.cancel();
            let observe = async {
                let response = sibling_response.await.map_err(error)?;
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while let Some(frame) = body.data().await {
                    let frame = frame.map_err(error)?;
                    bytes.extend_from_slice(&frame);
                    body.flow_control().release_capacity(frame.len()).map_err(error)?;
                }
                if bytes!=REPLY {return Err(failed());}
                Ok::<_,io::Error>(())
            };
            let (completed,observed) = tokio::join!(sibling_exchange,observe);
            completed?;
            observed?;
            drop((sibling_lease,sender,sessions));
            phase.store(50,Ordering::Release);
            if !changed {return Err(io::Error::other("dropped exchange retained future admission while sibling was in flight"));}
            Ok::<_,io::Error>(())
        }).await.map_err(|_|io::Error::other(format!("Drop-only exchange deadline: phase={},opens={},live={}",phase.load(Ordering::Acquire),opens.load(Ordering::Acquire),live.load(Ordering::Acquire))))?
    }).catch_unwind().await;
    stop.cancel();
    release_sibling.cancel();
    let mut failures = Vec::new();
    for mut task in tasks {
        match timeout(WAIT, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(other) => failures.push(format!("owned Drop-only task: {other:?}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                failures.push("Drop-only task required abort".into());
            }
        }
    }
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(live.load(Ordering::Acquire), 0);
    let result = match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    assert!(result.is_ok(), "{result:?}");
}
