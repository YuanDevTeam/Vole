//! Client-owned kcptun sessions over existing protected UDP paths.
//! KCP, FEC and Snappy are distinct from VMess mKCP's wire format.
mod crypto;
mod driver;
mod fec;
mod snappy;
use super::smux;
use crate::{
    config::KcptunConfig,
    dispatch::{BoxStream, DatagramBudget, DispatchError},
    outbound::{DatagramRequest, EstablishContext, UpstreamPath},
    session::{DatagramSession, Destination, StreamSession},
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
struct Connection {
    client: smux::Client,
    cancel: CancellationToken,
    expires: Option<Instant>,
    _observation: crate::resources::observation::Guard,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct State {
    slots: Vec<Option<Connection>>,
    retired: Vec<(Connection, Instant)>,
    next: usize,
    closed: bool,
}
pub(crate) struct Owner {
    options: KcptunConfig,
    crypto: Arc<crypto::PacketCrypt>,
    state: Mutex<State>,
    opening: tokio::sync::Mutex<()>,
    cancel: CancellationToken,
    tasks: TaskTracker,
}
impl Owner {
    pub(crate) fn new(options: KcptunConfig) -> io::Result<Self> {
        let crypto = Arc::new(crypto::PacketCrypt::new(&options.key, &options.crypt)?);
        let slots = (0..options.connections).map(|_| None).collect();
        Ok(Self {
            options,
            crypto,
            state: Mutex::new(State {
                slots,
                retired: Vec::new(),
                next: 0,
                closed: false,
            }),
            opening: Default::default(),
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        })
    }
    pub(crate) async fn open(
        &self,
        upstream: &UpstreamPath,
        server: &Destination,
        session: &StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        context
            .run_io("Shadowsocks kcptun session", async {
                tokio::select! {biased;
                    ()=self.cancel.cancelled()=>Err(io::ErrorKind::ConnectionAborted.into()),
                    result=self.open_inner(upstream,server,session,context)=>result,
                }
            })
            .await
    }
    async fn open_inner(
        &self,
        upstream: &UpstreamPath,
        server: &Destination,
        session: &StreamSession,
        context: &EstablishContext,
    ) -> io::Result<BoxStream> {
        let _opening = self.opening.lock().await;
        let (index, existing) = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            let now = Instant::now();
            state
                .retired
                .retain(|(connection, expires)| !connection.client.is_closed() && *expires > now);
            let index = state.next % state.slots.len();
            state.next = state.next.wrapping_add(1);
            if state.slots[index]
                .as_ref()
                .is_some_and(|c| c.client.is_closed() || c.expires.is_some_and(|at| at <= now))
            {
                let old = state.slots[index].take().unwrap();
                if !old.client.is_closed() {
                    if state.retired.len() == 16 {
                        state.retired.remove(0);
                    }
                    let cancel = old.cancel.clone();
                    let ttl = Duration::from_secs(u64::from(self.options.scavengettl));
                    self.tasks.spawn(async move {tokio::select!{biased;()=cancel.cancelled()=>{},_=tokio::time::sleep(ttl)=>cancel.cancel(),}});
                    state.retired.push((
                        old,
                        now + Duration::from_secs(u64::from(self.options.scavengettl)),
                    ));
                }
            }
            (index, state.slots[index].as_ref().map(|c| c.client.clone()))
        };
        let client = if let Some(client) = existing {
            client
        } else {
            let peer = upstream
                .datagram_server(server, context)
                .await
                .map_err(io::Error::other)?;
            let address = context.resolve_ip(&peer).await.map_err(io::Error::other)?;
            let request =
                DatagramRequest::new(DatagramSession::new(session.inbound, session.source))
                    .with_budget(DatagramBudget::new(self.options.mtu, 1500))
                    .with_kcptun_socket(self.options.socket_buffer, self.options.dscp);
            let transport = upstream
                .open_datagram(request, context)
                .await
                .map_err(io::Error::other)?;
            let cancel = self.cancel.child_token();
            let (raw, driver) = driver::attach(
                transport,
                Destination::Ip(address),
                self.options.clone(),
                self.crypto.clone(),
                cancel.clone(),
            )?;
            let raw = if self.options.no_comp {
                raw
            } else {
                snappy::wrap(raw)
            };
            let (client, smux) = smux::with_options(
                raw,
                smux::Options {
                    version: self.options.smux_version,
                    frame_size: self.options.frame_size,
                    receive_buffer: self.options.smux_buffer,
                    stream_buffer: self.options.stream_buffer,
                    keepalive: Some(Duration::from_secs(u64::from(self.options.keepalive))),
                },
            )?;
            let stopped = cancel.clone();
            let guard = crate::resources::observation::track(
                crate::resources::observation::ResourceKind::Task,
            );
            let task = crate::resources::observation::bind(async move {
                let _guard = guard;
                // The UDP driver owns its close path. Always join it after the
                // smux endpoint stops instead of detaching or dropping it.
                tokio::pin!(driver);
                tokio::select! {biased;()=stopped.cancelled()=>{},_=&mut driver=>{stopped.cancel();return;},_=smux=>{}}
                stopped.cancel();
                let _ = driver.await;
            });
            let connection = Connection {
                _observation: crate::resources::observation::track(
                    crate::resources::observation::ResourceKind::Pool,
                ),
                client: client.clone(),
                cancel,
                expires: (self.options.autoexpire > 0).then(|| {
                    Instant::now() + Duration::from_secs(u64::from(self.options.autoexpire))
                }),
            };
            // Admission and registration share the shutdown mutex. Stop cannot
            // finish waiting and subsequently gain a new owned driver.
            let unregistered = {
                let mut state = self.state.lock().unwrap();
                if state.closed {
                    Some(task)
                } else {
                    self.tasks.spawn(task);
                    state.slots[index] = Some(connection);
                    None
                }
            };
            if let Some(task) = unregistered {
                // No task was registered: this future owns and joins UDP close.
                // The mutex is released before polling any I/O.
                task.await;
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            client
        };
        client.open().await
    }
    pub(crate) fn begin_shutdown(&self) {
        self.cancel.cancel();
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.slots.clear();
        state.retired.clear();
        self.tasks.close();
    }
    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        self.tasks.wait().await;
    }
}
