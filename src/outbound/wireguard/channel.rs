use super::{datagram::Registry, peer, routes::Routes};
use crate::{
    config::WireGuardOutboundConfig,
    dispatch::DispatchError,
    outbound::{EstablishContext, UpstreamPath},
    resources::observation,
    session::DatagramSession,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{Packet, PacketSink};
#[derive(Clone, Copy)]
pub(super) enum Ready {
    Waiting,
    Established,
    Failed,
}
pub(super) struct Refresh {
    pub context: EstablishContext,
    pub reply: oneshot::Sender<()>,
}
pub(super) struct Channel {
    pub tx: mpsc::Sender<Packet>,
    pub cancel: CancellationToken,
    ready: watch::Receiver<Ready>,
    commands: mpsc::Sender<Refresh>,
    initial: EstablishContext,
    updated: Arc<Mutex<Instant>>,
    refresh: AsyncMutex<()>,
    task: Mutex<Option<JoinHandle<()>>>,
    stop: AsyncMutex<()>,
}
impl Channel {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        config: Arc<WireGuardOutboundConfig>,
        index: usize,
        upstream: UpstreamPath,
        session: DatagramSession,
        context: EstablishContext,
        cancel: CancellationToken,
        sink: PacketSink,
        registry: Arc<Registry>,
        routes: Arc<Routes>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(32);
        let (ready, state) = watch::channel(Ready::Waiting);
        let (commands, requests) = mpsc::channel(1);
        let updated = Arc::new(Mutex::new(Instant::now()));
        let channel = Arc::new(Self {
            tx,
            cancel: cancel.clone(),
            ready: state,
            commands,
            initial: context.clone(),
            updated: updated.clone(),
            refresh: AsyncMutex::new(()),
            task: Mutex::new(None),
            stop: AsyncMutex::new(()),
        });
        let task = observation::spawn(peer::drive(
            config, index, upstream, session, context, cancel, rx, requests, ready, sink, registry,
            routes, updated,
        ));
        *channel.task.lock().unwrap() = Some(task);
        channel
    }
    pub fn is_ready(&self) -> bool {
        !self.cancel.is_cancelled() && matches!(*self.ready.borrow(), Ready::Established)
    }
    pub async fn wait_ready(&self, context: &EstablishContext) -> Result<(), DispatchError> {
        let mut ready = self.ready.clone();
        context.run("WireGuard handshake",async{
            loop {
                match *ready.borrow_and_update(){Ready::Established=>return Ok(()),Ready::Failed=>return Err(DispatchError::ConnectionRefused),Ready::Waiting=>{}}
                tokio::select!{biased;()=self.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),result=ready.changed()=>if result.is_err(){return Err(DispatchError::ConnectionRefused);}}
            }
        }).await
    }
    pub async fn refresh_if_due(&self, interval: i64, caller: &EstablishContext) {
        if interval == 0 || !self.is_ready() {
            return;
        }
        let Ok(_guard) = self.refresh.try_lock() else {
            return;
        };
        if self.updated.lock().unwrap().elapsed() < Duration::from_secs(interval.max(0) as u64) {
            return;
        }
        let context = self
            .initial
            .authenticated_continuation()
            .capped_by(caller.deadline());
        let (reply, done) = oneshot::channel();
        let _ = tokio::select! {biased;()=self.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),result=caller.run("WireGuard endpoint refresh",async{
            self.commands.send(Refresh{context,reply}).await.map_err(|_|DispatchError::ConnectionRefused)?;
            done.await.map_err(|_|DispatchError::ConnectionRefused)
        })=>result};
    }
    pub async fn stop(&self) {
        let _guard = self.stop.lock().await;
        self.cancel.cancel();
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.get_mut().unwrap().take() {
            task.abort();
        }
    }
}
