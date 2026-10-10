//! Standard WireGuard over shared controlled UDP and the active raw-IP stack.
mod datagram;
mod engine;
mod peer;
#[cfg(test)]
mod tests;

use crate::{
    config::WireGuardOutboundConfig,
    dispatch::{DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, UpstreamPath,
        owned_stream::OwnedStream, server_destination,
    },
    resources::observation,
    session::{DatagramSession, Destination, StreamSession},
};
use async_trait::async_trait;
use engine::Engine;
use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub struct WireGuardOutbound {
    config: Arc<WireGuardOutboundConfig>,
    server: Destination,
    upstream: UpstreamPath,
    current: AsyncMutex<Option<Arc<Engine>>>,
    cancel: CancellationToken,
    admission: Mutex<()>,
    retired: TaskTracker,
}
impl std::fmt::Debug for WireGuardOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardOutbound").finish_non_exhaustive()
    }
}
impl WireGuardOutbound {
    pub fn new_with_path(
        config: &WireGuardOutboundConfig,
        upstream: UpstreamPath,
    ) -> io::Result<Self> {
        config.validate().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WireGuard configuration",
            )
        })?;
        Ok(Self {
            config: Arc::new(config.clone()),
            server: server_destination(&config.address, config.port)?,
            upstream,
            current: AsyncMutex::new(None),
            cancel: CancellationToken::new(),
            admission: Mutex::new(()),
            retired: TaskTracker::new(),
        })
    }
    async fn engine(
        &self,
        session: DatagramSession,
        context: &EstablishContext,
    ) -> Result<Arc<Engine>, DispatchError> {
        let engine = tokio::select! { biased;
            ()=self.cancel.cancelled()=>return Err(DispatchError::NotAllowed),
            result=context.run("WireGuard initialize",async {
                let mut current=self.current.lock().await;
                if let Some(engine)=current.as_ref().filter(|engine|!engine.cancel.is_cancelled()) { return Ok(engine.clone()); }
                let _admission=self.admission.lock().unwrap();
                if self.cancel.is_cancelled() {return Err(DispatchError::NotAllowed);}
                if let Some(old)=current.take() {self.retired.spawn(observation::task(async move {old.stop().await;}));}
                let engine=Engine::start(self.config.clone(),self.server.clone(),self.upstream.clone(),session,context.clone(),self.cancel.child_token())?;
                // Publish ownership before waiting for network setup or authentication.
                *current=Some(engine.clone());
                Ok(engine)
            })=>result?,
        };
        engine.wait_ready(context).await?;
        Ok(engine)
    }
}
#[async_trait]
impl OutboundConnector for WireGuardOutbound {
    async fn connect_stream(
        &self,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        let datagram =
            DatagramSession::new(session.inbound, session.source).with_metadata(session.metadata);
        let engine = self.engine(datagram, context).await?;
        let resolution = context.resolution();
        let remote = tokio::select! {biased; ()=engine.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),result=resolution.resolve_local_family(&session.destination, context.deadline(), engine.ipv4.is_some(), engine.ipv6.is_some())=>result?};
        engine.local(remote.ip())?;
        let stream = tokio::select! {biased;
            ()=engine.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
            result=context.run_io("WireGuard TCP",engine.tcp.connect(remote,context.deadline()))=>result?,
        };
        Ok(ConnectedStream {
            io: Box::new(OwnedStream::new(
                Box::new(stream),
                engine.cancel.child_token(),
            )),
            effective_peer: Destination::Ip(remote),
        })
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let engine = self.engine(request.session.clone(), context).await?;
        Ok(Box::new(datagram::Datagrams::new(
            engine,
            request.budget(),
            context.resolution(),
        )?))
    }
    fn begin_shutdown(&self) {
        let _admission = self.admission.lock().unwrap();
        self.cancel.cancel();
        self.retired.close();
    }
    async fn shutdown(&self) {
        self.begin_shutdown();
        self.retired.wait().await;
        let engine = self.current.lock().await.take();
        if let Some(engine) = engine {
            engine.stop().await;
        }
    }
}
impl Drop for WireGuardOutbound {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
