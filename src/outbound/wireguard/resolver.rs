//! Node DNS has a weak engine link; endpoint bootstrap never enters this resolver.
use super::{datagram::Datagrams, engine::Engine};
use crate::{
    config::DnsConfig,
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError, Dispatcher},
    dns::{resolution::ResolutionContext, runtime::RuntimeDns},
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, EstablishContext, owned_stream::OwnedStream},
    session::{DatagramSession, Destination, StreamSession},
};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
};
use tokio::time::Instant;
pub(super) async fn resolve(
    engine: &Arc<Engine>,
    target: &Destination,
    resolution: &ResolutionContext,
    deadline: Instant,
) -> Result<SocketAddr, DispatchError> {
    tokio::select! {biased;()=engine.cancel.cancelled()=>Err(DispatchError::ConnectionRefused),result=async{
        if engine.config.dns.is_empty(){return resolution.resolve_local_family(target,deadline,engine.ipv4.is_some(),engine.ipv6.is_some()).await;}
        let dns=engine.remote.get_or_init(||{
            let mut config=DnsConfig{enable:true,ipv6:engine.ipv6.is_some()&&resolution.ipv6_allowed(),nameservers:engine.config.dns.clone(),use_hosts:false,use_system_hosts:false,..Default::default()};
            config.hosts.clear();config.default_nameservers.clear();
            RuntimeDns::new_for_node(&config,Arc::new(NodeDns{engine:Arc::downgrade(engine)}),engine.resolution.clone(),engine.security.clone())
        });
        resolution.resolve_node_local(target,deadline,dns,engine.ipv4.is_some(),engine.ipv6.is_some()).await
    }=>result}
}
struct NodeDns {
    engine: Weak<Engine>,
}
#[async_trait]
impl Dispatcher for NodeDns {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let engine = self
            .engine
            .upgrade()
            .ok_or(DispatchError::ConnectionRefused)?;
        let Destination::Ip(remote) = session.destination else {
            return Err(DispatchError::HostUnreachable);
        };
        let context =
            EstablishContext::with_resolution(DEFAULT_ESTABLISH_TIMEOUT, engine.resolution.clone());
        let datagram =
            DatagramSession::new(session.inbound, session.source).with_metadata(session.metadata);
        let channel = engine.peer(remote.ip(), datagram, &context).await?;
        let stream = tokio::select! {biased;()=channel.cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),result=context.run_io("WireGuard DNS TCP",engine.tcp.connect(remote,context.deadline()))=>result?};
        Ok(Box::new(OwnedStream::new(
            Box::new(stream),
            channel.cancel.child_token(),
        )))
    }
    async fn open_datagram(
        &self,
        session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        let engine = self
            .engine
            .upgrade()
            .ok_or(DispatchError::ConnectionRefused)?;
        let resolution = engine.resolution.clone();
        Ok(Box::new(Datagrams::new(
            engine,
            DatagramBudget::new(u16::MAX, session.max_response_payload_size()),
            resolution,
            session,
        )?))
    }
}
