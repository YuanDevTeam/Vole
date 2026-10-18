//! Stream plugins are below SS2022; UDP stays native unless UoT is configured.
use crate::{
    config::{SecurityConfig, ShadowsocksPlugin, StreamTransport},
    dispatch::{BoxStream, DispatchError},
    outbound::{EstablishContext, OwnedStream, UpstreamPath},
    security::{SecurityClient, SecurityContext},
    session::{Destination, StreamSession},
    transport::{self, ss_framed},
};
use std::{io, sync::Mutex};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
enum Kind {
    Security(SecurityClient),
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
    Kcptun(transport::kcptun::Owner),
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
                Kind::Security(SecurityClient::from_security_with_context(
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
            ShadowsocksPlugin::Kcptun(config) => {
                Kind::Kcptun(transport::kcptun::Owner::new(config.clone())?)
            }
        };
        Ok(Self {
            kind,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
            closed: Mutex::new(false),
        })
    }
    pub(super) async fn open(
        &self,
        upstream: &UpstreamPath,
        server: &Destination,
        session: StreamSession,
        context: &EstablishContext,
    ) -> Result<BoxStream, DispatchError> {
        if let Kind::Kcptun(owner) = &self.kind {
            return owner.open(upstream, server, &session, context).await;
        }
        tokio::select! {biased;
            ()=self.cancel.cancelled()=>Err(DispatchError::NotAllowed),
            result=async {
                let raw=upstream.connect_server(session,server,context).await?.io;
                match &self.kind {
                    Kind::Security(security)=>context.run_io("Shadowsocks plugin identity",security.connect_with_context(raw,context)).await,
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
                    Kind::Kcptun(_)=>unreachable!(),
                }
            }=>result,
        }
    }
    pub(super) fn begin_shutdown(&self) {
        self.cancel.cancel();
        let mut closed = self.closed.lock().unwrap();
        *closed = true;
        self.tasks.close();
        if let Kind::Kcptun(owner) = &self.kind {
            owner.begin_shutdown();
        }
    }
    pub(super) async fn shutdown(&self) {
        self.begin_shutdown();
        if let Kind::Kcptun(owner) = &self.kind {
            owner.shutdown().await;
        }
        self.tasks.wait().await;
    }
}
