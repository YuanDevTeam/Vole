//! Private node DNS owns no strong link back to its outbound or IP engine.
use super::{ConnectionFactory, datagram::Datagrams, ip::Engine};
use crate::{
    config::{DnsConfig, DnsNameserver},
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError, Dispatcher},
    dns::{resolution::ResolutionContext, runtime::RuntimeDns},
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, EstablishContext, owned_stream::OwnedStream},
    security::SecurityContext,
    session::{DatagramSession, Destination, StreamSession},
    transport::h3_connect,
};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock, Weak},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

fn configuration(nameservers: &[DnsNameserver], ipv6: bool) -> DnsConfig {
    let mut config = DnsConfig {
        enable: true,
        ipv6,
        nameservers: nameservers.to_vec(),
        use_hosts: false,
        use_system_hosts: false,
        ..Default::default()
    };
    config.hosts.clear();
    config.default_nameservers.clear();
    config
}

async fn resolve_published_dns(
    dns: &RuntimeDns,
    cancel: &CancellationToken,
    resolution: &ResolutionContext,
    target: &Destination,
    deadline: Instant,
    ipv4: bool,
    ipv6: bool,
) -> Result<SocketAddr, DispatchError> {
    // Stop can precede publication in OnceLock while its constructor runs.
    // A published resolver must observe cancellation before opening a driver.
    if cancel.is_cancelled() {
        dns.begin_shutdown();
        return Err(DispatchError::ConnectionRefused);
    }
    let result = resolution
        .resolve_node_local(target, deadline, dns, ipv4, ipv6)
        .await;
    // A cache hit can complete without yielding to the outer cancellation arm.
    if cancel.is_cancelled() {
        dns.begin_shutdown();
        return Err(DispatchError::ConnectionRefused);
    }
    result
}

pub(super) async fn resolve_ip(
    engine: &Arc<Engine>,
    target: &Destination,
    resolution: &ResolutionContext,
    deadline: Instant,
) -> Result<SocketAddr, DispatchError> {
    let ipv4 = engine
        .client
        .prefixes()
        .any(|prefix| prefix.address.is_ipv4());
    let ipv6 = engine.client.has_ipv6();
    tokio::select! {
        biased;
        () = engine.cancel.cancelled() => Err(DispatchError::ConnectionRefused),
        result = async {
            if engine.config.dns.is_empty() || matches!(target, Destination::Ip(_)) {
                return resolution.resolve_local_family(target, deadline, ipv4, ipv6).await;
            }
            let dns = engine.remote.get_or_init(|| {
                RuntimeDns::new_for_masque_node(
                    &configuration(&engine.config.dns, ipv6 && resolution.ipv6_allowed()),
                    Arc::new(IpDns { engine: Arc::downgrade(engine) }),
                    engine.resolution.clone(),
                    engine.security.clone(),
                )
            });
            resolve_published_dns(dns, &engine.cancel, resolution, target, deadline, ipv4, ipv6).await
        } => result,
    }
}

struct IpDns {
    engine: Weak<Engine>,
}

#[async_trait]
impl Dispatcher for IpDns {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        let engine = self
            .engine
            .upgrade()
            .ok_or(DispatchError::ConnectionRefused)?;
        let Destination::Ip(remote) = session.destination else {
            return Err(DispatchError::HostUnreachable);
        };
        let context =
            EstablishContext::with_resolution(DEFAULT_ESTABLISH_TIMEOUT, engine.resolution.clone())
                .with_metadata(&session.metadata);
        let stream = tokio::select! {
            biased;
            () = engine.cancel.cancelled() => return Err(DispatchError::ConnectionRefused),
            result = context.run_io("MASQUE DNS TCP", engine.tcp.connect(remote, context.deadline())) => result?,
        };
        Ok(Box::new(OwnedStream::new(
            Box::new(stream),
            engine.cancel.child_token(),
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
        if !engine.config.udp {
            return Err(DispatchError::NotAllowed);
        }
        let resolution = engine.resolution.clone();
        Ok(Box::new(Datagrams::new(
            engine,
            DatagramBudget::new(u16::MAX, session.max_response_payload_size()),
            resolution,
        )?))
    }
}

pub(super) struct L4DnsContext<'a> {
    pub remote: &'a OnceLock<Arc<RuntimeDns>>,
    pub nameservers: &'a [DnsNameserver],
    pub factory: &'a Arc<ConnectionFactory>,
    pub pool: &'a Arc<h3_connect::Pool>,
    pub cancel: &'a CancellationToken,
    pub security: &'a SecurityContext,
    pub bootstrap: &'a ResolutionContext,
}

pub(super) async fn resolve_l4(
    context: L4DnsContext<'_>,
    target: &Destination,
    deadline: Instant,
) -> Result<SocketAddr, DispatchError> {
    tokio::select! {
        biased;
        () = context.cancel.cancelled() => Err(DispatchError::ConnectionRefused),
        result = async {
            if context.nameservers.is_empty() || matches!(target, Destination::Ip(_)) {
                return context.bootstrap.resolve_local_family(target, deadline, true, true).await;
            }
            let dns = context.remote.get_or_init(|| {
                RuntimeDns::new_for_masque_node(
                    &configuration(context.nameservers, context.bootstrap.ipv6_allowed()),
                    Arc::new(L4Dns {
                        factory: Arc::downgrade(context.factory),
                        pool: Arc::downgrade(context.pool),
                        cancel: context.cancel.clone(),
                        bootstrap: context.bootstrap.clone(),
                    }),
                    context.bootstrap.clone(),
                    context.security.clone(),
                )
            });
            resolve_published_dns(dns, context.cancel, context.bootstrap, target, deadline, true, true).await
        } => result,
    }
}

struct L4Dns {
    factory: Weak<ConnectionFactory>,
    pool: Weak<h3_connect::Pool>,
    cancel: CancellationToken,
    bootstrap: ResolutionContext,
}

#[async_trait]
impl Dispatcher for L4Dns {
    async fn connect_tcp(&self, session: StreamSession) -> Result<BoxStream, DispatchError> {
        if !matches!(session.destination, Destination::Ip(_)) {
            return Err(DispatchError::HostUnreachable);
        }
        let factory = self
            .factory
            .upgrade()
            .ok_or(DispatchError::ConnectionRefused)?;
        let pool = self
            .pool
            .upgrade()
            .ok_or(DispatchError::ConnectionRefused)?;
        let context =
            EstablishContext::with_resolution(DEFAULT_ESTABLISH_TIMEOUT, self.bootstrap.clone())
                .with_metadata(&session.metadata);
        let stream = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(DispatchError::ConnectionRefused),
            result = super::connect_l4_literal(factory, pool, session, &context) => result?,
        };
        Ok(Box::new(OwnedStream::new(
            stream,
            self.cancel.child_token(),
        )))
    }

    async fn open_datagram(
        &self,
        _session: DatagramSession,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{DnsRoute, DnsTransport},
        session::Datagram,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct MemoryDns {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl Dispatcher for MemoryDns {
        async fn connect_tcp(&self, _: StreamSession) -> Result<BoxStream, DispatchError> {
            Err(DispatchError::NotAllowed)
        }

        async fn open_datagram(
            &self,
            _: DatagramSession,
        ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(MemoryReply(None)))
        }
    }

    struct MemoryReply(Option<Datagram>);

    #[async_trait]
    impl DatagramTransport for MemoryReply {
        async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
            // RuntimeDns generates this bounded, uncompressed A question.
            let end = 12
                + datagram.payload[12..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap()
                + 5;
            let mut response = datagram.payload[..end].to_vec();
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
            response[10..12].fill(0);
            response
                .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 1]);
            self.0 = Some(Datagram {
                payload: response.into(),
                ..datagram
            });
            Ok(())
        }

        async fn receive(&mut self) -> Result<Datagram, DispatchError> {
            self.0.take().ok_or(DispatchError::HostUnreachable)
        }
    }

    fn private_dns(dispatcher: Arc<MemoryDns>) -> Arc<RuntimeDns> {
        let nameserver = DnsNameserver {
            transport: DnsTransport::Udp,
            address: "192.0.2.53".parse::<std::net::IpAddr>().unwrap().into(),
            port: 53,
            route: DnsRoute::Direct,
            path: None,
            http_auth: None,
            options: Default::default(),
        };
        RuntimeDns::new_for_masque_node(
            &configuration(&[nameserver], false),
            dispatcher,
            ResolutionContext::default(),
            SecurityContext::new(),
        )
    }

    fn target() -> Destination {
        Destination::Domain {
            host: "cached.example".into(),
            port: 443,
        }
    }

    #[tokio::test]
    async fn masque_private_dns_rejects_late_publication_after_stop() {
        let dispatcher = Arc::new(MemoryDns::default());
        let remote = OnceLock::new();
        let cancel = CancellationToken::new();
        let dns = remote.get_or_init(|| {
            // Stop saw an empty OnceLock while this constructor was running.
            cancel.cancel();
            private_dns(dispatcher.clone())
        });
        let result = resolve_published_dns(
            dns,
            &cancel,
            &ResolutionContext::default(),
            &target(),
            Instant::now() + std::time::Duration::from_secs(1),
            true,
            false,
        )
        .await;
        assert!(matches!(result, Err(DispatchError::ConnectionRefused)));
        assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 0);
        dns.shutdown().await;
    }

    #[tokio::test]
    async fn masque_private_dns_rejects_cached_lookup_after_stop() {
        let dispatcher = Arc::new(MemoryDns::default());
        let remote = OnceLock::new();
        let cancel = CancellationToken::new();
        let dns = remote.get_or_init(|| private_dns(dispatcher.clone()));
        let resolution = ResolutionContext::default();
        for _ in 0..2 {
            let address = resolve_published_dns(
                dns,
                &cancel,
                &resolution,
                &target(),
                Instant::now() + std::time::Duration::from_secs(1),
                true,
                false,
            )
            .await
            .unwrap();
            assert_eq!(address, "203.0.113.1:443".parse().unwrap());
        }
        assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 1);
        cancel.cancel();
        let result = resolve_published_dns(
            dns,
            &cancel,
            &resolution,
            &target(),
            Instant::now() + std::time::Duration::from_secs(1),
            true,
            false,
        )
        .await;
        assert!(matches!(result, Err(DispatchError::ConnectionRefused)));
        assert_eq!(dispatcher.calls.load(Ordering::Relaxed), 1);
        dns.shutdown().await;
    }
}
