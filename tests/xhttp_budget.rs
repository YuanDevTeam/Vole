#![cfg(feature = "outbound-vless")]
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use vole::{
    config::{Config, ProxyProtocol},
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{
        ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector, VlessOutbound,
    },
    session::{Datagram, Destination, InboundKind, StreamSession},
};

struct Upstream {
    budget: u16,
    sends: Arc<AtomicUsize>,
    opens: AtomicUsize,
}
struct Transport {
    budget: u16,
    sends: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl DatagramTransport for Transport {
    async fn send(&mut self, _: Datagram) -> Result<(), DispatchError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::from(io::ErrorKind::NotConnected).into())
    }
    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        std::future::pending().await
    }
    async fn close(&mut self) -> Result<(), DispatchError> {
        Ok(())
    }
    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        DatagramBudget::new(self.budget, self.budget)
    }
}
#[async_trait::async_trait]
impl OutboundConnector for Upstream {
    async fn connect_stream(
        &self,
        _: StreamSession,
        _: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        panic!("H3 fell back to TCP")
    }
    async fn open_datagram(
        &self,
        request: DatagramRequest,
        _: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        assert_eq!(request.budget(), DatagramBudget::new(1400, 1400));
        self.opens.fetch_add(1, Ordering::SeqCst);
        if self.budget == 0 {
            return Err(DispatchError::NotAllowed);
        }
        Ok(Box::new(Transport {
            budget: self.budget,
            sends: self.sends.clone(),
        }))
    }
}
#[tokio::test]
async fn h3_rejects_incapable_or_small_budget_upstreams_before_any_datagram() {
    #[cfg(feature = "interop-test")]
    let _case = vole::resources::case_events::Case::new(
        "XHTTP-UNIT",
        "h3_rejects_incapable_or_small_budget_upstreams_before_any_datagram",
    );
    let config=Config::parse_yaml(b"mixed-port: 1080\nproxies: [{name: edge, type: vless, server: 192.0.2.1, port: 443, uuid: 07070707-0707-0707-0707-070707070707, tls: true, network: xhttp, alpn: [h3]}]\nrules: ['MATCH,edge']").unwrap();
    let ProxyProtocol::Vless(config) = &config.proxies[0].protocol else {
        unreachable!()
    };
    for budget in [0, 1199] {
        let upstream = Arc::new(Upstream {
            budget,
            sends: Arc::default(),
            opens: AtomicUsize::new(0),
        });
        let outbound = VlessOutbound::new_with_upstream(config, upstream.clone()).unwrap();
        let result = outbound
            .connect_stream(
                StreamSession {
                    metadata: Default::default(),
                    inbound: InboundKind::InternalMeasure,
                    source: "127.0.0.1:1".parse().unwrap(),
                    destination: "192.0.2.2:80"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into(),
                    sniffed_domain: None,
                },
                &EstablishContext::default(),
            )
            .await;
        assert!(result.is_err());
        assert_eq!(upstream.opens.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.sends.load(Ordering::SeqCst), 0);
        outbound.shutdown().await;
    }
}
