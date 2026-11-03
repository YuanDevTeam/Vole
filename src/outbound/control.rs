//! A routing-only node has no stream or datagram transport to return.
use async_trait::async_trait;

use super::{ConnectedStream, DatagramRequest, EstablishContext, OutboundConnector};
use crate::{
    dispatch::{DatagramTransport, DispatchError},
    session::StreamSession,
};

pub(crate) struct RuleControlConnector;
#[async_trait]
impl OutboundConnector for RuleControlConnector {
    async fn connect_stream(
        &self,
        _session: StreamSession,
        _context: &EstablishContext,
    ) -> Result<ConnectedStream, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
    async fn open_datagram(
        &self,
        _request: DatagramRequest,
        _context: &EstablishContext,
    ) -> Result<Box<dyn DatagramTransport>, DispatchError> {
        Err(DispatchError::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{DatagramSession, Destination, InboundKind};

    #[tokio::test]
    async fn routing_only_controls_never_return_successful_io() {
        let context = EstablishContext::default();
        let session = StreamSession {
            metadata: Default::default(),
            inbound: InboundKind::Tun,
            source: "192.0.2.2:10000".parse().unwrap(),
            destination: Destination::Ip("198.51.100.1:443".parse().unwrap()),
            sniffed_domain: None,
        };
        assert!(matches!(
            RuleControlConnector.connect_stream(session, &context).await,
            Err(DispatchError::NotAllowed)
        ));
        assert!(matches!(
            RuleControlConnector
                .open_datagram(
                    DatagramRequest::new(DatagramSession::new(
                        InboundKind::Tun,
                        "192.0.2.2:10000".parse().unwrap()
                    )),
                    &context,
                )
                .await,
            Err(DispatchError::NotAllowed)
        ));
    }
}
