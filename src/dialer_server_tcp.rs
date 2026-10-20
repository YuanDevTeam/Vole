//! Explicit node-owned physical TCP I/O. A pending TFO stream is not an eager
//! connection or address-race winner; its effective address is known at prepare.
use std::{io, net::SocketAddr};

use tokio::time::Instant;

use super::{Dialer, ResolvedEndpoint};
use crate::dispatch::BoxStream;

pub(crate) struct ServerTcpConnection {
    pub io: BoxStream,
    pub address: SocketAddr,
}

impl Dialer {
    /// Explicitly configured node endpoints only. Built-in DIRECT and ordinary
    /// callers retain connect()/connect_address()'s established TCP contract.
    pub(crate) async fn connect_server_tcp(
        &self,
        endpoint: &ResolvedEndpoint,
        deadline: Instant,
    ) -> io::Result<ServerTcpConnection> {
        #[cfg(target_os = "linux")]
        if let Some(address) = self.single_tfo_address(endpoint)? {
            let (stream, address) = self.prepare_tcp_fast_open(address, deadline).await?;
            return Ok(ServerTcpConnection {
                io: Box::new(stream),
                address,
            });
        }
        // Multiple permitted addresses retain the existing eager serial/race
        // selection. Other OSes retain their normal controlled TCP adapter.
        let stream = tokio::time::timeout_at(deadline, self.connect(endpoint))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        let address = stream.peer_addr()?;
        Ok(ServerTcpConnection {
            io: Box::new(stream),
            address,
        })
    }

    #[cfg(target_os = "linux")]
    fn single_tfo_address(&self, endpoint: &ResolvedEndpoint) -> io::Result<Option<SocketAddr>> {
        if !self.tfo {
            return Ok(None);
        }
        self.validate_connected_endpoint(endpoint)?;
        let addresses = self.ordered_connected_addresses(&endpoint.addresses);
        Ok(match addresses.as_slice() {
            [address] => Some(*address),
            _ => None,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn node_tfo_requires_exact_policy_and_one_permitted_physical_address() {
        let first = "192.0.2.1:443".parse().unwrap();
        let second = "[2001:db8::2]:443".parse().unwrap();
        let endpoint = |addresses| ResolvedEndpoint {
            logical_host: "node.invalid".into(),
            port: 443,
            addresses,
        };
        let selected = endpoint(vec![first]);
        let default = Dialer::default();
        assert_eq!(default.single_tfo_address(&selected).unwrap(), None);
        let enabled = default.with_tfo(true);
        assert_eq!(enabled.single_tfo_address(&selected).unwrap(), Some(first));
        assert_eq!(
            enabled
                .single_tfo_address(&endpoint(vec![first, second]))
                .unwrap(),
            None,
        );
        assert_eq!(
            enabled
                .clone()
                .with_ip_version(crate::config::IpVersion::Ipv4)
                .single_tfo_address(&endpoint(vec![first, second]))
                .unwrap(),
            Some(first),
        );
        assert_eq!(
            enabled
                .with_tfo(false)
                .single_tfo_address(&selected)
                .unwrap(),
            None,
        );
    }
}
