//! Bounded physical paths for one authenticated QUIC connection.
use super::{bandwidth::Bandwidth, salamander, socket::WindowSocket};
use crate::{
    config::Hysteria2OutboundConfig,
    dispatch::{DatagramBudget, DispatchError},
    outbound::{DatagramRequest, EstablishContext, UpstreamPath},
    session::{DatagramSession, Destination},
    transport::quic::{self, DatagramDriver, DatagramSocket},
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::Instant;

const QUIC_PAYLOAD: u16 = crate::limits::HY2_QUIC_PAYLOAD as u16;
const RETIRE_AFTER: Duration = Duration::from_secs(crate::limits::HY2_PATH_RETIRE_SECONDS as u64);

pub(super) struct Paths {
    config: Arc<Hysteria2OutboundConfig>,
    upstream: UpstreamPath,
    datagram: DatagramSession,
    context: EstablishContext,
    bandwidth: Arc<Bandwidth>,
    pub peer: SocketAddr,
    pub mtu: u16,
    current: Option<DatagramDriver>,
    retiring: Option<DatagramDriver>,
    current_socket: Option<Arc<DatagramSocket>>,
}
impl Paths {
    pub async fn open(
        config: Arc<Hysteria2OutboundConfig>,
        upstream: UpstreamPath,
        server: &Destination,
        datagram: DatagramSession,
        context: EstablishContext,
        bandwidth: Arc<Bandwidth>,
    ) -> Result<(Self, Arc<WindowSocket>), DispatchError> {
        let destination = upstream.datagram_server(server, &context).await?;
        let peer = context.resolve_ip(&destination).await?;
        let mut paths = Self {
            config,
            upstream,
            datagram,
            context,
            bandwidth,
            peer,
            mtu: 0,
            current: None,
            retiring: None,
            current_socket: None,
        };
        let (socket, driver) = paths.attach(&paths.context).await?;
        paths.current = Some(driver);
        paths.mtu = socket.budget().quic_payload_limit()?;
        paths.current_socket = Some(socket.clone());
        Ok((paths, WindowSocket::new(socket, None)))
    }
    fn physical_peer(&self) -> SocketAddr {
        let mut peer = self.peer;
        if let Some(hopping) = &self.config.hopping {
            peer.set_port(hopping.ports[rand::random_range(0..hopping.ports.len())]);
        }
        peer
    }
    fn interval(&self) -> Duration {
        let hopping = self.config.hopping.as_ref().unwrap();
        Duration::from_secs(u64::from(rand::random_range(
            hopping.min_seconds..=hopping.max_seconds,
        )))
    }
    async fn attach(
        &self,
        context: &EstablishContext,
    ) -> Result<(Arc<DatagramSocket>, DatagramDriver), DispatchError> {
        let wire_mtu = QUIC_PAYLOAD
            + if self.config.obfs_password.is_some() {
                salamander::OVERHEAD
            } else {
                0
            };
        let request = DatagramRequest::new(self.datagram.clone())
            .with_budget(DatagramBudget::new(wire_mtu, wire_mtu));
        let raw = self.upstream.open_datagram(request, context).await?;
        // Pace the encrypted wire packet, including the optional salt.
        let raw = self.bandwidth.wrap(raw, wire_mtu);
        let raw = if let Some(password) = &self.config.obfs_password {
            salamander::wrap(raw, password)
        } else {
            raw
        };
        Ok(quic::attach_mapped(
            raw,
            self.peer,
            self.physical_peer(),
            DatagramBudget::new(QUIC_PAYLOAD, QUIC_PAYLOAD),
        )?)
    }
    pub async fn hopping(&mut self, endpoint: &quinn::Endpoint) -> Result<(), DispatchError> {
        if self.config.hopping.is_none() {
            return std::future::pending().await;
        }
        // The first socket has now authenticated: all lazy upstream choices
        // are known. Never sample the live group again for this connection.
        self.context = self.context.authenticated_continuation();
        let mut next = Instant::now() + self.interval();
        loop {
            tokio::time::sleep_until(next).await;
            let context = self.context.authenticated_continuation();
            let (socket, driver) = context
                .run("Hysteria2 hop path", self.attach(&context))
                .await?;
            self.retiring = Some(driver);
            if socket.budget().quic_payload_limit()? < self.mtu {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Hysteria2 hop path budget decreased",
                )
                .into());
            }
            let old = self.current_socket.replace(socket.clone()).unwrap();
            let window = WindowSocket::new(socket, Some(old));
            endpoint.rebind_abstract(window.clone())?;
            std::mem::swap(&mut self.current, &mut self.retiring);
            // Measure the next interval from the switch, not from the end of
            // retirement, so the grace period never stretches configured hops.
            next = Instant::now() + self.interval();
            tokio::time::sleep(RETIRE_AFTER).await;
            window.retire_previous();
            // Keep ownership while joining. If node Stop cancels this future,
            // stop() resumes the same join rather than losing an aborted task.
            self.retiring.as_mut().unwrap().join().await?;
            self.retiring.take();
        }
    }
    pub async fn stop(&mut self) {
        let current = async {
            if let Some(driver) = self.current.as_mut() {
                let _ = driver.join().await;
            }
        };
        let retiring = async {
            if let Some(driver) = self.retiring.as_mut() {
                let _ = driver.join().await;
            }
        };
        tokio::join!(current, retiring);
        self.current.take();
        self.retiring.take();
    }
}
