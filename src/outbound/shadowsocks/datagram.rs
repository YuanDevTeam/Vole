use super::{
    packet_io::{MAX_WIRE_PACKET, PacketIo},
    packet_window::PacketWindowFilter,
};
use crate::{
    dispatch::{DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use shadowsocks::{
    ServerConfig,
    context::SharedContext,
    relay::udprelay::{
        ProxySocket, crypto_io::encrypt_client_payload, options::UdpSocketControlData,
        proxy_socket::UdpSocketType,
    },
};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::time::Instant;

// Largest response: XChaCha nonce, IDs/type/time/length, optional padding,
// maximum SOCKS address and AEAD tag. The payload is separately bounded.
pub(super) const MAX_RESPONSE_HEADER: u16 = 24 + 16 + 1 + 8 + 8 + 2 + 900 + 259 + 16;
// The official library pads empty UDP only. For nonempty payloads, directional
// headers differ by the response's client-session ID; AES EIH is request-only.
pub(super) fn request_header(config: &ServerConfig) -> usize {
    nonce_size(config) + 43 + config.identity_keys().len().saturating_mul(16)
}

fn nonce_size(config: &ServerConfig) -> usize {
    if config.method() == shadowsocks::crypto::CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 {
        24
    } else {
        0
    }
}
const SESSION_RETENTION: Duration = Duration::from_secs(60);
const SEND_BURST: usize = 1;

struct ServerSession {
    id: u64,
    last: Instant,
    window: PacketWindowFilter,
}

pub(super) struct SsDatagram {
    inner: Box<dyn DatagramTransport>,
    server: Destination,
    socket: ProxySocket<PacketIo>,
    context: SharedContext,
    config: Arc<ServerConfig>,
    chacha_decoder: Option<super::chacha_datagram::Decoder>,
    io: PacketIo,
    control: UdpSocketControlData,
    sessions: VecDeque<ServerSession>,
    maximum: usize,
    wire_maximum: usize,
    buffer: Vec<u8>,
    closed: bool,
    request_header: usize,
    response_header: usize,
    sent_in_burst: usize,
}

impl SsDatagram {
    pub(super) fn new(
        inner: Box<dyn DatagramTransport>,
        server: Destination,
        context: SharedContext,
        config: Arc<ServerConfig>,
        maximum: u16,
        wire_maximum: u16,
    ) -> Self {
        let io = PacketIo::default();
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random();
        Self {
            inner,
            server,
            socket: ProxySocket::from_socket(
                UdpSocketType::Client,
                context.clone(),
                &config,
                io.clone(),
            ),
            context,
            chacha_decoder: super::chacha_datagram::Decoder::new(&config),
            io,
            control,
            sessions: VecDeque::with_capacity(2),
            maximum: usize::from(maximum),
            wire_maximum: usize::from(wire_maximum).min(MAX_WIRE_PACKET),
            buffer: vec![0; usize::from(wire_maximum).min(MAX_WIRE_PACKET)],
            closed: false,
            request_header: request_header(&config),
            response_header: nonce_size(&config) + 51,
            config,
            sent_in_burst: 0,
        }
    }

    fn accept_control(&mut self, control: &UdpSocketControlData) -> bool {
        if control.client_session_id != self.control.client_session_id
            || control.packet_id == u64::MAX
        {
            return false;
        }
        let now = Instant::now();
        let index = if let Some(index) = self
            .sessions
            .iter()
            .position(|session| session.id == control.server_session_id)
        {
            index
        } else {
            // SIP022 permits an old and a current server session. Never evict
            // the old replay window within one minute of its last valid packet.
            if self.sessions.len() == 2 {
                if now.duration_since(self.sessions[0].last) < SESSION_RETENTION {
                    return false;
                }
                self.sessions.pop_front();
            }
            self.sessions.push_back(ServerSession {
                id: control.server_session_id,
                last: now,
                window: PacketWindowFilter::new(),
            });
            self.sessions.len() - 1
        };
        let session = &mut self.sessions[index];
        if !session
            .window
            .validate_packet_id(control.packet_id, u64::MAX)
        {
            return false;
        }
        session.last = now;
        true
    }

    fn peer_matches(&self, peer: &Destination) -> bool {
        self.server == *peer
            || matches!((&self.server, peer),
            (Destination::Domain { port, .. }, Destination::Ip(addr)) if *port == addr.port())
    }
}

#[async_trait]
impl DatagramTransport for SsDatagram {
    fn supports_shared_destinations(&self) -> bool {
        // SIP022 authenticates an address in every packet. The source owner
        // keeps one replay window; the router demultiplexes live IP targets.
        true
    }

    fn payload_budget(&self, peer: &Destination) -> crate::dispatch::DatagramBudget {
        let address = super::address(peer).serialized_len();
        let response_address = if matches!(peer, Destination::Domain { .. }) {
            259
        } else {
            address
        };
        self.inner
            .payload_budget(&self.server)
            .intersect(crate::dispatch::DatagramBudget::new(
                MAX_WIRE_PACKET as u16,
                self.wire_maximum as u16,
            ))
            .subtract_overhead(
                self.request_header.saturating_add(address),
                self.response_header + response_address,
            )
            .intersect(crate::dispatch::DatagramBudget::new(
                u16::MAX,
                self.maximum as u16,
            ))
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closed {
            return Err(DispatchError::NotAllowed);
        }
        if datagram.payload.len() > MAX_WIRE_PACKET {
            return Err(DispatchError::Other(
                "Shadowsocks UDP payload exceeds wire limit".into(),
            ));
        }
        if self.sent_in_burst == SEND_BURST {
            self.sent_in_burst = 0;
            // Give sibling IO a turn before encoding another packet. A
            // cancellation here cannot leave an accepted wire packet behind.
            tokio::task::yield_now().await;
        }
        // Reserve the ID before any cancellable write; an abandoned send must
        // never cause the next packet to reuse an ID/session combination.
        if self.control.packet_id == u64::MAX - 1 {
            let previous = self.control.client_session_id;
            loop {
                self.control.client_session_id = rand::random();
                if self.control.client_session_id != previous {
                    break;
                }
            }
            self.control.packet_id = 0;
            self.sessions.clear();
        }
        self.control.packet_id += 1;
        let target = super::address(&datagram.remote);
        let payload = if datagram.payload.is_empty() {
            // The official empty-payload encoder advances over up to 900
            // padding bytes without initializing them. Initialize its entire
            // maximum wire image before clear: capacity and initialized bytes
            // survive, so its reserve cannot replace this backing allocation.
            let initialized_len = self
                .request_header
                .checked_add(target.serialized_len())
                .and_then(|length| length.checked_add(900))
                .filter(|length| *length <= MAX_WIRE_PACKET)
                .ok_or_else(|| {
                    DispatchError::Other("Shadowsocks UDP packet exceeds wire limit".into())
                })?;
            let mut encoded = BytesMut::zeroed(initialized_len);
            rand::fill(&mut encoded[..]);
            encoded.clear();
            encrypt_client_payload(
                &self.context,
                self.config.method(),
                self.config.key(),
                &target,
                &self.control,
                self.config.identity_keys(),
                &[],
                &mut encoded,
            );
            debug_assert!(encoded.len() <= initialized_len);
            encoded.freeze()
        } else {
            self.socket
                .send_with_ctrl(&target, &self.control, &datagram.payload)
                .await
                .map_err(|_| DispatchError::Other("Shadowsocks UDP encoding failed".into()))?;
            self.io.take().map_err(DispatchError::from)?
        };
        self.inner
            .send(Datagram {
                remote: self.server.clone(),
                payload,
                sniffed_domain: None,
            })
            .await?;
        self.sent_in_burst += 1;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closed {
            return Err(DispatchError::NotAllowed);
        }
        loop {
            let wire = self.inner.receive().await?;
            if !self.peer_matches(&wire.remote)
                || wire.payload.len() < self.response_header
                || wire.payload.len() > self.wire_maximum
            {
                continue;
            }
            let decoded = if let Some(decoder) = &self.chacha_decoder {
                let length = wire.payload.len();
                self.buffer[..length].copy_from_slice(&wire.payload);
                decoder.decode(&mut self.buffer[..length]).ok()
            } else {
                self.io.put(wire.payload).map_err(DispatchError::from)?;
                // The handoff is always Ready. Only the shared transport
                // above can pend; no partial packet survives cancellation.
                self.socket
                    .recv_with_ctrl(&mut self.buffer)
                    .await
                    .ok()
                    .and_then(|(size, source, _, control)| {
                        control.map(|control| (size, source, control))
                    })
            };
            let Some((size, source, control)) = decoded else {
                continue;
            };
            if size > self.maximum {
                continue;
            }
            let Ok(remote) = super::destination(source) else {
                continue;
            };
            if !self.accept_control(&control) {
                continue;
            }
            return Ok(Datagram {
                remote,
                payload: Bytes::copy_from_slice(&self.buffer[..size]),
                sniffed_domain: None,
            });
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        self.closed = true;
        self.sessions.clear();
        self.chacha_decoder.take();
        self.inner.close().await
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod tests;
