use super::{datagram_codec, packet_window::PacketWindowFilter};
use crate::{
    dispatch::{DatagramTransport, DispatchError},
    session::{Datagram, Destination},
};
use async_trait::async_trait;
use bytes::Bytes;
use shadowsocks::{
    ServerConfig, context::SharedContext, crypto::v2::udp::UdpCipher,
    relay::udprelay::options::UdpSocketControlData,
};
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::time::Instant;

pub(super) const MAX_WIRE_PACKET: usize = 65_507;

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
    cipher: Option<UdpCipher>,
}

pub(super) struct SsDatagram {
    inner: Box<dyn DatagramTransport>,
    server: Destination,
    context: SharedContext,
    config: Arc<ServerConfig>,
    tx_cipher: Option<UdpCipher>,
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
        let mut control = UdpSocketControlData::default();
        control.client_session_id = rand::random();
        Self {
            inner,
            server,
            tx_cipher: Some(UdpCipher::new(
                config.method(),
                config.key(),
                control.client_session_id,
            )),
            context,
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

    fn accept_control(
        &mut self,
        control: &UdpSocketControlData,
        cipher: Option<UdpCipher>,
    ) -> bool {
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
                cipher,
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
            self.tx_cipher = Some(UdpCipher::new(
                self.config.method(),
                self.config.key(),
                self.control.client_session_id,
            ));
        }
        self.control.packet_id += 1;
        let target = super::address(&datagram.remote);
        let payload = datagram_codec::encode_request(
            &self.context,
            &self.config,
            self.tx_cipher.as_ref().expect("open SS association"),
            &target,
            &self.control,
            &datagram.payload,
        )
        .map_err(|_| DispatchError::Other("Shadowsocks UDP encoding failed".into()))?
        .freeze();
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
            let length = wire.payload.len();
            self.buffer[..length].copy_from_slice(&wire.payload);
            drop(wire);
            let Ok(server_id) =
                datagram_codec::prepare_response(&self.config, &mut self.buffer[..length])
            else {
                continue;
            };
            let mut candidate = None;
            let cipher = if let Some(id) = server_id {
                if let Some(session) = self.sessions.iter().find(|session| session.id == id) {
                    session.cipher.as_ref().expect("AES session cipher")
                } else {
                    if self.sessions.len() == 2
                        && Instant::now().duration_since(self.sessions[0].last) < SESSION_RETENTION
                    {
                        continue;
                    }
                    // A tentative unauthenticated ID never enters retained state.
                    candidate = Some(UdpCipher::new(self.config.method(), self.config.key(), id));
                    candidate.as_ref().unwrap()
                }
            } else {
                // ChaCha's cipher depends only on PSK; the nonce is per packet.
                self.tx_cipher.as_ref().expect("open SS association")
            };
            let Ok((size, source, control)) =
                datagram_codec::decode_response(&self.config, cipher, &mut self.buffer[..length])
            else {
                continue;
            };
            if size > self.maximum {
                continue;
            }
            let Ok(remote) = super::destination(source) else {
                continue;
            };
            if !self.accept_control(&control, candidate) {
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
        self.tx_cipher.take();
        self.inner.close().await
    }
}

#[cfg(test)]
#[path = "datagram_tests.rs"]
mod tests;
