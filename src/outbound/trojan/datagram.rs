use std::io;

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    dispatch::{BoxStream, DatagramBudget, DatagramTransport, DispatchError},
    session::{Datagram, Destination},
    socks5::{Socks5CodecError, decode_address, encode_address},
};

// Mihomo's Trojan decoder accepts at most 8192 bytes per datagram. Do not
// emulate its sender's splitting: splitting would change UDP message boundaries.
pub const MAX_DATAGRAM_PAYLOAD: u16 = 8192;
const MAX_FRAME_BYTES: usize = 259 + 4 + MAX_DATAGRAM_PAYLOAD as usize;

/// One UDP association over an already authenticated Trojan stream. Partial
/// receive state survives cancellation; a cancelled write poisons the stream.
/// No reader task or lock can prevent the caller from sending while read-idle.
pub struct TrojanDatagram {
    stream: Option<BoxStream>,
    wire: BytesMut,
    budget: DatagramBudget,
    send_incomplete: bool,
}

impl std::fmt::Debug for TrojanDatagram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanDatagram")
            .field("closed", &self.stream.is_none())
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl TrojanDatagram {
    pub fn new(stream: BoxStream, budget: DatagramBudget) -> Self {
        Self {
            stream: Some(stream),
            wire: BytesMut::new(),
            budget: budget.intersect(DatagramBudget::new(
                MAX_DATAGRAM_PAYLOAD,
                MAX_DATAGRAM_PAYLOAD,
            )),
            send_incomplete: false,
        }
    }

    fn check_open(&mut self) -> io::Result<()> {
        if self.send_incomplete {
            self.stream.take();
        }
        if self.stream.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Trojan association is closed",
            ));
        }
        Ok(())
    }

    fn packet(&mut self) -> io::Result<Option<Datagram>> {
        let (remote, address_size) = match decode_address(&self.wire) {
            Ok(address) => address,
            Err(Socks5CodecError::Truncated) => return Ok(None),
            Err(_) => return Err(invalid_frame()),
        };
        let Some(header) = self.wire.get(address_size..address_size + 4) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if length > usize::from(MAX_DATAGRAM_PAYLOAD) || &header[2..] != b"\r\n" {
            return Err(invalid_frame());
        }
        let header_size = address_size + 4;
        if self.wire.len() < header_size + length {
            return Ok(None);
        }
        self.wire.advance(header_size);
        let payload = self.wire.split_to(length).freeze();
        Ok(Some(Datagram {
            remote,
            payload,
            sniffed_domain: None,
        }))
    }
}

fn invalid_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Trojan datagram frame")
}

#[async_trait]
impl DatagramTransport for TrojanDatagram {
    fn supports_shared_destinations(&self) -> bool {
        true
    }

    fn payload_budget(&self, _: &Destination) -> DatagramBudget {
        self.budget
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.check_open()?;
        if datagram.payload.len() > usize::from(self.budget.transmit())
            || datagram.remote.port() == 0
        {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Trojan datagram").into(),
            );
        }
        let mut packet = Vec::with_capacity(263 + datagram.payload.len());
        encode_address(&datagram.remote, &mut packet)?;
        packet.extend_from_slice(&(datagram.payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(&datagram.payload);
        self.send_incomplete = true;
        let stream = self.stream.as_mut().expect("checked open");
        stream.write_all(&packet).await?;
        stream.flush().await?;
        self.send_incomplete = false;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.check_open()?;
        let mut discarded = 0;
        loop {
            match self.packet() {
                Ok(Some(packet)) if packet.payload.len() <= usize::from(self.budget.receive()) => {
                    return Ok(packet);
                }
                Ok(Some(_)) => {
                    discarded += 1;
                    if discarded == crate::limits::IO_POLL_BUDGET {
                        tokio::task::yield_now().await;
                        discarded = 0;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(error) => {
                    self.stream.take();
                    return Err(error.into());
                }
            }
            let mut buffer = [0; 2048];
            let remaining = (MAX_FRAME_BYTES - self.wire.len()).min(buffer.len());
            if remaining == 0 {
                self.stream.take();
                return Err(invalid_frame().into());
            }
            match self
                .stream
                .as_mut()
                .expect("checked open")
                .read(&mut buffer[..remaining])
                .await
            {
                Ok(0) => {
                    self.stream.take();
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Trojan datagram stream ended",
                    )
                    .into());
                }
                Ok(length) => self.wire.extend_from_slice(&buffer[..length]),
                Err(error) => {
                    self.stream.take();
                    return Err(error.into());
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        // Dropping the complete owned stream closes both directions even if a
        // protocol shutdown would wait for an unresponsive peer.
        self.stream.take();
        self.wire.clear();
        Ok(())
    }
}
