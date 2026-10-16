//! XUDP frames over an authenticated mux stream; protocol response headers belong to the caller.

use std::io;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    dispatch::{BoxStream, DatagramTransport, DispatchError},
    outbound::address::{
        decode_port_first as decode_destination, encode_port_first as encode_destination,
    },
    session::{Datagram, Destination},
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;
pub const MAX_METADATA_LENGTH: usize = 512;

pub struct XudpTransport {
    stream: Option<BoxStream>,
    global_id: [u8; 8],
    max_response_payload_size: u16,
    max_request_payload_size: u16,
    first_write: bool,
    last_remote: Option<Destination>,
    pending_write: Option<PendingWrite>,
    receive_buffer: BytesMut,
    max_receive_buffer_size: usize,
    closed: bool,
}

struct PendingWrite {
    frame: Bytes,
    offset: usize,
    remote: Destination,
}

impl std::fmt::Debug for XudpTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XudpTransport")
            .field("max_response_payload_size", &self.max_response_payload_size)
            .field("first_write", &self.first_write)
            .field("receive_buffered", &self.receive_buffer.len())
            .field("max_receive_buffer_size", &self.max_receive_buffer_size)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl XudpTransport {
    #[must_use]
    pub fn new(stream: BoxStream, global_id: [u8; 8], max_response_payload_size: u16) -> Self {
        Self::with_budget(
            stream,
            global_id,
            crate::dispatch::DatagramBudget::new(u16::MAX, max_response_payload_size),
        )
    }

    pub fn with_budget(
        stream: BoxStream,
        global_id: [u8; 8],
        budget: crate::dispatch::DatagramBudget,
    ) -> Self {
        let max_response_payload_size = budget.receive();
        // One maximum-size XUDP frame; the caller consumes its protocol header. The
        // checked construction keeps the bound explicit if any component is
        // widened in the future.
        let max_receive_buffer_size = 2_usize
            .checked_add(MAX_METADATA_LENGTH)
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(usize::from(max_response_payload_size)))
            .expect("XUDP receive-buffer ceiling fits usize");
        Self {
            stream: Some(stream),
            global_id,
            max_response_payload_size,
            max_request_payload_size: budget.transmit(),
            first_write: true,
            last_remote: None,
            pending_write: None,
            receive_buffer: BytesMut::with_capacity(max_receive_buffer_size),
            max_receive_buffer_size,
            closed: false,
        }
    }

    // A cancelled logical target may have submitted a frame prefix. Retain
    // exactly that frame and finish it before another send or receive, rather
    // than corrupting a shared wire or retaining a per-target payload queue.
    async fn flush_pending(&mut self) -> io::Result<()> {
        if let Some(pending) = &mut self.pending_write {
            let stream = self.stream.as_mut().expect("open XUDP stream");
            while pending.offset < pending.frame.len() {
                let written = stream.write(&pending.frame[pending.offset..]).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                pending.offset += written;
            }
            stream.flush().await?;
            self.first_write = false;
            self.last_remote = Some(self.pending_write.take().expect("pending frame").remote);
        }
        Ok(())
    }

    fn fail(&mut self) {
        self.closed = true;
        self.pending_write = None;
        self.stream.take();
    }

    /// Incrementally fills the persistent receive buffer using only
    /// cancellation-safe `read` calls. Every successful partial read is
    /// committed before the next await, so dropping `receive()` from a
    /// `tokio::select!` cannot lose bytes or parser progress.
    async fn fill_receive_buffer(&mut self, required: usize) -> io::Result<()> {
        if required > self.max_receive_buffer_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XUDP receive frame exceeds the bounded buffer",
            ));
        }

        let mut scratch = [0_u8; 1024];
        while self.receive_buffer.len() < required {
            // Consume available stream bytes within the existing one-frame
            // byte budget. Reading exactly each small header field repeatedly
            // enters TLS/H2 even when several complete packets are ready.
            let remaining = self.max_receive_buffer_size - self.receive_buffer.len();
            let chunk = remaining.min(scratch.len());
            let read = self
                .stream
                .as_mut()
                .expect("open XUDP stream")
                .read(&mut scratch[..chunk])
                .await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP stream ended in the middle of a frame",
                ));
            }
            self.receive_buffer.extend_from_slice(&scratch[..read]);
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> io::Result<Datagram> {
        loop {
            self.fill_receive_buffer(2).await?;
            let metadata_length = usize::from(u16::from_be_bytes([
                self.receive_buffer[0],
                self.receive_buffer[1],
            ]));
            if !(4..=MAX_METADATA_LENGTH).contains(&metadata_length) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid XUDP metadata length",
                ));
            }
            let metadata_end = 2_usize
                .checked_add(metadata_length)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(metadata_end).await?;
            let (status, option) = {
                let metadata = &self.receive_buffer[2..metadata_end];
                if metadata[0..2] != [0, 0] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected XUDP session id",
                    ));
                }
                let status = metadata[2];
                let option = metadata[3];
                if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown XUDP frame option",
                    ));
                }
                if option & OPTION_ERROR != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "XUDP peer closed the association with an error",
                    ));
                }
                match status {
                    STATUS_END => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "XUDP peer closed the association normally",
                        ));
                    }
                    STATUS_KEEP | STATUS_KEEP_ALIVE => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unexpected XUDP frame status",
                        ));
                    }
                }
                (status, option)
            };
            if option & OPTION_DATA == 0 {
                self.receive_buffer.advance(metadata_end);
                continue;
            }

            // Xray consumes and discards data attached to a keepalive frame.
            // It is transport padding/liveness data, not an application UDP
            // datagram, and therefore has no meaningful remote destination.
            let remote = (status != STATUS_KEEP_ALIVE)
                .then(|| {
                    let metadata = &self.receive_buffer[2..metadata_end];
                    if metadata_length > 4 {
                        if metadata[4] != NETWORK_UDP {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected XUDP response network",
                            ));
                        }
                        let (destination, consumed) = decode_destination(&metadata[5..])?;
                        if 5 + consumed > metadata_length {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "truncated XUDP response destination",
                            ));
                        }
                        Ok(destination)
                    } else {
                        self.last_remote.clone().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XUDP response omitted its destination before any request",
                            )
                        })
                    }
                })
                .transpose()?;

            let payload_length_end = metadata_end
                .checked_add(2)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(payload_length_end).await?;
            let payload_length = u16::from_be_bytes([
                self.receive_buffer[metadata_end],
                self.receive_buffer[metadata_end + 1],
            ]);
            if payload_length > self.max_response_payload_size {
                self.closed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "XUDP response payload length {payload_length} exceeds ceiling {}",
                        self.max_response_payload_size
                    ),
                ));
            }
            let frame_end = payload_length_end
                .checked_add(usize::from(payload_length))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XUDP frame overflow"))?;
            self.fill_receive_buffer(frame_end).await?;

            if status == STATUS_KEEP_ALIVE {
                self.receive_buffer.advance(frame_end);
                continue;
            }
            let payload =
                Bytes::copy_from_slice(&self.receive_buffer[payload_length_end..frame_end]);
            self.receive_buffer.advance(frame_end);
            return Ok(Datagram {
                remote: remote.expect("non-keepalive XUDP data has a remote destination"),
                payload,
                sniffed_domain: None,
            });
        }
    }
}

#[async_trait::async_trait]
impl DatagramTransport for XudpTransport {
    fn supports_shared_destinations(&self) -> bool {
        true
    }

    fn payload_budget(&self, _peer: &Destination) -> crate::dispatch::DatagramBudget {
        crate::dispatch::DatagramBudget::new(
            self.max_request_payload_size,
            self.max_response_payload_size,
        )
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        if self.closed {
            return Err(DispatchError::Other(
                "XUDP association is closed".to_owned(),
            ));
        }
        if datagram.payload.len() > usize::from(self.max_request_payload_size) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let result = async {
            self.flush_pending().await?;
            let frame = encode_data_frame(
                &datagram,
                self.first_write,
                if self.first_write && self.global_id != [0; 8] {
                    Some(self.global_id)
                } else {
                    None
                },
            )?;
            self.pending_write = Some(PendingWrite {
                frame,
                offset: 0,
                remote: datagram.remote,
            });
            self.flush_pending().await
        }
        .await;
        if result.is_err() {
            self.fail();
        }
        result.map_err(DispatchError::from)
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        if self.closed {
            return Err(DispatchError::Other(
                "XUDP association is closed".to_owned(),
            ));
        }
        let result = async {
            self.flush_pending().await?;
            self.read_frame().await
        }
        .await;
        if result.is_err() {
            self.fail();
        }
        result.map_err(DispatchError::from)
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut stream = self.stream.take().expect("open XUDP stream");
        // A partial data frame cannot be followed by a mux END frame. Closing
        // the last owner may discard it and terminate the underlying stream.
        if self.pending_write.take().is_none() {
            stream
                .write_all(&[0, 4, 0, 0, STATUS_END, 0])
                .await
                .map_err(DispatchError::from)?;
        }
        stream.shutdown().await.map_err(DispatchError::from)?;
        Ok(())
    }
}

pub(crate) fn encode_data_frame(
    datagram: &Datagram,
    first: bool,
    global_id: Option<[u8; 8]>,
) -> io::Result<Bytes> {
    if datagram.payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP does not send empty datagrams",
        ));
    }
    let payload_length = u16::try_from(datagram.payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XUDP datagram exceeds 65535 bytes",
        )
    })?;

    let mut destination = BytesMut::with_capacity(19);
    encode_destination(&datagram.remote, &mut destination)?;
    let global_id_length = global_id.map_or(0, |_| 8);
    let metadata_length = 2 + 1 + 1 + 1 + destination.len() + global_id_length;
    let metadata_length = u16::try_from(metadata_length).expect("XUDP metadata is bounded");

    let mut output =
        BytesMut::with_capacity(2 + usize::from(metadata_length) + 2 + datagram.payload.len());
    output.put_u16(metadata_length);
    output.put_u16(0); // one XUDP association uses mux session zero
    output.put_u8(if first { STATUS_NEW } else { STATUS_KEEP });
    output.put_u8(OPTION_DATA);
    output.put_u8(NETWORK_UDP);
    output.extend_from_slice(&destination);
    if let Some(global_id) = global_id {
        output.extend_from_slice(&global_id);
    }
    output.put_u16(payload_length);
    output.extend_from_slice(&datagram.payload);
    Ok(output.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shared_xudp_receives_frames_without_a_vless_response_header() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "shared_xudp_receives_frames_without_a_vless_response_header",
        );
        let (client, mut peer) = tokio::io::duplex(64);
        peer.write_all(&[
            0, 12, 0, 0, 2, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 3, b'a', b'b', b'c',
        ])
        .await
        .unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1452);
        let datagram = transport.receive().await.unwrap();
        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(datagram.payload.as_ref(), b"abc");
    }

    #[tokio::test]
    async fn coalesced_data_and_keepalive_preserve_every_frame_within_the_receive_budget() {
        let (client, mut server) = tokio::io::duplex(256);
        let payloads = [b"first".as_slice(), b"second", b"third"];
        let mut wire = Vec::new();
        for payload in payloads {
            // A metadata-only keepalive must not discard the following frame.
            wire.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP_ALIVE, 0]);
            wire.extend_from_slice(&response_data_prefix(payload.len() as u16));
            wire.extend_from_slice(payload);
        }
        server.write_all(&wire).await.unwrap();
        drop(server);
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1452);
        for payload in payloads {
            assert_eq!(transport.receive().await.unwrap().payload.as_ref(), payload);
            assert!(transport.receive_buffer.len() <= transport.max_receive_buffer_size);
        }
        assert!(transport.receive().await.is_err());
    }

    #[test]
    fn first_frame_matches_xray_mux_wire_format() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "first_frame_matches_xray_mux_wire_format",
        );
        let datagram = Datagram {
            remote: "1.2.3.4:53".parse::<std::net::SocketAddr>().unwrap().into(),
            payload: Bytes::from_static(b"abc"),
            sniffed_domain: None,
        };
        let frame = encode_data_frame(&datagram, true, Some([0; 8])).unwrap();
        assert_eq!(
            frame.as_ref(),
            &[
                0, 20, // metadata length
                0, 0, // mux session id
                1, 1, 2, // new, data, UDP
                0, 53, 1, 1, 2, 3, 4, // port + IPv4
                0, 0, 0, 0, 0, 0, 0, 0, // global id
                0, 3, b'a', b'b', b'c',
            ]
        );
    }

    #[test]
    fn followup_frame_carries_each_datagrams_destination() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "followup_frame_carries_each_datagrams_destination",
        );
        let datagram = Datagram {
            remote: Destination::domain("dns.example", 53).unwrap(),
            payload: Bytes::from_static(b"q"),
            sniffed_domain: None,
        };
        let frame = encode_data_frame(&datagram, false, None).unwrap();
        assert_eq!(u16::from_be_bytes([frame[0], frame[1]]), 20);
        assert_eq!(&frame[2..7], &[0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
        assert!(frame.ends_with(&[0, 1, b'q']));
    }

    #[test]
    fn destination_codec_round_trips_all_address_families() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "destination_codec_round_trips_all_address_families",
        );
        for destination in [
            Destination::from("192.0.2.1:80".parse::<std::net::SocketAddr>().unwrap()),
            Destination::from("[2001:db8::1]:443".parse::<std::net::SocketAddr>().unwrap()),
            Destination::domain("example.com", 53).unwrap(),
        ] {
            let mut encoded = BytesMut::new();
            encode_destination(&destination, &mut encoded).unwrap();
            let (decoded, consumed) = decode_destination(&encoded).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, destination);
        }
    }

    #[tokio::test]
    async fn normal_and_error_end_frames_are_distinguishable() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "normal_and_error_end_frames_are_distinguishable",
        );
        let normal = receive_frame_error(&[0, 4, 0, 0, STATUS_END, 0]).await;
        let failed = receive_frame_error(&[0, 4, 0, 0, STATUS_END, OPTION_ERROR]).await;

        assert!(
            normal
                .to_string()
                .contains("closed the association normally")
        );
        assert!(
            failed
                .to_string()
                .contains("closed the association with an error")
        );
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_payload_read() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "oversized_response_is_rejected_before_payload_read",
        );
        let (client, mut server) = tokio::io::duplex(64);
        server
            .write_all(&response_data_prefix(u16::MAX))
            .await
            .unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        let bounded_capacity = 2 + MAX_METADATA_LENGTH + 2 + 1_452;
        assert_eq!(transport.max_receive_buffer_size, bounded_capacity);
        assert_eq!(transport.receive_buffer.capacity(), bounded_capacity);

        let error = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            transport.read_frame(),
        )
        .await
        .expect("oversized length must be rejected without waiting for payload bytes")
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("65535 exceeds ceiling 1452"));
        assert_eq!(transport.receive_buffer.len(), 2 + 12 + 2);
        assert_eq!(transport.receive_buffer.capacity(), bounded_capacity);
        assert!(transport.closed);
        assert!(
            transport
                .receive()
                .await
                .unwrap_err()
                .to_string()
                .contains("closed")
        );
    }

    #[tokio::test]
    async fn fragmented_receive_survives_cancellation_and_resumes() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "fragmented_receive_survives_cancellation_and_resumes",
        );
        let (client, mut server) = tokio::io::duplex(64);
        let mut frame = response_data_prefix(3);
        frame.extend_from_slice(b"abc");

        // Stop in the middle of the two-byte metadata length. The first byte
        // has already crossed the stream boundary when receive is cancelled.
        server.write_all(&frame[..1]).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), transport.receive())
                .await
                .is_err()
        );
        assert_eq!(transport.receive_buffer.as_ref(), &[0]);

        let remaining = frame[1..].to_vec();
        let writer = tokio::spawn(async move {
            for byte in remaining {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let datagram = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
            .await
            .expect("fragmented frame should complete")
            .unwrap();
        writer.await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(&datagram.payload[..], b"abc");
        assert!(transport.receive_buffer.is_empty());
        assert!(transport.receive_buffer.capacity() <= transport.max_receive_buffer_size);
    }

    #[tokio::test]
    async fn cancelled_partial_send_preserves_the_shared_frame_boundary() {
        let (client, mut server) = tokio::io::duplex(1);
        let first = Datagram {
            remote: "192.0.2.1:53"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            payload: Bytes::from_static(b"first"),
            sniffed_domain: None,
        };
        let second = Datagram {
            remote: "192.0.2.2:53"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
            payload: Bytes::from_static(b"second"),
            sniffed_domain: None,
        };
        let mut expected = encode_data_frame(&first, true, None).unwrap().to_vec();
        expected.extend_from_slice(&encode_data_frame(&second, false, None).unwrap());
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1452);
        assert!(futures_util::poll!(transport.send(first)).is_pending());
        let length = expected.len();
        let reader = tokio::spawn(async move {
            let mut received = vec![0; length];
            server.read_exact(&mut received).await.unwrap();
            received
        });
        transport.send(second).await.unwrap();
        assert_eq!(reader.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn receive_finishes_a_cancelled_partial_send_without_another_packet() {
        let (client, mut server) = tokio::io::duplex(1);
        let request = Datagram {
            remote: "1.2.3.4:53".parse::<std::net::SocketAddr>().unwrap().into(),
            payload: Bytes::from_static(b"abc"),
            sniffed_domain: None,
        };
        let expected = encode_data_frame(&request, true, None).unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1452);
        assert!(futures_util::poll!(transport.send(request)).is_pending());
        let peer = tokio::spawn(async move {
            let mut wire = vec![0; expected.len()];
            server.read_exact(&mut wire).await.unwrap();
            assert_eq!(wire, expected);
            let mut response = response_data_prefix(3);
            response.extend_from_slice(b"abc");
            server.write_all(&response).await.unwrap();
        });
        assert_eq!(transport.receive().await.unwrap().payload.as_ref(), b"abc");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_data_is_consumed_without_becoming_an_udp_response() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "keepalive_data_is_consumed_without_becoming_an_udp_response",
        );
        let (client, mut server) = tokio::io::duplex(128);
        let mut wire = vec![
            0,
            4, // metadata length
            0,
            0, // mux session id
            STATUS_KEEP_ALIVE,
            OPTION_DATA,
            0,
            4, // discarded payload length
        ];
        wire.extend_from_slice(b"ping");
        wire.extend_from_slice(&response_data_prefix(3));
        wire.extend_from_slice(b"abc");
        server.write_all(&wire).await.unwrap();

        let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1_452);
        let datagram = transport.receive().await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(&datagram.payload[..], b"abc");
        assert!(transport.receive_buffer.is_empty());
    }

    #[tokio::test]
    async fn full_wire_payload_remains_available_to_proxy_inbounds() {
        #[cfg(any(test, feature = "interop-test"))]
        let mut _case = crate::resources::case_events::Case::new(
            "FOUNDATIONS-XUDP",
            "full_wire_payload_remains_available_to_proxy_inbounds",
        );
        let (client, mut server) = tokio::io::duplex(66_000);
        let mut frame = response_data_prefix(u16::MAX);
        frame.resize(frame.len() + usize::from(u16::MAX), 0x5a);
        server.write_all(&frame).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], u16::MAX);

        let datagram = transport.receive().await.unwrap();

        assert_eq!(datagram.remote.to_string(), "1.2.3.4:53");
        assert_eq!(datagram.payload.len(), usize::from(u16::MAX));
        assert!(datagram.payload.iter().all(|byte| *byte == 0x5a));
    }

    fn response_data_prefix(payload_length: u16) -> Vec<u8> {
        let mut frame = vec![
            0,
            12, // metadata length
            0,
            0, // mux session id
            STATUS_KEEP,
            OPTION_DATA,
            NETWORK_UDP,
            0,
            53,
            1,
            1,
            2,
            3,
            4, // port + IPv4
        ];
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame
    }

    async fn receive_frame_error(frame: &[u8]) -> DispatchError {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(frame).await.unwrap();
        let mut transport = XudpTransport::new(Box::new(client), [0; 8], u16::MAX);
        transport.receive().await.unwrap_err()
    }
}
