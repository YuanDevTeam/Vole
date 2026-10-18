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
    flush_each_frame: bool,
    last_remote: Option<Destination>,
    multiple_remotes: bool,
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
            flush_each_frame: true,
            last_remote: None,
            multiple_remotes: false,
            pending_write: None,
            receive_buffer: BytesMut::with_capacity(max_receive_buffer_size),
            max_receive_buffer_size,
            closed: false,
        }
    }

    /// Only for a supplied transport whose owned driver independently advances
    /// every accepted write. Ordinary buffered streams retain per-frame flush.
    pub(crate) fn with_autonomous_writes(mut self) -> Self {
        self.flush_each_frame = false;
        self
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
            if self.first_write || self.flush_each_frame {
                stream.flush().await?;
            }
            self.first_write = false;
            let remote = self.pending_write.take().expect("pending frame").remote;
            self.multiple_remotes |= self
                .last_remote
                .as_ref()
                .is_some_and(|last| last != &remote);
            self.last_remote = Some(remote);
        }
        Ok(())
    }

    fn fail(&mut self) {
        self.closed = true;
        self.pending_write = None;
        self.stream.take();
    }

    /// Incrementally fills the persistent receive buffer using only
    /// cancellation-safe `read_buf` calls. Every successful partial read is
    /// committed before the next await, so dropping `receive()` from a
    /// `tokio::select!` cannot lose bytes or parser progress.
    async fn fill_receive_buffer(&mut self, required: usize) -> io::Result<()> {
        if required > self.max_receive_buffer_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XUDP receive frame exceeds the bounded buffer",
            ));
        }

        while self.receive_buffer.len() < required {
            // Consume available stream bytes within the existing one-frame
            // byte budget. Reading exactly each small header field repeatedly
            // enters TLS/H2 even when several complete packets are ready.
            let remaining = self.max_receive_buffer_size - self.receive_buffer.len();
            let mut destination = (&mut self.receive_buffer).limit(remaining);
            let read = self
                .stream
                .as_mut()
                .expect("open XUDP stream")
                .read_buf(&mut destination)
                .await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "XUDP stream ended in the middle of a frame",
                ));
            }
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
                        if self.multiple_remotes {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "XUDP response omitted an ambiguous destination",
                            ));
                        }
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

    let destination_length = match &datagram.remote {
        Destination::Ip(address) if address.is_ipv4() => 7,
        Destination::Ip(_) => 19,
        Destination::Domain { host, .. } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "proxy domain is too long")
            })?;
            4 + usize::from(length)
        }
    };
    let global_id_length = global_id.map_or(0, |_| 8);
    let metadata_length = 2 + 1 + 1 + 1 + destination_length + global_id_length;
    let metadata_length = u16::try_from(metadata_length).expect("XUDP metadata is bounded");

    let mut output =
        BytesMut::with_capacity(2 + usize::from(metadata_length) + 2 + datagram.payload.len());
    output.put_u16(metadata_length);
    output.put_u16(0); // one XUDP association uses mux session zero
    output.put_u8(if first { STATUS_NEW } else { STATUS_KEEP });
    output.put_u8(OPTION_DATA);
    output.put_u8(NETWORK_UDP);
    encode_destination(&datagram.remote, &mut output)?;
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

    struct FlushGate {
        inner: tokio::io::DuplexStream,
        blocked: std::sync::Arc<std::sync::atomic::AtomicBool>,
        reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl tokio::io::AsyncRead for FlushGate {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            self.reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }
    impl tokio::io::AsyncWrite for FlushGate {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buffer)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.blocked.load(std::sync::atomic::Ordering::Relaxed) {
                std::task::Poll::Pending
            } else {
                std::pin::Pin::new(&mut self.inner).poll_flush(cx)
            }
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn autonomous_upload_skips_only_established_frame_flush_barriers() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        for autonomous in [false, true] {
            let (client, mut server) = tokio::io::duplex(256);
            let blocked = Arc::new(AtomicBool::new(true));
            let mut transport = XudpTransport::new(
                Box::new(FlushGate {
                    inner: client,
                    blocked: blocked.clone(),
                    reads: std::sync::Arc::default(),
                }),
                [0; 8],
                1452,
            );
            if autonomous {
                transport = transport.with_autonomous_writes();
            }
            let packet = Datagram {
                remote: "192.0.2.1:53"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                payload: Bytes::from_static(b"packet"),
                sniffed_domain: None,
            };
            assert!(
                futures_util::poll!(transport.send(packet.clone())).is_pending(),
                "first frame must retain its setup flush"
            );
            blocked.store(false, Ordering::Relaxed);
            // Finish the cancelled first frame without introducing a duplicate.
            transport.flush_pending().await.unwrap();
            blocked.store(true, Ordering::Relaxed);
            let sent = futures_util::poll!(transport.send(packet.clone()));
            assert_eq!(sent.is_ready(), autonomous);
            blocked.store(false, Ordering::Relaxed);
            transport.flush_pending().await.unwrap();
            let mut expected = encode_data_frame(&packet, true, None).unwrap().to_vec();
            expected.extend_from_slice(&encode_data_frame(&packet, false, None).unwrap());
            let mut actual = vec![0; expected.len()];
            server.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn mtu_sized_response_and_coalesced_tail_use_one_bounded_read() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let payload = vec![b'x'; 1452];
        let mut wire = response_data_prefix(payload.len() as u16);
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(&response_data_prefix(4));
        wire.extend_from_slice(b"tail");
        let (client, mut server) = tokio::io::duplex(4096);
        server.write_all(&wire).await.unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut transport = XudpTransport::new(
            Box::new(FlushGate {
                inner: client,
                blocked: Arc::new(AtomicBool::new(false)),
                reads: reads.clone(),
            }),
            [0; 8],
            1452,
        );
        assert_eq!(transport.receive().await.unwrap().payload.as_ref(), payload);
        assert_eq!(transport.receive().await.unwrap().payload.as_ref(), b"tail");
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert!(transport.receive_buffer.capacity() <= transport.max_receive_buffer_size);
    }

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

    #[tokio::test]
    async fn omitted_response_destination_is_accepted_only_for_an_unambiguous_association() {
        for destinations in [1, 2] {
            let (client, mut server) = tokio::io::duplex(256);
            let mut transport = XudpTransport::new(Box::new(client), [0; 8], 1452);
            for last in 1..=destinations {
                transport
                    .send(Datagram {
                        remote: format!("192.0.2.{last}:53")
                            .parse::<std::net::SocketAddr>()
                            .unwrap()
                            .into(),
                        payload: Bytes::from_static(b"q"),
                        sniffed_domain: None,
                    })
                    .await
                    .unwrap();
            }
            server
                .write_all(&[0, 4, 0, 0, STATUS_KEEP, OPTION_DATA, 0, 1, b'a'])
                .await
                .unwrap();
            let reply = transport.receive().await;
            if destinations == 1 {
                assert_eq!(reply.unwrap().remote.to_string(), "192.0.2.1:53");
            } else {
                assert!(
                    reply.is_err(),
                    "an omitted address must not select the last sender"
                );
                assert!(transport.closed);
            }
        }
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
        let cases: [(Destination, &[u8]); 2] = [
            (
                Destination::domain("dns.example", 53).unwrap(),
                b"\x00\x14\x00\x00\x02\x01\x02\x00\x35\x02\x0bdns.example\x00\x01q",
            ),
            (
                "[2001:db8::1]:443"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                &[
                    0, 24, 0, 0, 2, 1, 2, 1, 187, 3, // KEEP, UDP, port, IPv6
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, b'q',
                ],
            ),
        ];
        for (remote, expected) in cases {
            let datagram = Datagram {
                remote,
                payload: Bytes::from_static(b"q"),
                sniffed_domain: None,
            };
            assert_eq!(
                encode_data_frame(&datagram, false, None).unwrap().as_ref(),
                expected
            );
        }
    }

    #[test]
    fn maximum_domain_and_payload_preserve_wire_lengths_and_reject_overflow() {
        let mut datagram = Datagram {
            remote: Destination::domain("x".repeat(255), 443).unwrap(),
            payload: Bytes::from(vec![7; usize::from(u16::MAX)]),
            sniffed_domain: None,
        };
        let frame = encode_data_frame(&datagram, true, Some([9; 8])).unwrap();
        assert_eq!(frame.len(), 65_811);
        assert_eq!(&frame[..11], &[1, 16, 0, 0, 1, 1, 2, 1, 187, 2, 255]);
        assert!(frame[11..266].iter().all(|byte| *byte == b'x'));
        assert_eq!(&frame[266..274], &[9; 8]);
        assert_eq!(&frame[274..276], &[255, 255]);
        assert!(frame[276..].iter().all(|byte| *byte == 7));

        datagram.payload = Bytes::from(vec![7; usize::from(u16::MAX) + 1]);
        assert_eq!(
            encode_data_frame(&datagram, false, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        datagram.payload = Bytes::new();
        assert_eq!(
            encode_data_frame(&datagram, false, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        datagram.payload = Bytes::from_static(b"q");
        datagram.remote = Destination::Domain {
            host: "x".repeat(256),
            port: 443,
        };
        assert_eq!(
            encode_data_frame(&datagram, false, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
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
