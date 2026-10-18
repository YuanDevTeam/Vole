use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    dispatch::{DatagramTransport, DispatchError},
    session::{Datagram, Destination},
    socks5::encode_address,
};

pub(crate) const MAGIC_DESTINATION: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_ADDRESS_IPV4: u8 = 0x00;
const UOT_ADDRESS_IPV6: u8 = 0x01;
const UOT_ADDRESS_DOMAIN: u8 = 0x02;
const RESPONSE_QUEUE_CAPACITY: usize = 1;
const DRAIN_BUFFER_SIZE: usize = 2_048;

#[derive(Debug, Clone)]
struct ReceiveFailure {
    kind: io::ErrorKind,
    message: Arc<str>,
}

impl ReceiveFailure {
    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: Arc::from(error.to_string()),
        }
    }

    fn into_dispatch(self) -> DispatchError {
        DispatchError::from(io::Error::new(self.kind, self.message.to_string()))
    }
}

enum ReceiveEvent {
    Datagram(Datagram),
    Failed(ReceiveFailure),
}

struct PendingWrite {
    packet: Bytes,
    offset: usize,
}

pub(crate) struct UotTransport {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    responses: mpsc::Receiver<ReceiveEvent>,
    cancellation: CancellationToken,
    reader_task: Option<JoinHandle<()>>,
    first_write: bool,
    initial_deadline: Option<tokio::time::Instant>,
    pending_write: Option<PendingWrite>,
    closed: bool,
}

impl std::fmt::Debug for UotTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UotTransport")
            .field("first_write", &self.first_write)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl UotTransport {
    pub(crate) fn new<R, W>(
        reader: R,
        writer: W,
        max_response_payload_size: u16,
        parent_cancellation: CancellationToken,
        tracker: &TaskTracker,
    ) -> Self
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let cancellation = parent_cancellation.child_token();
        let (responses, receiver) = mpsc::channel(RESPONSE_QUEUE_CAPACITY);
        let reader_cancellation = cancellation.clone();
        let reader_task = tracker.spawn(crate::resources::observation::task(read_loop(
            reader,
            responses,
            max_response_payload_size,
            reader_cancellation,
        )));
        Self {
            writer: Box::new(writer),
            responses: receiver,
            cancellation,
            reader_task: Some(reader_task),
            first_write: true,
            initial_deadline: None,
            pending_write: None,
            closed: false,
        }
    }
    #[cfg(feature = "outbound-tuic")]
    pub(crate) fn with_initial_deadline(mut self, deadline: tokio::time::Instant) -> Self {
        self.initial_deadline = Some(deadline);
        self
    }

    fn check_open(&mut self) -> Result<(), DispatchError> {
        if self.closed || self.cancellation.is_cancelled() {
            return Err(DispatchError::Other("UoT association is closed".to_owned()));
        }
        if self
            .initial_deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            self.fail();
            return Err(DispatchError::TimedOut);
        }
        Ok(())
    }

    fn fail(&mut self) {
        self.closed = true;
        self.pending_write = None;
        self.cancellation.cancel();
    }

    async fn flush_pending(&mut self) -> Result<(), DispatchError> {
        let Some(pending) = &mut self.pending_write else {
            return Ok(());
        };
        let cancellation = self.cancellation.clone();
        let initial_deadline = self.initial_deadline;
        let writing = async {
            while pending.offset < pending.packet.len() {
                let written = self.writer.write(&pending.packet[pending.offset..]).await?;
                if written == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                pending.offset += written;
            }
            self.writer.flush().await
        };
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(DispatchError::NotAllowed),
            result = async {
                if let Some(deadline) = initial_deadline {
                    tokio::time::timeout_at(deadline, writing).await.map_err(|_| DispatchError::TimedOut)?
                        .map_err(DispatchError::from)
                } else { writing.await.map_err(DispatchError::from) }
            } => result,
        };
        if let Err(error) = result {
            self.fail();
            return Err(error);
        }
        self.pending_write = None;
        self.first_write = false;
        self.initial_deadline = None;
        Ok(())
    }
}

#[async_trait]
impl DatagramTransport for UotTransport {
    fn supports_shared_destinations(&self) -> bool {
        // Datagram mode carries a destination in every packet.
        true
    }

    async fn send(&mut self, datagram: Datagram) -> Result<(), DispatchError> {
        self.check_open()?;
        self.flush_pending().await?;
        let packet = if self.first_write {
            encode_first_packet(&datagram).map_err(DispatchError::from)?
        } else {
            encode_datagram(&datagram).map_err(DispatchError::from)?
        };
        self.pending_write = Some(PendingWrite { packet, offset: 0 });
        self.flush_pending().await
    }

    async fn receive(&mut self) -> Result<Datagram, DispatchError> {
        self.check_open()?;
        self.flush_pending().await?;
        match self.responses.recv().await {
            Some(ReceiveEvent::Datagram(datagram)) => Ok(datagram),
            Some(ReceiveEvent::Failed(error)) => {
                self.closed = true;
                Err(error.into_dispatch())
            }
            None => {
                self.closed = true;
                Err(DispatchError::from(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "UoT response stream ended",
                )))
            }
        }
    }

    async fn close(&mut self) -> Result<(), DispatchError> {
        if self.closed && self.reader_task.is_none() {
            return Ok(());
        }
        self.cancellation.cancel();
        self.pending_write = None;
        if let Some(reader_task) = self.reader_task.take() {
            let _ = reader_task.await;
        }
        let result = self.writer.shutdown().await.map_err(DispatchError::from);
        self.closed = true;
        result
    }
}

impl Drop for UotTransport {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(reader_task) = self.reader_task.take() {
            reader_task.abort();
        }
    }
}

async fn read_loop<R>(
    mut reader: R,
    responses: mpsc::Sender<ReceiveEvent>,
    max_response_payload_size: u16,
    cancellation: CancellationToken,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            datagram = read_datagram(&mut reader, max_response_payload_size) => datagram,
        };
        match outcome {
            Ok(Some(datagram)) => {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return,
                    result = responses.send(ReceiveEvent::Datagram(datagram)) => {
                        if result.is_err() {
                            return;
                        }
                    }
                }
            }
            Ok(None) => continue,
            Err(error) => {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => {}
                    _ = responses.send(ReceiveEvent::Failed(ReceiveFailure::from_io(&error))) => {}
                }
                return;
            }
        }
    }
}

pub(crate) fn magic_destination() -> Destination {
    Destination::Domain {
        host: MAGIC_DESTINATION.to_owned(),
        port: 0,
    }
}

fn encode_first_packet(datagram: &Datagram) -> io::Result<Bytes> {
    let request = encode_request(&datagram.remote)?;
    let packet = encode_datagram(datagram)?;
    let mut output = BytesMut::with_capacity(request.len() + packet.len());
    output.extend_from_slice(&request);
    output.extend_from_slice(&packet);
    Ok(output.freeze())
}

fn encode_request(destination: &Destination) -> io::Result<Bytes> {
    let mut output = Vec::with_capacity(260);
    output.push(0); // Datagram mode; one association may carry many destinations.
    encode_address(destination, &mut output)?;
    Ok(Bytes::from(output))
}

fn encode_datagram(datagram: &Datagram) -> io::Result<Bytes> {
    let payload_length = u16::try_from(datagram.payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UoT datagram exceeds 65535 bytes",
        )
    })?;
    let mut output = BytesMut::with_capacity(259 + 2 + datagram.payload.len());
    encode_uot_address(&datagram.remote, &mut output)?;
    output.put_u16(payload_length);
    output.extend_from_slice(&datagram.payload);
    Ok(output.freeze())
}

fn encode_uot_address(destination: &Destination, output: &mut BytesMut) -> io::Result<()> {
    match destination {
        Destination::Ip(SocketAddr::V4(address)) => {
            output.put_u8(UOT_ADDRESS_IPV4);
            output.extend_from_slice(&address.ip().octets());
            output.put_u16(address.port());
        }
        Destination::Ip(SocketAddr::V6(address)) => {
            output.put_u8(UOT_ADDRESS_IPV6);
            output.extend_from_slice(&address.ip().octets());
            output.put_u16(address.port());
        }
        Destination::Domain { host, port } => {
            let length = u8::try_from(host.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "UoT domain is too long")
            })?;
            if length == 0 || *port == 0 || host.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UoT destination is invalid",
                ));
            }
            output.put_u8(UOT_ADDRESS_DOMAIN);
            output.put_u8(length);
            output.extend_from_slice(host.as_bytes());
            output.put_u16(*port);
        }
    }
    if destination.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UoT destination port is zero",
        ));
    }
    Ok(())
}

async fn read_datagram<R>(
    reader: &mut R,
    max_response_payload_size: u16,
) -> io::Result<Option<Datagram>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let remote = read_uot_address(reader).await?;
    let payload_length = reader.read_u16().await?;
    if payload_length > max_response_payload_size {
        drain_exact(reader, usize::from(payload_length)).await?;
        return Ok(None);
    }
    let mut payload = BytesMut::zeroed(usize::from(payload_length));
    reader.read_exact(&mut payload).await?;
    Ok(Some(Datagram {
        remote,
        payload: payload.freeze(),
        sniffed_domain: None,
    }))
}

async fn drain_exact<R>(reader: &mut R, mut remaining: usize) -> io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = [0_u8; DRAIN_BUFFER_SIZE];
    while remaining != 0 {
        let length = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..length]).await?;
        remaining -= length;
    }
    Ok(())
}

async fn read_uot_address<R>(reader: &mut R) -> io::Result<Destination>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let address_type = reader.read_u8().await?;
    let destination = match address_type {
        UOT_ADDRESS_IPV4 => {
            let mut address = [0_u8; 4];
            reader.read_exact(&mut address).await?;
            let port = reader.read_u16().await?;
            Destination::Ip(SocketAddr::from((address, port)))
        }
        UOT_ADDRESS_IPV6 => {
            let mut address = [0_u8; 16];
            reader.read_exact(&mut address).await?;
            let port = reader.read_u16().await?;
            Destination::Ip(SocketAddr::from((address, port)))
        }
        UOT_ADDRESS_DOMAIN => {
            let length = usize::from(reader.read_u8().await?);
            if length == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UoT response has an empty domain",
                ));
            }
            let mut host = vec![0_u8; length];
            reader.read_exact(&mut host).await?;
            let host = String::from_utf8(host).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "UoT response domain is not UTF-8",
                )
            })?;
            let port = reader.read_u16().await?;
            Destination::domain(host, port)?
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UoT response has an unknown address type",
            ));
        }
    };
    if destination.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UoT response port is zero",
        ));
    }
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::*;

    fn datagram(remote: Destination, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote,
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    #[test]
    fn encodes_v2_address_families() {
        let ipv4 = encode_datagram(&datagram(
            Destination::Ip((Ipv4Addr::new(1, 2, 3, 4), 53).into()),
            b"x",
        ))
        .unwrap();
        assert_eq!(ipv4.as_ref(), &[0, 1, 2, 3, 4, 0, 53, 0, 1, b'x']);

        let ipv6 = encode_datagram(&datagram(
            Destination::Ip((Ipv6Addr::LOCALHOST, 443).into()),
            b"",
        ))
        .unwrap();
        assert_eq!(ipv6[0], UOT_ADDRESS_IPV6);
        assert_eq!(&ipv6[17..], &[1, 187, 0, 0]);

        let domain = encode_datagram(&datagram(
            Destination::domain("dns.test", 853).unwrap(),
            b"q",
        ))
        .unwrap();
        assert_eq!(domain[0], UOT_ADDRESS_DOMAIN);
        assert_eq!(domain[1], 8);
        assert_eq!(&domain[2..10], b"dns.test");
        assert_eq!(&domain[10..], &[3, 85, 0, 1, b'q']);
    }

    #[test]
    fn first_packet_combines_request_and_datagram() {
        let packet = encode_first_packet(&datagram(
            Destination::domain("dns.test", 53).unwrap(),
            b"abc",
        ))
        .unwrap();
        assert_eq!(packet[0], 0);
        assert_eq!(packet[1], 3); // Standard SOCKS domain address in Request.
        assert_eq!(packet[2], 8);
        let datagram_offset = 1 + 1 + 1 + 8 + 2;
        assert_eq!(packet[datagram_offset], UOT_ADDRESS_DOMAIN);
    }

    #[test]
    fn rejects_invalid_destinations_and_enforces_the_u16_payload_limit() {
        for remote in [
            Destination::Ip("127.0.0.1:0".parse().unwrap()),
            Destination::Ip("[::1]:0".parse().unwrap()),
            Destination::Domain {
                host: String::new(),
                port: 53,
            },
            Destination::Domain {
                host: "a".repeat(256),
                port: 53,
            },
            Destination::Domain {
                host: "bad\nname.test".into(),
                port: 53,
            },
            Destination::Domain {
                host: "dns.test".into(),
                port: 0,
            },
        ] {
            assert!(encode_first_packet(&datagram(remote, b"x")).is_err());
        }
        let mut packet = datagram(Destination::domain("a".repeat(255), 53).unwrap(), b"");
        packet.payload = Bytes::from(vec![7; 65_535]);
        assert!(encode_first_packet(&packet).is_ok());
        packet.payload = Bytes::from(vec![7; 65_536]);
        assert!(encode_first_packet(&packet).is_err());
    }

    #[cfg(feature = "outbound-tuic")]
    #[tokio::test]
    async fn tuic_uot_v2_writes_independent_vectors_and_joins_after_stop() {
        let tracker = TaskTracker::new();
        let cancellation = CancellationToken::new();
        let (io, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(io);
        let mut transport = UotTransport::new(reader, writer, 8, cancellation.clone(), &tracker)
            .with_initial_deadline(tokio::time::Instant::now() + Duration::from_secs(1));
        let packet = datagram(
            Destination::Ip((Ipv4Addr::new(1, 2, 3, 4), 53).into()),
            b"q",
        );
        transport.send(packet).await.unwrap();
        let expected: &[u8] = &[0, 1, 1, 2, 3, 4, 0, 53, 0, 1, 2, 3, 4, 0, 53, 0, 1, b'q'];
        let mut actual = vec![0; expected.len()];
        peer.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        // The response codec is supplied independently of the request encoder.
        peer.write_all(&[0, 8, 8, 8, 8, 0, 53, 0, 1, b'a'])
            .await
            .unwrap();
        let reply = transport.receive().await.unwrap();
        assert_eq!(
            reply.remote,
            Destination::Ip((Ipv4Addr::new(8, 8, 8, 8), 53).into())
        );
        assert_eq!(reply.payload.as_ref(), b"a");
        cancellation.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(1), transport.close())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
    }

    #[cfg(feature = "outbound-tuic")]
    #[tokio::test]
    async fn tuic_uot_expired_original_first_packet_deadline_sends_no_bytes() {
        let tracker = TaskTracker::new();
        let (io, mut peer) = tokio::io::duplex(128);
        let (reader, writer) = tokio::io::split(io);
        let mut transport =
            UotTransport::new(reader, writer, 8, CancellationToken::new(), &tracker)
                .with_initial_deadline(tokio::time::Instant::now());
        assert!(matches!(
            transport
                .send(datagram(Destination::domain("dns.test", 53).unwrap(), b"q"))
                .await,
            Err(DispatchError::TimedOut)
        ));
        tracker.close();
        transport.close().await.unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
        tracker.wait().await;
    }

    #[tokio::test]
    async fn malformed_and_truncated_responses_are_rejected_without_a_datagram() {
        // Independent wire vectors, including a length-prefixed invalid UTF-8
        // name and incomplete payload. No production encoder creates input.
        for frame in [
            vec![3],
            vec![2, 0],
            vec![2, 1, 255, 0, 53, 0, 0],
            vec![2, 1, b'\n', 0, 53, 0, 0],
            vec![0, 127, 0, 0, 1, 0, 0, 0, 0],
            vec![1, 0],
            vec![0, 127, 0, 0, 1, 0, 53, 0, 2, 7],
        ] {
            assert!(
                read_datagram(&mut frame.as_slice(), u16::MAX)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn reads_fragmented_datagram() {
        let encoded = encode_datagram(&datagram(
            Destination::domain("dns.test", 53).unwrap(),
            b"reply",
        ))
        .unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(1);
        let sending = tokio::spawn(async move {
            for byte in encoded {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        let decoded = read_datagram(&mut reader, 64).await.unwrap().unwrap();
        sending.await.unwrap();
        assert_eq!(decoded.remote, Destination::domain("dns.test", 53).unwrap());
        assert_eq!(decoded.payload.as_ref(), b"reply");
    }

    #[tokio::test]
    async fn oversized_payload_is_drained_before_the_next_datagram() {
        let oversized = encode_datagram(&datagram(
            Destination::Ip((Ipv4Addr::new(1, 2, 3, 4), 53).into()),
            b"oversized",
        ))
        .unwrap();
        let expected = datagram(Destination::domain("dns.test", 53).unwrap(), b"accepted");
        let accepted = encode_datagram(&expected).unwrap();
        let mut input = std::io::Cursor::new([oversized.as_ref(), accepted.as_ref()].concat());

        assert!(read_datagram(&mut input, 4).await.unwrap().is_none());
        let decoded = read_datagram(&mut input, 64).await.unwrap().unwrap();
        assert_eq!(decoded.remote, expected.remote);
        assert_eq!(decoded.payload, expected.payload);
    }

    #[tokio::test]
    async fn cancelled_partial_write_finishes_before_the_next_datagram() {
        assert_cancelled_frame_progress(true).await;
    }

    #[tokio::test]
    async fn receive_finishes_a_cancelled_partial_write_without_another_send() {
        assert_cancelled_frame_progress(false).await;
    }

    #[cfg(feature = "outbound-tuic")]
    #[tokio::test(start_paused = true)]
    async fn cancelled_first_write_keeps_its_original_deadline() {
        let tracker = TaskTracker::new();
        let (io, mut peer) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(io);
        let mut transport =
            UotTransport::new(reader, writer, 64, CancellationToken::new(), &tracker)
                .with_initial_deadline(tokio::time::Instant::now() + Duration::from_secs(1));
        let packet = datagram(
            "192.0.2.1:53".parse::<SocketAddr>().unwrap().into(),
            b"request",
        );
        assert!(futures_util::poll!(transport.send(packet)).is_pending());
        assert_eq!(peer.read_u8().await.unwrap(), 0);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(matches!(
            transport.receive().await,
            Err(DispatchError::TimedOut)
        ));
        transport.close().await.unwrap();
        let mut extra = Vec::new();
        peer.read_to_end(&mut extra).await.unwrap();
        assert!(extra.is_empty());
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn close_discards_a_pending_frame_without_waiting_for_write_capacity() {
        let tracker = TaskTracker::new();
        let (io, mut peer) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(io);
        let mut transport =
            UotTransport::new(reader, writer, 64, CancellationToken::new(), &tracker);
        let packet = datagram(
            "192.0.2.1:53".parse::<SocketAddr>().unwrap().into(),
            b"request",
        );
        assert!(futures_util::poll!(transport.send(packet)).is_pending());
        tokio::time::timeout(Duration::from_secs(1), transport.close())
            .await
            .unwrap()
            .unwrap();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
        let mut prefix = Vec::new();
        peer.read_to_end(&mut prefix).await.unwrap();
        assert_eq!(prefix, [0]);
        assert!(transport.receive().await.is_err());
    }

    async fn assert_cancelled_frame_progress(send_another: bool) {
        let tracker = TaskTracker::new();
        let (io, mut peer) = tokio::io::duplex(1);
        let (reader, writer) = tokio::io::split(io);
        let mut transport =
            UotTransport::new(reader, writer, 64, CancellationToken::new(), &tracker);
        let first = datagram(
            "192.0.2.1:53".parse::<SocketAddr>().unwrap().into(),
            b"first",
        );
        let second = datagram(
            "[2001:db8::2]:853".parse::<SocketAddr>().unwrap().into(),
            b"second",
        );
        let mut expected = encode_first_packet(&first).unwrap().to_vec();
        if send_another {
            expected.extend_from_slice(&encode_datagram(&second).unwrap());
        }
        assert!(futures_util::poll!(transport.send(first.clone())).is_pending());
        assert!(
            !transport.cancellation.is_cancelled(),
            "dropping one partial send must preserve the shared wire"
        );
        let prefix = peer.read_u8().await.unwrap();
        assert_eq!(prefix, expected[0]);
        let remaining = expected.len() - 1;
        let reply = encode_datagram(&datagram(first.remote.clone(), b"reply")).unwrap();
        let server = tokio::spawn(async move {
            let mut received = vec![prefix; 1];
            received.resize(remaining + 1, 0);
            peer.read_exact(&mut received[1..]).await.unwrap();
            peer.write_all(&reply).await.unwrap();
            received
        });
        if send_another {
            transport.send(second).await.unwrap();
        }
        let reply = tokio::time::timeout(Duration::from_secs(1), transport.receive())
            .await
            .expect("pending frame prevented receive progress")
            .unwrap();
        assert_eq!(reply.remote, first.remote);
        assert_eq!(reply.payload.as_ref(), b"reply");
        assert_eq!(server.await.unwrap(), expected);
        transport.close().await.unwrap();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn read_loop_shutdown_is_not_blocked_by_a_full_response_queue() {
        let first = encode_datagram(&datagram(
            Destination::Ip((Ipv4Addr::new(1, 1, 1, 1), 53).into()),
            b"first",
        ))
        .unwrap();
        let second = encode_datagram(&datagram(
            Destination::Ip((Ipv4Addr::new(8, 8, 8, 8), 53).into()),
            b"second",
        ))
        .unwrap();
        let (mut writer, reader) = tokio::io::duplex(256);
        let (responses, _receiver) = mpsc::channel(1);
        let capacity = responses.clone();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(read_loop(reader, responses, 64, cancellation.clone()));
        writer.write_all(&first).await.unwrap();
        writer.write_all(&second).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            while capacity.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("read loop must observe cancellation while response send is pending")
            .unwrap();
    }
}
