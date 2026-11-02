use super::{
    BodyCipher, BodyOptions, ClientHandshake, Command,
    crypto::{aead_key, error, kdf, open, random, seal},
};
use crate::dispatch::BoxStream;
use bytes::{Buf, Bytes, BytesMut};
use ring::aead;
use shake::{ExtendableOutput, Shake128, Update, XofReader};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const MAX_BODY_WIRE: usize = 16 * 1024;
// Keep TCP chunks within the native Mihomo listener's initial copy buffer.
// Larger first chunks leave a cache tail which sing's switch to an MTU-sized
// ReadBuffer can skip. This shapes only our wire, never third-party source.
pub const WRITE_CHUNK: usize = 4 * 1024;
/// One intact UDP body; native Mihomo's writer chunks at 15,000 bytes.
/// TCP uses smaller pieces, but splitting a UDP body would change its meaning.
pub const MAX_PACKET_BYTES: usize = 15_000;

struct BodyCodec {
    options: BodyOptions,
    iv: [u8; 16],
    length_iv: [u8; 16],
    body: aead::LessSafeKey,
    length: Option<Box<aead::LessSafeKey>>,
    mask: shake::Shake128Reader,
    counter: u16,
    framed: bool,
    write_limit: usize,
}

impl BodyCodec {
    fn new(
        options: BodyOptions,
        command: Command,
        key: &[u8; 16],
        iv: [u8; 16],
        request_key: &[u8; 16],
        request_iv: [u8; 16],
    ) -> Self {
        let mut mask = Shake128::default();
        mask.update(&iv);
        // Most streams do not authenticate lengths. Keep that expanded key
        // out of each direction's resident codec unless it is actually used.
        let length = options.authenticated_length.then(|| {
            let key = kdf(request_key, &[b"auth_len"]);
            Box::new(aead_key(options.cipher, key[..16].try_into().unwrap()))
        });
        Self {
            options,
            iv,
            length_iv: request_iv,
            body: aead_key(options.cipher, key),
            length,
            mask: mask.finalize_xof(),
            counter: 0,
            framed: options.cipher != BodyCipher::None || command == Command::Udp,
            write_limit: if command == Command::Udp {
                MAX_PACKET_BYTES
            } else {
                WRITE_CHUNK
            },
        }
    }
    fn overhead(&self) -> usize {
        if self.options.cipher == BodyCipher::None {
            0
        } else {
            16
        }
    }
    fn length_size(&self) -> usize {
        if self.options.authenticated_length {
            18
        } else {
            2
        }
    }
    fn nonce(&self, iv: &[u8; 16]) -> [u8; 12] {
        // Match Mihomo/sing-vmess and V2Ray's 16-bit wire counter. VMess
        // does not negotiate a larger counter or rekey at the wrap boundary.
        let mut nonce: [u8; 12] = iv[..12].try_into().unwrap();
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }
    fn next_mask(&mut self) -> u16 {
        let mut bytes = [0; 2];
        self.mask.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
    fn padding(&mut self) -> usize {
        if self.options.padding {
            usize::from(self.next_mask() % 64)
        } else {
            0
        }
    }
    fn encode(&mut self, plain: &[u8]) -> io::Result<Bytes> {
        if plain.len() > self.write_limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess chunk exceeds limit",
            ));
        }
        if !self.framed {
            return Ok(Bytes::copy_from_slice(plain));
        }
        let padding = self.padding();
        let mut body = plain.to_vec();
        if self.overhead() != 0 {
            seal(&self.body, self.nonce(&self.iv), &[], &mut body)?;
        }
        let mut length = (body.len() + padding) as u16;
        let mut wire = if let Some(key) = self.length.as_deref() {
            let mut encoded = (length - 16).to_be_bytes().to_vec();
            seal(key, self.nonce(&self.length_iv), &[], &mut encoded)?;
            encoded
        } else {
            if self.options.cipher != BodyCipher::None {
                length ^= self.next_mask();
            }
            length.to_be_bytes().to_vec()
        };
        wire.extend_from_slice(&body);
        let start = wire.len();
        wire.resize(start + padding, 0);
        random(&mut wire[start..])?;
        self.counter = self.counter.wrapping_add(1);
        Ok(wire.into())
    }
    fn decode_length(&mut self, wire: &mut [u8]) -> io::Result<(usize, usize)> {
        let padding = self.padding();
        let length = if let Some(key) = self.length.as_deref() {
            let plain = open(key, self.nonce(&self.length_iv), &[], wire)?;
            usize::from(u16::from_be_bytes(plain.try_into().map_err(|_| error())?)) + 16
        } else {
            let mut length = u16::from_be_bytes(wire.try_into().map_err(|_| error())?);
            if self.options.cipher != BodyCipher::None {
                length ^= self.next_mask();
            }
            usize::from(length)
        };
        if length < padding + self.overhead() || length > MAX_BODY_WIRE {
            return Err(error());
        }
        Ok((length, padding))
    }
    fn decode_body(&mut self, mut wire: BytesMut, padding: usize) -> io::Result<Bytes> {
        wire.truncate(wire.len().checked_sub(padding).ok_or_else(error)?);
        if self.overhead() != 0 {
            let length = open(&self.body, self.nonce(&self.iv), &[], &mut wire)?.len();
            wire.truncate(length);
        }
        self.counter = self.counter.wrapping_add(1);
        Ok(wire.freeze())
    }
}

enum ReadStage {
    ResponseLength,
    Response(usize),
    Length,
    Body { length: usize, padding: usize },
    Eof,
}

/// Bounded, cancellation-safe framed IO after the caller has written and
/// flushed `handshake.request()` (including WS early data) within setup's
/// deadline. Response authentication is lazy and does not expire active business
/// IO while a peer legitimately waits for upload before its first response.
pub struct VmessStream {
    io: Option<BoxStream>,
    handshake: Option<ClientHandshake>,
    read: BodyCodec,
    write: BodyCodec,
    stage: ReadStage,
    input: BytesMut,
    plain: Bytes,
    output: Bytes,
    shutdown: bool,
    whole_close: bool,
    closed: bool,
    reader: futures_util::task::AtomicWaker,
}

impl VmessStream {
    pub fn new(io: BoxStream, handshake: ClientHandshake) -> Self {
        Self {
            io: Some(io),
            read: BodyCodec::new(
                handshake.options,
                handshake.command,
                &handshake.response_key,
                handshake.response_iv,
                &handshake.key,
                handshake.iv,
            ),
            write: BodyCodec::new(
                handshake.options,
                handshake.command,
                &handshake.key,
                handshake.iv,
                &handshake.key,
                handshake.iv,
            ),
            handshake: Some(handshake),
            stage: ReadStage::ResponseLength,
            input: BytesMut::new(),
            plain: Bytes::new(),
            output: Bytes::new(),
            shutdown: false,
            whole_close: false,
            closed: false,
            reader: futures_util::task::AtomicWaker::new(),
        }
    }
    /// Mihomo falls back to whole-connection Close for gRPC, HTTP camouflage
    /// and legacy H2. TCP/ordinary WS keep the underlying CloseWrite behavior.
    pub fn with_whole_close(mut self) -> Self {
        self.whole_close = true;
        self
    }
    fn check(&self) -> io::Result<()> {
        if self.io.is_none() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    fn fail<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.io.take();
        }
        result
    }
    fn fill(
        &mut self,
        cx: &mut Context<'_>,
        length: usize,
        eof_allowed: bool,
    ) -> Poll<io::Result<bool>> {
        while self.input.len() < length {
            let mut storage = [0; 2048];
            let amount = (length - self.input.len()).min(storage.len());
            let mut buf = ReadBuf::new(&mut storage[..amount]);
            ready!(
                Pin::new(self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?)
                    .poll_read(cx, &mut buf)
            )?;
            if buf.filled().is_empty() {
                return Poll::Ready(if eof_allowed && self.input.is_empty() {
                    Ok(false)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                });
            }
            self.input.extend_from_slice(buf.filled());
        }
        Poll::Ready(Ok(true))
    }
    fn poll_packet_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        self.reader.register(cx.waker());
        if self.closed {
            return Poll::Ready(Ok(None));
        }
        self.check()?;
        loop {
            match self.stage {
                ReadStage::ResponseLength => {
                    ready!(self.fill(cx, 18, false))?;
                    let length = self
                        .handshake
                        .as_ref()
                        .unwrap()
                        .response_length(self.input[..].try_into().unwrap())?;
                    self.input.clear();
                    self.stage = ReadStage::Response(length);
                }
                ReadStage::Response(length) => {
                    ready!(self.fill(cx, length, false))?;
                    self.handshake
                        .as_ref()
                        .unwrap()
                        .authenticate_response(&mut self.input)?;
                    self.handshake.take();
                    self.input.clear();
                    self.stage = ReadStage::Length;
                }
                ReadStage::Length if !self.read.framed => {
                    let mut data = [0; WRITE_CHUNK];
                    let mut buf = ReadBuf::new(&mut data);
                    ready!(Pin::new(self.io.as_mut().unwrap()).poll_read(cx, &mut buf))?;
                    if buf.filled().is_empty() {
                        self.stage = ReadStage::Eof;
                        return Poll::Ready(Ok(None));
                    }
                    return Poll::Ready(Ok(Some(Bytes::copy_from_slice(buf.filled()))));
                }
                ReadStage::Length => {
                    let length = self.read.length_size();
                    // Native peers may close at a frame boundary without an EOF
                    // frame; partial lengths/bodies still fail as truncation.
                    if !ready!(self.fill(cx, length, true))? {
                        self.stage = ReadStage::Eof;
                        return Poll::Ready(Ok(None));
                    }
                    let (length, padding) = self.read.decode_length(&mut self.input)?;
                    self.input.clear();
                    self.stage = ReadStage::Body { length, padding };
                }
                ReadStage::Body { length, padding } => {
                    ready!(self.fill(cx, length, false))?;
                    let data = self.read.decode_body(self.input.split(), padding)?;
                    self.stage = if data.is_empty() {
                        ReadStage::Eof
                    } else {
                        ReadStage::Length
                    };
                    return Poll::Ready(Ok(if data.is_empty() { None } else { Some(data) }));
                }
                ReadStage::Eof => return Poll::Ready(Ok(None)),
            }
        }
    }
    pub async fn receive_packet(&mut self) -> io::Result<Bytes> {
        std::future::poll_fn(|cx| self.poll_packet(cx))
            .await?
            .ok_or(io::ErrorKind::UnexpectedEof.into())
    }
    pub(super) fn poll_packet(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        let result = ready!(self.poll_packet_inner(cx));
        Poll::Ready(self.fail(result))
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check()?;
        while !self.output.is_empty() {
            let n = ready!(Pin::new(self.io.as_mut().unwrap()).poll_write(cx, &self.output))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.output.advance(n);
        }
        // advance() keeps the allocation owner even when no bytes remain.
        self.output = Bytes::new();
        Poll::Ready(Ok(()))
    }
    pub async fn send_packet(&mut self, payload: &[u8]) -> io::Result<()> {
        if self.shutdown {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if payload.is_empty() || payload.len() > self.write.write_limit {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        use tokio::io::AsyncWriteExt;
        // A datagram owner poisons its association when this future is cancelled.
        self.flush().await?;
        self.output = self.write.encode(payload)?;
        self.flush().await
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.plain.is_empty() {
            self.plain = match ready!(self.poll_packet(cx))? {
                Some(data) => data,
                None => return Poll::Ready(Ok(())),
            };
        }
        let length = self.plain.len().min(buf.remaining());
        buf.put_slice(&self.plain.split_to(length));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = ready!(self.drain(cx));
        self.fail(result)?;
        if self.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = data.len().min(WRITE_CHUNK);
        let encoded = self.write.encode(&data[..length]);
        self.output = self.fail(encoded)?;
        Poll::Ready(Ok(length))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = ready!(self.drain(cx));
        self.fail(result)?;
        let result = ready!(Pin::new(self.io.as_mut().unwrap()).poll_flush(cx));
        Poll::Ready(self.fail(result))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if self.whole_close {
            ready!(self.as_mut().poll_flush(cx))?;
            self.shutdown = true;
            self.closed = true;
            self.io.take();
            self.handshake.take();
            self.plain = Bytes::new();
            self.input.clear();
            self.reader.wake();
            return Poll::Ready(Ok(()));
        }
        let result = ready!(self.drain(cx));
        self.fail(result)?;
        if !self.shutdown {
            self.shutdown = true;
            let encoded = self.write.encode(&[]);
            self.output = self.fail(encoded)?;
        }
        ready!(self.as_mut().poll_flush(cx))?;
        let result = ready!(Pin::new(self.io.as_mut().unwrap()).poll_shutdown(cx));
        Poll::Ready(self.fail(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(cipher: BodyCipher, padding: bool, length: bool) -> BodyCodec {
        BodyCodec::new(
            BodyOptions::new(cipher, padding, length).unwrap(),
            Command::Tcp,
            &[7; 16],
            [9; 16],
            &[7; 16],
            [9; 16],
        )
    }

    #[tokio::test]
    async fn encrypted_packetaddr_preserves_targets_and_reply_sources_on_one_wire() {
        use super::super::{VmessDatagram, VmessIdentity};
        use crate::{
            dispatch::{DatagramBudget, DatagramTransport},
            dns::resolution::ResolutionContext,
            outbound::address::{decode_packet_addr, encode_packet_addr},
            session::{Datagram, Destination},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut capabilities = Vec::new();
        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            let targets = [
                Destination::Ip("192.0.2.1:53".parse().unwrap()),
                Destination::Ip("[2001:db8::2]:443".parse().unwrap()),
            ];
            let handshake = ClientHandshake::new(
                &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
                Command::Udp,
                &Destination::domain("sp.packet-addr.v2fly.arpa", 443).unwrap(),
                BodyOptions::new(cipher, false, false).unwrap(),
            )
            .unwrap();
            let (raw, mut peer) = tokio::io::duplex(4096);
            let mut stream = VmessStream::new(Box::new(raw), handshake);
            // Existing post-response-authentication seam; actual frame parsing,
            // AEAD, packetaddr encoding and per-packet source delivery remain.
            stream.read = codec(cipher, false, false);
            stream.write = codec(cipher, false, false);
            stream.stage = ReadStage::Length;
            stream.handshake = None;
            let mut transport = VmessDatagram::packet_addr(
                stream,
                DatagramBudget::new(128, 128),
                ResolutionContext::default(),
            );
            let shareable = transport.supports_shared_destinations();
            let mut decoder = codec(cipher, false, false);
            let mut received = Vec::new();
            for (index, target) in targets.iter().enumerate() {
                transport
                    .send(Datagram {
                        remote: target.clone(),
                        payload: Bytes::from(vec![b'a' + u8::try_from(index).unwrap(); 3]),
                        sniffed_domain: None,
                    })
                    .await
                    .unwrap();
                let mut header = [0; 2];
                peer.read_exact(&mut header).await.unwrap();
                let (length, padding) = decoder.decode_length(&mut header).unwrap();
                let mut wire = BytesMut::new();
                wire.resize(length, 0);
                peer.read_exact(&mut wire).await.unwrap();
                let plain = decoder.decode_body(wire, padding).unwrap();
                let (target, offset) = decode_packet_addr(&plain).unwrap();
                received.push((target, plain.slice(offset..)));
            }
            let mut encoder = codec(cipher, false, false);
            for (index, target) in targets.iter().enumerate().rev() {
                let mut plain = BytesMut::new();
                encode_packet_addr(target, &mut plain).unwrap();
                plain.extend_from_slice(if index == 0 { b"first" } else { b"second" });
                peer.write_all(&encoder.encode(&plain).unwrap())
                    .await
                    .unwrap();
            }
            let replies = [
                transport.receive().await.unwrap(),
                transport.receive().await.unwrap(),
            ];
            transport.close().await.unwrap();
            let closed = peer.read(&mut [0; 1]).await.unwrap();
            assert_eq!(received[0].0, targets[0]);
            assert_eq!(received[0].1.as_ref(), b"aaa");
            assert_eq!(received[1].0, targets[1]);
            assert_eq!(received[1].1.as_ref(), b"bbb");
            assert_eq!(replies[0].remote, targets[1]);
            assert_eq!(replies[0].payload.as_ref(), b"second");
            assert_eq!(replies[1].remote, targets[0]);
            assert_eq!(replies[1].payload.as_ref(), b"first");
            assert_eq!(closed, 0);
            assert!(!transport.supports_shared_destinations());
            capabilities.push((cipher, shareable));
        }
        assert!(
            capabilities.iter().all(|(_, shareable)| *shareable),
            "encrypted packetaddr must expose its multi-target wire: {capabilities:?}",
        );
    }

    #[tokio::test]
    async fn drained_output_releases_owner_only_after_all_partial_writes_complete() {
        use super::super::VmessIdentity;
        use crate::session::Destination;
        use std::{
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            time::Duration,
        };
        use tokio::io::AsyncReadExt;

        struct WireOwner {
            wire: Box<[u8]>,
            dropped: Arc<AtomicUsize>,
        }
        impl AsRef<[u8]> for WireOwner {
            fn as_ref(&self) -> &[u8] {
                &self.wire
            }
        }
        impl Drop for WireOwner {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (raw, mut peer) = tokio::io::duplex(3);
        let handshake = ClientHandshake::new(
            &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
            Command::Udp,
            &Destination::Ip("192.0.2.1:53".parse().unwrap()),
            BodyOptions::new(BodyCipher::Aes128Gcm, false, false).unwrap(),
        )
        .unwrap();
        let mut stream = VmessStream::new(Box::new(raw), handshake);
        let expected = stream.write.encode(b"owned framed datagram").unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        // The stream holds the only reference to this real allocation owner.
        // expected is a separate allocation and cannot hide premature release.
        stream.output = Bytes::from_owner(WireOwner {
            wire: expected.to_vec().into_boxed_slice(),
            dropped: dropped.clone(),
        });
        let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(stream.drain(&mut context).is_pending());
        assert_eq!(stream.output.len(), expected.len() - 3);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            0,
            "a partial write must retain its unsubmitted bytes"
        );

        let mut received = vec![0; expected.len()];
        let (drained, read) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                std::future::poll_fn(|context| stream.drain(context)),
                peer.read_exact(&mut received),
            )
        })
        .await
        .unwrap();
        drained.unwrap();
        read.unwrap();
        assert_eq!(received.as_slice(), expected.as_ref());
        assert!(stream.output.is_empty());
        // This fails on the old drain: len is zero, but Bytes still owns WireOwner.
        // Keep the stream alive so destruction cannot make the assertion pass.
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "a completely drained frame must release its last output owner"
        );
        assert!(matches!(stream.drain(&mut context), Poll::Ready(Ok(()))));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(stream);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn chunks_preserve_boundaries_masks_padding_and_authenticated_eof() {
        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            for padding in [false, true] {
                for length in [false, true] {
                    let mut tx = codec(cipher, padding, length);
                    let mut rx = codec(cipher, padding, length);
                    for size in (1..256).chain([WRITE_CHUNK, 0]) {
                        let data = vec![0x5a; size];
                        let mut wire = BytesMut::from(tx.encode(&data).unwrap().as_ref());
                        let mut header = wire.split_to(rx.length_size());
                        let (size, padding) = rx.decode_length(&mut header).unwrap();
                        assert_eq!(wire.len(), size);
                        assert_eq!(rx.decode_body(wire, padding).unwrap(), data);
                    }
                }
            }
        }
    }

    #[test]
    fn tags_and_lengths_fail_closed() {
        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            let mut tx = codec(cipher, false, true);
            let wire = tx.encode(b"synthetic-payload").unwrap();
            for index in [0, 17, 18, wire.len() - 1] {
                let mut rx = codec(cipher, false, true);
                let mut tampered = BytesMut::from(wire.as_ref());
                tampered[index] ^= 1;
                let mut header = tampered.split_to(18);
                if index < 18 {
                    assert!(rx.decode_length(&mut header).is_err());
                } else {
                    let (_, padding) = rx.decode_length(&mut header).unwrap();
                    assert!(rx.decode_body(tampered, padding).is_err());
                }
            }
            let mut rx = codec(cipher, false, false);
            let mask = rx.next_mask();
            let mut rx = codec(cipher, false, false);
            assert!(rx.decode_length(&mut (mask ^ 65535).to_be_bytes()).is_err());
            assert!(
                codec(cipher, true, true)
                    .encode(&vec![0; WRITE_CHUNK + 1])
                    .is_err()
            );
        }
    }

    #[test]
    fn encrypted_records_continue_across_the_official_counter_wrap() {
        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            for padding in [false, true] {
                for authenticated_length in [false, true] {
                    let mut tx = codec(cipher, padding, authenticated_length);
                    let mut rx = codec(cipher, padding, authenticated_length);
                    for record in 0..65538u32 {
                        let payload = record.to_be_bytes();
                        let mut wire = BytesMut::from(tx.encode(&payload).unwrap().as_ref());
                        let mut header = wire.split_to(rx.length_size());
                        let (length, pad) = rx.decode_length(&mut header).unwrap();
                        assert_eq!(wire.len(), length);
                        assert_eq!(rx.decode_body(wire, pad).unwrap().as_ref(), payload);
                    }
                    assert_eq!(u32::from(tx.counter), 2);
                    assert_eq!(u32::from(rx.counter), 2);
                    let mut eof = BytesMut::from(tx.encode(&[]).unwrap().as_ref());
                    let mut header = eof.split_to(rx.length_size());
                    let (_, pad) = rx.decode_length(&mut header).unwrap();
                    assert!(rx.decode_body(eof, pad).unwrap().is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn stream_receives_the_wrapped_peer_record_and_closes_normally() {
        use super::super::VmessIdentity;
        use crate::session::Destination;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            for padding in [false, true] {
                for authenticated_length in [false, true] {
                    let handshake = ClientHandshake::new(
                        &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
                        Command::Tcp,
                        &Destination::Ip("192.0.2.1:443".parse().unwrap()),
                        BodyOptions::new(cipher, padding, authenticated_length).unwrap(),
                    )
                    .unwrap();
                    let (raw, mut peer) = tokio::io::duplex(4096);
                    let mut stream = VmessStream::new(Box::new(raw), handshake).with_whole_close();
                    // Post-response-authentication seam, with the production
                    // parser/AEAD and the final pre-wrap record still intact.
                    stream.read = codec(cipher, padding, authenticated_length);
                    stream.read.counter = u16::MAX.into();
                    stream.stage = ReadStage::Length;
                    stream.handshake = None;
                    let mut encoder = codec(cipher, padding, authenticated_length);
                    encoder.counter = u16::MAX.into();
                    peer.write_all(&encoder.encode(b"before wrap").unwrap())
                        .await
                        .unwrap();
                    let mut before = [0; 11];
                    stream.read_exact(&mut before).await.unwrap();
                    assert_eq!(&before, b"before wrap");

                    // Model the official peer's uint16 counter explicitly,
                    // independently of the receiver's boundary handling.
                    encoder.counter = 0;
                    peer.write_all(&encoder.encode(b"after wrap").unwrap())
                        .await
                        .unwrap();
                    let mut after = [0; 10];
                    stream.read_exact(&mut after).await.unwrap();
                    assert_eq!(&after, b"after wrap");
                    assert_eq!(u32::from(stream.read.counter), 1);
                    peer.write_all(&encoder.encode(&[]).unwrap()).await.unwrap();
                    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
                    stream.shutdown().await.unwrap();
                    assert!(stream.io.is_none());
                    assert_eq!(
                        tokio::time::timeout(
                            std::time::Duration::from_secs(1),
                            peer.read(&mut [0; 1]),
                        )
                        .await
                        .unwrap()
                        .unwrap(),
                        0
                    );
                }
            }
        }
    }

    #[derive(Default)]
    struct ReceiveWake(std::sync::atomic::AtomicUsize);

    impl futures_util::task::ArcWake for ReceiveWake {
        fn wake_by_ref(owner: &std::sync::Arc<Self>) {
            owner.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[derive(Default)]
    struct ByteGate {
        permit: std::sync::atomic::AtomicBool,
        reader: std::sync::Mutex<Option<std::task::Waker>>,
    }

    struct OneByteStream {
        bytes: Bytes,
        gate: std::sync::Arc<ByteGate>,
    }

    impl AsyncRead for OneByteStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            destination: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.bytes.is_empty() || destination.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            *self.gate.reader.lock().unwrap() = Some(context.waker().clone());
            if !self
                .gate
                .permit
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Poll::Pending;
            }
            destination.put_slice(&self.bytes.split_to(1));
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for OneByteStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn vmess_datagram_polled_receive_keeps_frames_across_byte_gates_and_waker_changes() {
        use crate::{
            dispatch::{DatagramBudget, DatagramTransport},
            dns::resolution::ResolutionContext,
            outbound::{
                address::encode_packet_addr,
                vmess::{VmessDatagram, VmessIdentity},
            },
            session::Destination,
        };
        use std::sync::{Arc, atomic::Ordering};

        for cipher in [BodyCipher::Aes128Gcm, BodyCipher::Chacha20Poly1305] {
            for padding in [false, true] {
                for authenticated_length in [false, true] {
                    for packetaddr in [false, true] {
                        let targets = [
                            Destination::Ip("192.0.2.1:53".parse().unwrap()),
                            Destination::Ip(if packetaddr {
                                "[2001:db8::2]:443".parse().unwrap()
                            } else {
                                "192.0.2.1:53".parse().unwrap()
                            }),
                        ];
                        let mut encoder = codec(cipher, padding, authenticated_length);
                        let mut wire = Vec::new();
                        // A discarded oversize packet must consume its complete
                        // record once, then deliver two distinct authenticated
                        // records with their original addresses and payloads.
                        for (target, payload) in [
                            (&targets[0], &[0x5a; 32][..]),
                            (&targets[0], b"one".as_slice()),
                            (&targets[1], b"two".as_slice()),
                        ] {
                            let mut packet = BytesMut::new();
                            if packetaddr {
                                encode_packet_addr(target, &mut packet).unwrap();
                            }
                            packet.extend_from_slice(payload);
                            wire.extend_from_slice(&encoder.encode(&packet).unwrap());
                        }
                        wire.extend_from_slice(&encoder.encode(&[]).unwrap());
                        let poll_bound = wire.len() + 1;
                        let gate = Arc::new(ByteGate::default());
                        let handshake = ClientHandshake::new(
                            &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
                            Command::Udp,
                            &targets[0],
                            BodyOptions::new(cipher, padding, authenticated_length).unwrap(),
                        )
                        .unwrap();
                        let mut stream = VmessStream::new(
                            Box::new(OneByteStream {
                                bytes: wire.into(),
                                gate: gate.clone(),
                            }),
                            handshake,
                        );
                        // This seam begins after response authentication. The
                        // existing official-response tests cover that header;
                        // no replacement body parser or cipher is used here.
                        stream.read = codec(cipher, padding, authenticated_length);
                        stream.stage = ReadStage::Length;
                        stream.handshake = None;
                        let budget = DatagramBudget::new(128, 8);
                        let mut transport = if packetaddr {
                            VmessDatagram::packet_addr(stream, budget, ResolutionContext::default())
                        } else {
                            VmessDatagram::raw(stream, targets[0].clone(), budget)
                        };
                        assert!(transport.supports_poll_receive());
                        let owners = [
                            Arc::new(ReceiveWake::default()),
                            Arc::new(ReceiveWake::default()),
                        ];
                        let wakes = owners
                            .each_ref()
                            .map(|owner| futures_util::task::waker(owner.clone()));
                        let mut scratch = Vec::new();
                        let mut step = 0;
                        for expected in 0..3 {
                            let result = loop {
                                assert!(step < poll_bound, "byte-gated receive made no progress");
                                let old = step % 2;
                                let fresh = 1 - old;
                                assert!(
                                    transport
                                        .poll_receive(
                                            &mut Context::from_waker(&wakes[old]),
                                            &mut scratch,
                                        )
                                        .is_pending()
                                );
                                assert!(
                                    transport
                                        .poll_receive(
                                            &mut Context::from_waker(&wakes[fresh]),
                                            &mut scratch,
                                        )
                                        .is_pending()
                                );
                                let count = owners[fresh].0.load(Ordering::Relaxed);
                                gate.permit.store(true, Ordering::Release);
                                gate.reader.lock().unwrap().take().unwrap().wake();
                                assert_eq!(owners[fresh].0.load(Ordering::Relaxed), count + 1);
                                step += 1;
                                match transport.poll_receive(
                                    &mut Context::from_waker(&wakes[fresh]),
                                    &mut scratch,
                                ) {
                                    Poll::Pending => {}
                                    Poll::Ready(result) => break result,
                                }
                            };
                            if expected < 2 {
                                let packet = result.unwrap();
                                assert_eq!(packet.remote, targets[expected]);
                                assert_eq!(
                                    &packet.payload[..],
                                    if expected == 0 { b"one" } else { b"two" }
                                );
                            } else {
                                assert!(result.is_err(), "UDP EOF must not remain Pending");
                            }
                        }
                        assert!(matches!(
                            transport
                                .poll_receive(&mut Context::from_waker(&wakes[0]), &mut scratch,),
                            Poll::Ready(Err(_))
                        ));
                    }
                }
            }
        }
    }
}
