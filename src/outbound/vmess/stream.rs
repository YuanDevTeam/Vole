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
    length: aead::LessSafeKey,
    mask: shake::Shake128Reader,
    counter: u32,
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
        let length_key = kdf(request_key, &[b"auth_len"]);
        Self {
            options,
            iv,
            length_iv: request_iv,
            body: aead_key(options.cipher, key),
            length: aead_key(options.cipher, length_key[..16].try_into().unwrap()),
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
    fn nonce(&self, iv: &[u8; 16]) -> io::Result<[u8; 12]> {
        // The wire counter is only 16 bits. Never reuse a nonce under the same
        // key: an exhausted encrypted session must be re-established by caller.
        let counter = u16::try_from(self.counter)
            .map_err(|_| io::Error::other("VMess nonce sequence exhausted"))?;
        let mut nonce: [u8; 12] = iv[..12].try_into().unwrap();
        nonce[..2].copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
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
            seal(&self.body, self.nonce(&self.iv)?, &[], &mut body)?;
        }
        let mut length = (body.len() + padding) as u16;
        let mut wire = if self.options.authenticated_length {
            let mut encoded = (length - 16).to_be_bytes().to_vec();
            seal(
                &self.length,
                self.nonce(&self.length_iv)?,
                &[],
                &mut encoded,
            )?;
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
        self.counter += 1;
        Ok(wire.into())
    }
    fn decode_length(&mut self, wire: &mut [u8]) -> io::Result<(usize, usize)> {
        let padding = self.padding();
        let length = if self.options.authenticated_length {
            let plain = open(&self.length, self.nonce(&self.length_iv)?, &[], wire)?;
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
            let length = open(&self.body, self.nonce(&self.iv)?, &[], &mut wire)?.len();
            wire.truncate(length);
        }
        self.counter += 1;
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
    pub(super) fn uses_body_nonce(&self) -> bool {
        self.write.options.cipher != BodyCipher::None
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
    fn poll_packet(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
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

    #[test]
    fn chunks_preserve_boundaries_masks_padding_and_authenticated_eof() {
        #[cfg(feature = "interop-test")]
        let _evidence = crate::resources::case_events::Case::new(
            "VMESS-CODEC",
            "chunks_preserve_boundaries_masks_padding_and_authenticated_eof",
        );
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
    fn tags_lengths_and_nonce_exhaustion_fail_closed() {
        #[cfg(feature = "interop-test")]
        let _evidence = crate::resources::case_events::Case::new(
            "VMESS-CODEC",
            "tags_lengths_and_nonce_exhaustion_fail_closed",
        );
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
            let mut tx = codec(cipher, false, false);
            tx.counter = u32::from(u16::MAX);
            assert!(tx.encode(b"last-nonce").is_ok());
            assert!(tx.encode(b"must-not-repeat").is_err());
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
}
