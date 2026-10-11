//! Bounded TCP framing for the public Mieru v3 protocol.
//! https://github.com/enfein/mieru/blob/v3.38.1/docs/protocol.md
//! Session state, SOCKS business bytes, carrier I/O ownership and padding policy live above it.
use super::crypto::{ImplicitCipher, Key, NONCE_LEN, TAG_LEN};
use bytes::Bytes;
use std::{fmt, io, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const METADATA_LEN: usize = 32;
pub(crate) const MAX_CONTROL_PAYLOAD: usize = 1024;
pub(crate) const MAX_DATA_PAYLOAD: usize = 32_768;
const ENCRYPTED_METADATA_LEN: usize = METADATA_LEN + TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionKind {
    OpenRequest,
    OpenResponse,
    CloseRequest,
    CloseResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataKind {
    ClientData,
    ServerData,
    ClientAck,
    ServerAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionMetadata {
    pub(crate) kind: SessionKind,
    pub(crate) session_id: u32,
    pub(crate) sequence: u32,
    pub(crate) status: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataMetadata {
    pub(crate) kind: DataKind,
    pub(crate) session_id: u32,
    pub(crate) sequence: u32,
    pub(crate) unack_sequence: u32,
    pub(crate) window: u16,
    pub(crate) fragment: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Metadata {
    Session(SessionMetadata),
    Data(DataMetadata),
}

pub(crate) struct Frame {
    pub(crate) metadata: Metadata,
    pub(crate) payload: Bytes,
}

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MieruFrame")
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Padding<'a> {
    pub(crate) prefix: &'a [u8],
    pub(crate) suffix: &'a [u8],
}

struct Header {
    metadata: Metadata,
    payload_len: usize,
    prefix_len: usize,
    suffix_len: usize,
}

fn invalid_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Mieru frame")
}

fn encode_metadata(
    metadata: Metadata,
    payload_len: usize,
    padding: Padding<'_>,
    unix_secs: u64,
) -> io::Result<[u8; METADATA_LEN]> {
    let prefix_len = u8::try_from(padding.prefix.len()).map_err(|_| invalid_frame())?;
    let suffix_len = u8::try_from(padding.suffix.len()).map_err(|_| invalid_frame())?;
    let mut header = [0; METADATA_LEN];
    header[2..6].copy_from_slice(&((unix_secs / 60) as u32).to_be_bytes());
    match metadata {
        Metadata::Session(session) => {
            if payload_len > MAX_CONTROL_PAYLOAD || prefix_len != 0 {
                return Err(invalid_frame());
            }
            header[0] = match session.kind {
                SessionKind::OpenRequest => 2,
                SessionKind::OpenResponse => 3,
                SessionKind::CloseRequest => 4,
                SessionKind::CloseResponse => 5,
            };
            header[6..10].copy_from_slice(&session.session_id.to_be_bytes());
            header[10..14].copy_from_slice(&session.sequence.to_be_bytes());
            header[14] = session.status;
            header[15..17].copy_from_slice(&(payload_len as u16).to_be_bytes());
            header[17] = suffix_len;
        }
        Metadata::Data(data) => {
            if payload_len > MAX_DATA_PAYLOAD {
                return Err(invalid_frame());
            }
            header[0] = match data.kind {
                DataKind::ClientData => 6,
                DataKind::ServerData => 7,
                DataKind::ClientAck => 8,
                DataKind::ServerAck => 9,
            };
            header[6..10].copy_from_slice(&data.session_id.to_be_bytes());
            header[10..14].copy_from_slice(&data.sequence.to_be_bytes());
            header[14..18].copy_from_slice(&data.unack_sequence.to_be_bytes());
            header[18..20].copy_from_slice(&data.window.to_be_bytes());
            header[20] = data.fragment;
            header[21] = prefix_len;
            header[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
            header[24] = suffix_len;
        }
    }
    Ok(header)
}

fn decode_metadata(header: [u8; METADATA_LEN], unix_secs: u64) -> io::Result<Header> {
    let u32_at = |offset: usize| {
        u32::from_be_bytes(header[offset..offset + 4].try_into().expect("fixed header"))
    };
    let u16_at = |offset: usize| u16::from_be_bytes([header[offset], header[offset + 1]]);
    if u32_at(2).abs_diff((unix_secs / 60) as u32) > 1 {
        return Err(invalid_frame());
    }
    let kind = match header[0] {
        2 => Some(SessionKind::OpenRequest),
        3 => Some(SessionKind::OpenResponse),
        4 => Some(SessionKind::CloseRequest),
        5 => Some(SessionKind::CloseResponse),
        _ => None,
    };
    if let Some(kind) = kind {
        let payload_len = usize::from(u16_at(15));
        if payload_len > MAX_CONTROL_PAYLOAD {
            return Err(invalid_frame());
        }
        return Ok(Header {
            metadata: Metadata::Session(SessionMetadata {
                kind,
                session_id: u32_at(6),
                sequence: u32_at(10),
                status: header[14],
            }),
            payload_len,
            prefix_len: 0,
            suffix_len: usize::from(header[17]),
        });
    }
    let kind = match header[0] {
        6 => DataKind::ClientData,
        7 => DataKind::ServerData,
        8 => DataKind::ClientAck,
        9 => DataKind::ServerAck,
        _ => return Err(invalid_frame()),
    };
    // Received ordinary data uses the full wire u16 bound. The 32 KiB fragment limit
    // constrains our sender; it must not become an additional peer parser restriction.
    Ok(Header {
        metadata: Metadata::Data(DataMetadata {
            kind,
            session_id: u32_at(6),
            sequence: u32_at(10),
            unack_sequence: u32_at(14),
            window: u16_at(18),
            fragment: header[20],
        }),
        payload_len: usize::from(u16_at(22)),
        prefix_len: usize::from(header[21]),
        suffix_len: usize::from(header[24]),
    })
}

/// Serial encoder for one physical TCP write direction. The owner must finish writing an
/// encoded frame even if the logical business operation is subsequently cancelled.
pub(crate) struct StreamEncoder {
    cipher: ImplicitCipher,
    initial_nonce: [u8; NONCE_LEN],
    first: bool,
    unusable: bool,
}

impl StreamEncoder {
    pub(crate) fn new(key: Arc<Key>, initial_nonce: [u8; NONCE_LEN]) -> Self {
        Self {
            cipher: ImplicitCipher::new(key, initial_nonce),
            initial_nonce,
            first: true,
            unusable: false,
        }
    }

    /// Replace `out` with exactly one frame. Invalid local shapes do not consume a nonce;
    /// cryptographic failure retires this encoder and its physical connection.
    pub(crate) fn encode_frame(
        &mut self,
        metadata: Metadata,
        payload: &[u8],
        padding: Padding<'_>,
        unix_secs: u64,
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        if self.unusable {
            return Err(io::Error::other("Mieru encoder retired"));
        }
        let header = encode_metadata(metadata, payload.len(), padding, unix_secs)?;
        let nonce_len = if self.first { NONCE_LEN } else { 0 };
        let payload_tag_len = if payload.is_empty() { 0 } else { TAG_LEN };
        let payload_start = nonce_len + ENCRYPTED_METADATA_LEN + padding.prefix.len();
        let suffix_start = payload_start + payload.len() + payload_tag_len;
        let frame_len = suffix_start + padding.suffix.len();
        out.clear();
        out.resize(frame_len, 0);
        if self.first {
            out[..NONCE_LEN].copy_from_slice(&self.initial_nonce);
        }
        out[nonce_len..nonce_len + METADATA_LEN].copy_from_slice(&header);
        out[nonce_len + ENCRYPTED_METADATA_LEN..payload_start].copy_from_slice(padding.prefix);
        out[payload_start..payload_start + payload.len()].copy_from_slice(payload);
        out[suffix_start..].copy_from_slice(padding.suffix);
        self.unusable = true;
        let tag = self
            .cipher
            .seal(&mut out[nonce_len..nonce_len + METADATA_LEN])?;
        out[nonce_len + METADATA_LEN..nonce_len + ENCRYPTED_METADATA_LEN].copy_from_slice(&tag);
        if !payload.is_empty() {
            let tag = self
                .cipher
                .seal(&mut out[payload_start..payload_start + payload.len()])?;
            out[payload_start + payload.len()..suffix_start].copy_from_slice(&tag);
        }
        self.first = false;
        self.unusable = false;
        Ok(())
    }
}

/// One physical TCP read direction. No tasks or I/O handles are retained here.
/// Dropping a polled read future retires the decoder, so a partial frame cannot be retried.
pub(crate) struct StreamDecoder {
    key: Arc<Key>,
    cipher: Option<ImplicitCipher>,
    unusable: bool,
}

impl StreamDecoder {
    pub(crate) fn new(key: Arc<Key>) -> Self {
        Self {
            key,
            cipher: None,
            unusable: false,
        }
    }

    #[cfg(test)]
    pub(crate) async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        reader: &mut R,
        unix_secs: u64,
    ) -> io::Result<Option<Frame>> {
        self.read_frame_with_clock(reader, || Ok(unix_secs)).await
    }

    /// Read the clock after metadata arrives, so an idle pending read cannot reject a
    /// fresh frame using the time at which its future was first polled.
    pub(crate) async fn read_frame_with_clock<
        R: AsyncRead + Unpin + ?Sized,
        C: FnOnce() -> io::Result<u64>,
    >(
        &mut self,
        reader: &mut R,
        clock: C,
    ) -> io::Result<Option<Frame>> {
        if self.unusable {
            return Err(io::Error::other("Mieru decoder retired"));
        }
        self.unusable = true;
        let result = self.read_frame_inner(reader, clock).await;
        if result.is_ok() {
            self.unusable = false;
        }
        result
    }

    async fn read_frame_inner<R: AsyncRead + Unpin + ?Sized, C: FnOnce() -> io::Result<u64>>(
        &mut self,
        reader: &mut R,
        clock: C,
    ) -> io::Result<Option<Frame>> {
        let first = self.cipher.is_none();
        let nonce_len = if first { NONCE_LEN } else { 0 };
        let header_len = nonce_len + ENCRYPTED_METADATA_LEN;
        let mut encrypted_header = [0; NONCE_LEN + ENCRYPTED_METADATA_LEN];
        if reader.read(&mut encrypted_header[..1]).await? == 0 {
            return Ok(None);
        }
        reader
            .read_exact(&mut encrypted_header[1..header_len])
            .await?;
        if first {
            let nonce = encrypted_header[..NONCE_LEN]
                .try_into()
                .expect("fixed nonce");
            self.cipher = Some(ImplicitCipher::new(self.key.clone(), nonce));
        }
        let cipher = self.cipher.as_mut().expect("initialized direction");
        let tag = encrypted_header[nonce_len + METADATA_LEN..header_len]
            .try_into()
            .expect("fixed tag");
        let header_bytes = &mut encrypted_header[nonce_len..nonce_len + METADATA_LEN];
        cipher.open(header_bytes, tag)?;
        let header = decode_metadata(
            (&*header_bytes).try_into().expect("fixed metadata"),
            clock()?,
        )?;
        let mut padding = [0; u8::MAX as usize];
        reader.read_exact(&mut padding[..header.prefix_len]).await?;
        let payload = if header.payload_len == 0 {
            Bytes::new()
        } else {
            // Authenticated u16 length, allocated once only when a payload exists. The
            // 16-byte tag shares that allocation; prefix/suffix need no heap storage.
            let mut payload = vec![0; header.payload_len + TAG_LEN];
            reader.read_exact(&mut payload).await?;
            let tag = payload[header.payload_len..]
                .try_into()
                .expect("fixed payload tag");
            cipher.open(&mut payload[..header.payload_len], tag)?;
            payload.truncate(header.payload_len);
            Bytes::from(payload)
        };
        reader.read_exact(&mut padding[..header.suffix_len]).await?;
        Ok(Some(Frame {
            metadata: header.metadata,
            payload,
        }))
    }
}

impl fmt::Debug for StreamEncoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MieruStreamEncoder(..)")
    }
}

impl fmt::Debug for StreamDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MieruStreamDecoder(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{derive_key, make_client_nonce};
    use super::*;
    use std::{
        cell::Cell,
        future::Future,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll, Waker},
    };
    use tokio::io::{AsyncWriteExt, ReadBuf};

    const TIME: u64 = 1_700_000_000;
    // Independently computed from the wire specification and RFC 8439/HChaCha primitives.
    // The temporary Python oracle first verified the published ChaCha block, HChaCha
    // subkey and Poly1305 vectors; it is not a second production implementation.
    const OPEN_HEX: &str = concat!(
        "000102030405060708090a0b0c0d0e0f101112135b65f257",
        "2289a2f66e5cf623a3b69e0fb82a6dfb7d7ae09f5c0ad82e8e5b8c7d42961eb2",
        "ef09b588a8a6c70b7e206a7acf8a6b060",
        "ae568fd11d1c65dd949ecedbfccbbc1a2aaa9e471d3a6517dac",
        "aabb"
    );
    const ACK_HEX: &str = concat!(
        "6f872a970b7082c014e1e455394012129994baab97850b0af96d618860c4bddd",
        "70d580cdbabb0289ea3df4e5402fd904",
        "ccddeeff"
    );

    fn hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0, "fixture contains a partial byte");
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid fixture hex"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    fn key() -> Arc<Key> {
        Arc::new(derive_key("vole", "fixture-password", TIME))
    }

    fn nonce() -> [u8; NONCE_LEN] {
        make_client_nonce("vole", std::array::from_fn(|index| index as u8))
    }

    fn open() -> Metadata {
        Metadata::Session(SessionMetadata {
            kind: SessionKind::OpenRequest,
            session_id: 0x0102_0304,
            sequence: 0,
            status: 0,
        })
    }

    fn ack() -> Metadata {
        Metadata::Data(DataMetadata {
            kind: DataKind::ClientAck,
            session_id: 0x0102_0304,
            sequence: 1,
            unack_sequence: 2,
            window: 16,
            fragment: 0,
        })
    }

    struct Chunks {
        bytes: Bytes,
        read: Rc<Cell<usize>>,
        chunk: usize,
    }

    impl AsyncRead for Chunks {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let offset = this.read.get();
            let length = buffer
                .remaining()
                .min(this.chunk)
                .min(this.bytes.len() - offset);
            buffer.put_slice(&this.bytes[offset..offset + length]);
            this.read.set(offset + length);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn fixed_wire_vectors_and_implicit_nonce_sequence() {
        let payload = hex("050100017f0000010050");
        let mut encoder = StreamEncoder::new(key(), nonce());
        let mut encoded = Vec::new();
        encoder
            .encode_frame(
                open(),
                &payload,
                Padding {
                    prefix: &[],
                    suffix: &[0xaa, 0xbb],
                },
                TIME,
                &mut encoded,
            )
            .unwrap();
        assert_eq!(encoded, hex(OPEN_HEX));
        encoder
            .encode_frame(
                ack(),
                &[],
                Padding {
                    prefix: &[0xcc],
                    suffix: &[0xdd, 0xee, 0xff],
                },
                TIME,
                &mut encoded,
            )
            .unwrap();
        assert_eq!(encoded, hex(ACK_HEX));
        let mut incoming = hex(OPEN_HEX);
        incoming.extend_from_slice(&hex(ACK_HEX));
        let mut reader = Chunks {
            bytes: Bytes::from(incoming),
            read: Rc::new(Cell::new(0)),
            chunk: 1,
        };
        let mut decoder = StreamDecoder::new(key());
        let received = decoder
            .read_frame(&mut reader, TIME)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.metadata, open());
        assert_eq!(received.payload.as_ref(), payload.as_slice());
        let received = decoder
            .read_frame(&mut reader, TIME)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.metadata, ack());
        assert!(received.payload.is_empty());
        assert!(
            decoder
                .read_frame(&mut reader, TIME)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delayed_reply_keeps_physical_key_and_samples_clock_after_header() {
        let creation_time = 1_700_000_039;
        let reply_time = 1_700_000_160;
        let key = Arc::new(derive_key("vole", "fixture-password", creation_time));
        let mut encoder = StreamEncoder::new(key.clone(), [0x5a; NONCE_LEN]);
        let metadata = Metadata::Session(SessionMetadata {
            kind: SessionKind::OpenResponse,
            session_id: 0x0102_0304,
            sequence: 0,
            status: 0,
        });
        let mut encoded = Vec::new();
        encoder
            .encode_frame(
                metadata,
                b"reply",
                Padding::default(),
                reply_time,
                &mut encoded,
            )
            .unwrap();
        let consumed = Rc::new(Cell::new(0));
        let mut reader = Chunks {
            bytes: Bytes::from(encoded.clone()),
            read: consumed.clone(),
            chunk: 3,
        };
        let mut decoder = StreamDecoder::new(key);
        let received = decoder
            .read_frame_with_clock(&mut reader, || {
                assert_eq!(consumed.get(), NONCE_LEN + ENCRYPTED_METADATA_LEN);
                Ok(reply_time)
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.metadata, metadata);
        assert_eq!(received.payload.as_ref(), b"reply");
        // A new physical carrier selects a new key; it cannot decrypt this old carrier reply.
        let mut wrong =
            StreamDecoder::new(Arc::new(derive_key("vole", "fixture-password", reply_time)));
        let error = wrong
            .read_frame(&mut encoded.as_slice(), reply_time)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn cancelling_partial_frame_retires_decoder() {
        let (mut sender, mut reader) = tokio::io::duplex(128);
        sender.write_all(&hex(OPEN_HEX)[..10]).await.unwrap();
        let mut decoder = StreamDecoder::new(key());
        let mut pending = Box::pin(decoder.read_frame(&mut reader, TIME));
        let mut context = Context::from_waker(Waker::noop());
        assert!(pending.as_mut().poll(&mut context).is_pending());
        drop(pending);
        let error = decoder.read_frame(&mut reader, TIME).await.unwrap_err();
        assert_eq!(error.to_string(), "Mieru decoder retired");
    }

    #[tokio::test]
    async fn receiver_accepts_full_u16_payload_and_ignored_reserved_bytes() {
        // Construct a peer frame directly, since our own sender fragments at 32 KiB.
        let mut header = encode_metadata(ack(), 0, Padding::default(), TIME).unwrap();
        header[0] = 7;
        header[1] = 0xfe;
        header[22..24].copy_from_slice(&u16::MAX.to_be_bytes());
        header[25..].fill(0xff);
        let mut payload = vec![0x5a; usize::from(u16::MAX)];
        let mut cipher = ImplicitCipher::new(key(), nonce());
        let tag = cipher.seal(&mut header).unwrap();
        let mut incoming = nonce().to_vec();
        incoming.extend_from_slice(&header);
        incoming.extend_from_slice(&tag);
        let tag = cipher.seal(&mut payload).unwrap();
        incoming.extend_from_slice(&payload);
        incoming.extend_from_slice(&tag);
        let received = StreamDecoder::new(key())
            .read_frame(&mut incoming.as_slice(), TIME)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.payload.len(), usize::from(u16::MAX));
        assert!(received.payload.iter().all(|byte| *byte == 0x5a));
    }
}
