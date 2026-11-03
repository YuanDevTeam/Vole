use super::{
    BodyCipher, BodyOptions,
    crypto::{aead_key, error, kdf, open, random, seal},
};
use crate::{outbound::address::encode_port_first, session::Destination};
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use bytes::BytesMut;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct VmessIdentity([u8; 16]);
impl std::fmt::Debug for VmessIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessIdentity").finish_non_exhaustive()
    }
}
impl VmessIdentity {
    pub fn new(uuid: uuid::Uuid) -> Self {
        let mut digest = Md5::new();
        digest.update(uuid.as_bytes());
        digest.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        Self(digest.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
}

pub struct ClientHandshake {
    request: Vec<u8>,
    pub(super) key: [u8; 16],
    pub(super) iv: [u8; 16],
    pub(super) response_key: [u8; 16],
    pub(super) response_iv: [u8; 16],
    response_tag: u8,
    pub(super) options: BodyOptions,
    pub(super) command: Command,
}
impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake").finish_non_exhaustive()
    }
}

impl ClientHandshake {
    pub fn new(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
    ) -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("VMess clock before epoch"))?
            .as_secs();
        let mut entropy = [0; 61];
        random(&mut entropy)?;
        Self::with_entropy(identity, command, peer, options, timestamp, entropy)
    }

    /// Synthetic-clock hook for owned native-peer rejection tests only.
    #[cfg(feature = "interop-test")]
    pub fn with_test_timestamp(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
        timestamp: u64,
    ) -> io::Result<Self> {
        let mut entropy = [0; 61];
        random(&mut entropy)?;
        Self::with_entropy(identity, command, peer, options, timestamp, entropy)
    }

    fn with_entropy(
        identity: &VmessIdentity,
        command: Command,
        peer: &Destination,
        options: BodyOptions,
        timestamp: u64,
        entropy: [u8; 61],
    ) -> io::Result<Self> {
        if peer.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero VMess destination port",
            ));
        }
        let key: [u8; 16] = entropy[..16].try_into().unwrap();
        let iv: [u8; 16] = entropy[16..32].try_into().unwrap();
        let response_tag = entropy[32];
        let padding_length = entropy[33] as usize & 15;
        let mut plain = BytesMut::with_capacity(320);
        plain.extend_from_slice(&[1]);
        plain.extend_from_slice(&iv);
        plain.extend_from_slice(&key);
        plain.extend_from_slice(&[
            response_tag,
            options.wire(command),
            (padding_length as u8) << 4 | options.cipher.wire(),
            0,
            match command {
                Command::Tcp => 1,
                Command::Udp => 2,
                Command::Mux => 3,
            },
        ]);
        if command != Command::Mux {
            encode_port_first(peer, &mut plain)?;
        }
        plain.extend_from_slice(&entropy[34..34 + padding_length]);
        let checksum = plain.iter().fold(0x811c9dc5u32, |hash, byte| {
            (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
        });
        plain.extend_from_slice(&checksum.to_be_bytes());

        let mut auth_id = [0; 16];
        auth_id[..8].copy_from_slice(&timestamp.to_be_bytes());
        auth_id[8..12].copy_from_slice(&entropy[49..53]);
        let checksum = crc32fast::hash(&auth_id[..12]);
        auth_id[12..].copy_from_slice(&checksum.to_be_bytes());
        let auth_key = kdf(&identity.0, &[b"AES Auth ID Encryption"]);
        let block = aes::Aes128::new_from_slice(&auth_key[..16]).expect("AES key size");
        block.encrypt_block((&mut auth_id).into());
        let nonce = &entropy[53..61];
        let mut length = (plain.len() as u16).to_be_bytes().to_vec();
        let mut payload = plain.to_vec();
        for (data, key_salt, iv_salt) in [
            (
                &mut length,
                b"VMess Header AEAD Key_Length".as_slice(),
                b"VMess Header AEAD Nonce_Length".as_slice(),
            ),
            (
                &mut payload,
                b"VMess Header AEAD Key".as_slice(),
                b"VMess Header AEAD Nonce".as_slice(),
            ),
        ] {
            let key = kdf(&identity.0, &[key_salt, &auth_id, nonce]);
            let iv = kdf(&identity.0, &[iv_salt, &auth_id, nonce]);
            seal(
                &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
                iv[..12].try_into().unwrap(),
                &auth_id,
                data,
            )?;
        }
        let request = [&auth_id[..], &length, nonce, &payload].concat();
        Ok(Self {
            request,
            key,
            iv,
            response_key: Sha256::digest(key)[..16].try_into().unwrap(),
            response_iv: Sha256::digest(iv)[..16].try_into().unwrap(),
            response_tag,
            options,
            command,
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn response_length(&self, wire: &[u8; 18]) -> io::Result<usize> {
        let mut data = *wire;
        let plain = self.open_response(
            b"AEAD Resp Header Len Key",
            b"AEAD Resp Header Len IV",
            &mut data,
        )?;
        let length = usize::from(u16::from_be_bytes(plain.try_into().map_err(|_| error())?));
        if !(4..=259).contains(&length) {
            return Err(error());
        }
        Ok(length + 16)
    }

    pub fn authenticate_response(&self, wire: &mut [u8]) -> io::Result<()> {
        if !(20..=275).contains(&wire.len()) {
            return Err(error());
        }
        let plain = self.open_response(b"AEAD Resp Header Key", b"AEAD Resp Header IV", wire)?;
        if plain[0] != self.response_tag || plain.len() != 4 + usize::from(plain[3]) {
            return Err(error());
        }
        // Authenticated server commands never change the configured cipher,
        // identity, upstream or destination. Legacy account changes are ignored.
        Ok(())
    }

    fn open_response<'a>(
        &self,
        key_salt: &[u8],
        iv_salt: &[u8],
        data: &'a mut [u8],
    ) -> io::Result<&'a mut [u8]> {
        let key = kdf(&self.response_key, &[key_salt]);
        let iv = kdf(&self.response_iv, &[iv_salt]);
        open(
            &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
            iv[..12].try_into().unwrap(),
            &[],
            data,
        )
    }
}

#[cfg(test)]
mod datagram_memory_tests {
    use super::*;
    use crate::{
        dispatch::{DatagramBudget, DatagramTransport},
        dns::resolution::ResolutionContext,
        outbound::{
            address::encode_packet_addr,
            vmess::{VmessDatagram, VmessStream},
        },
        session::Datagram,
    };
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn fixture(capacity: usize, packetaddr: bool) -> (VmessDatagram, DuplexStream, Vec<u8>) {
        fixture_with_cipher(capacity, packetaddr, BodyCipher::None)
    }

    fn fixture_with_cipher(
        capacity: usize,
        packetaddr: bool,
        cipher: BodyCipher,
    ) -> (VmessDatagram, DuplexStream, Vec<u8>) {
        let peer = Destination::Ip("192.0.2.1:53".parse().unwrap());
        let handshake = ClientHandshake::new(
            &VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
            Command::Udp,
            &peer,
            BodyOptions::new(cipher, false, false).unwrap(),
        )
        .unwrap();
        // Body encryption is independent of this genuine authenticated VMess
        // response header; Body None must authenticate the header too.
        let mut response = Vec::new();
        for (mut data, key_salt, iv_salt) in [
            (
                4u16.to_be_bytes().to_vec(),
                b"AEAD Resp Header Len Key".as_slice(),
                b"AEAD Resp Header Len IV".as_slice(),
            ),
            (
                vec![handshake.response_tag, 0, 0, 0],
                b"AEAD Resp Header Key".as_slice(),
                b"AEAD Resp Header IV".as_slice(),
            ),
        ] {
            let key = kdf(&handshake.response_key, &[key_salt]);
            let iv = kdf(&handshake.response_iv, &[iv_salt]);
            seal(
                &aead_key(BodyCipher::Aes128Gcm, key[..16].try_into().unwrap()),
                iv[..12].try_into().unwrap(),
                &[],
                &mut data,
            )
            .unwrap();
            response.extend_from_slice(&data);
        }
        let (io, peer_io) = tokio::io::duplex(capacity);
        let stream = VmessStream::new(Box::new(io), handshake);
        let budget = DatagramBudget::new(128, 128);
        let datagram = if packetaddr {
            VmessDatagram::packet_addr(stream, budget, ResolutionContext::default())
        } else {
            VmessDatagram::raw(stream, peer, budget)
        };
        (datagram, peer_io, response)
    }

    fn packet(remote: Destination, payload: &'static [u8]) -> Datagram {
        Datagram {
            remote,
            payload: Bytes::from_static(payload),
            sniffed_domain: None,
        }
    }

    #[tokio::test]
    async fn vmess_packetaddr_memory_shares_multiple_targets_and_preserves_reply_addresses() {
        let (mut client, mut peer, response) = fixture(1024, true);
        assert!(client.supports_shared_destinations());
        let targets = [
            Destination::Ip("192.0.2.1:53".parse().unwrap()),
            Destination::Ip("[2001:db8::2]:443".parse().unwrap()),
        ];
        peer.write_all(&response).await.unwrap();
        for target in targets {
            let datagram = packet(target.clone(), b"target-specific payload");
            client.send(datagram.clone()).await.unwrap();
            let mut expected = BytesMut::new();
            encode_packet_addr(&target, &mut expected).unwrap();
            expected.extend_from_slice(&datagram.payload);
            let length = peer.read_u16().await.unwrap();
            let mut body = vec![0; usize::from(length)];
            peer.read_exact(&mut body).await.unwrap();
            assert_eq!(body, expected);
            peer.write_u16(length).await.unwrap();
            peer.write_all(&body).await.unwrap();
            let reply = client.receive().await.unwrap();
            assert_eq!(reply.remote, target);
            assert_eq!(reply.payload, datagram.payload);
        }
        client.close().await.unwrap();
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(client.receive().await.is_err());
    }

    #[tokio::test]
    async fn vmess_raw_memory_keeps_fixed_target_without_poisoning_valid_send() {
        let (mut client, mut peer, response) = fixture(1024, false);
        assert!(!client.supports_shared_destinations());
        let target = Destination::Ip("192.0.2.1:53".parse().unwrap());
        assert!(
            client
                .send(packet(
                    Destination::Ip("192.0.2.2:53".parse().unwrap()),
                    b"wrong target"
                ))
                .await
                .is_err()
        );
        client
            .send(packet(target.clone(), b"fixed target"))
            .await
            .unwrap();
        let length = peer.read_u16().await.unwrap();
        let mut body = vec![0; usize::from(length)];
        peer.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"fixed target");
        peer.write_all(&response).await.unwrap();
        peer.write_u16(length).await.unwrap();
        peer.write_all(&body).await.unwrap();
        let reply = client.receive().await.unwrap();
        assert_eq!(reply.remote, target);
        assert_eq!(reply.payload, body);
        client.close().await.unwrap();
    }

    #[tokio::test]
    async fn vmess_datagram_memory_cancelled_partial_send_closes_each_encoding() {
        for cipher in [
            BodyCipher::Auto,
            BodyCipher::None,
            BodyCipher::Aes128Gcm,
            BodyCipher::Chacha20Poly1305,
        ] {
            for packetaddr in [false, true] {
                let (mut client, mut peer, _) = fixture_with_cipher(1, packetaddr, cipher);
                assert_eq!(
                    client.supports_shared_destinations(),
                    packetaddr,
                    "packetaddr={packetaddr}, cipher={cipher:?}",
                );
                {
                    let sending = client.send(packet(
                        Destination::Ip("192.0.2.1:53".parse().unwrap()),
                        b"partial payload",
                    ));
                    tokio::pin!(sending);
                    assert!(futures_util::poll!(sending.as_mut()).is_pending());
                }
                let mut partial = Vec::new();
                peer.read_to_end(&mut partial).await.unwrap();
                assert_eq!(partial.len(), 1);
                assert!(
                    client
                        .send(packet(
                            Destination::Ip("192.0.2.1:53".parse().unwrap()),
                            b"must not replay"
                        ))
                        .await
                        .is_err()
                );
                assert!(client.receive().await.is_err());
                client.close().await.unwrap();
            }
        }
    }
}

#[cfg(test)]
mod delayed_response_memory_tests {
    use super::*;
    use crate::outbound::vmess::VmessStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(serde::Deserialize)]
    struct OfficialVector {
        cipher: String,
        alter_id: u32,
        global_padding: bool,
        authenticated_length: bool,
        request: Vec<u8>,
        request_key: [u8; 16],
        request_iv: [u8; 16],
        response_tag: u8,
        response: Vec<u8>,
        payload: Vec<u8>,
        response_empty_before_first_server_write: bool,
        official_client_response_roundtrip: bool,
    }

    fn fixture() -> (ClientHandshake, OfficialVector) {
        let vector: OfficialVector = serde_json::from_str(include_str!(
            "../../../tests/fixtures/vmess-delayed-response.json"
        ))
        .unwrap();
        assert_eq!(vector.cipher, "aes-128-gcm");
        assert_eq!(vector.alter_id, 0);
        assert!(!vector.global_padding && !vector.authenticated_length);
        assert!(vector.response_empty_before_first_server_write);
        assert!(vector.official_client_response_roundtrip);
        assert!(vector.response.len() > 38 && !vector.payload.is_empty());
        // The actual official client/Service produced and independently decoded
        // these synthetic bytes. Core's normal response authenticator/body
        // codec consumes them; no replacement AsyncRead parser is used.
        let handshake = ClientHandshake {
            request: vector.request.clone(),
            key: vector.request_key,
            iv: vector.request_iv,
            response_key: Sha256::digest(vector.request_key)[..16].try_into().unwrap(),
            response_iv: Sha256::digest(vector.request_iv)[..16].try_into().unwrap(),
            response_tag: vector.response_tag,
            options: BodyOptions::new(BodyCipher::Aes128Gcm, false, false).unwrap(),
            command: Command::Tcp,
        };
        (handshake, vector)
    }

    #[tokio::test(start_paused = true)]
    async fn vmess_committed_request_accepts_official_response_after_setup_deadline() {
        let (handshake, vector) = fixture();
        let (mut raw, mut peer) = tokio::io::duplex(4096);
        // This is the real call-site contract: the complete request prefix was
        // successfully written and flushed before business IO was returned.
        raw.write_all(handshake.request()).await.unwrap();
        raw.flush().await.unwrap();
        let mut request = vec![0; handshake.request().len()];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(request, vector.request);
        let stream = VmessStream::new(Box::new(raw), handshake);
        let (mut reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(b"upload before delayed response")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        let mut reply = vec![0; vector.payload.len()];
        {
            let pending = reader.read_exact(&mut reply);
            tokio::pin!(pending);
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            tokio::time::advance(std::time::Duration::from_secs(11)).await;
            assert!(
                futures_util::poll!(pending.as_mut()).is_pending(),
                "submitted request cannot expire while a one-way upload legitimately has no response header"
            );
            writer
                .write_all(b"upload continues after setup deadline")
                .await
                .unwrap();
            writer.flush().await.unwrap();
            peer.write_all(&vector.response).await.unwrap();
            pending.await.unwrap();
        }
        assert_eq!(reply, vector.payload);
        drop(reader);
        drop(writer);
        let mut remaining_upload = Vec::new();
        peer.read_to_end(&mut remaining_upload).await.unwrap();
        assert!(!remaining_upload.is_empty());
    }

    async fn expect_committed_http_request(peer: &mut tokio::io::DuplexStream, request: &[u8]) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(peer.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(head)
                .unwrap()
                .contains(&format!("content-length: {}\r\n", request.len()))
        );
        let mut prefix = vec![0; request.len()];
        peer.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, request);
    }

    #[tokio::test(start_paused = true)]
    async fn vmess_committed_http_request_accepts_official_response_after_setup_deadline() {
        use crate::transport::{HttpObfsOptions, http_obfs};
        use std::task::Poll;
        use tokio::time::{Duration, Instant};

        let (handshake, vector) = fixture();
        let (raw, mut peer) = tokio::io::duplex(4096);
        let options = HttpObfsOptions::new(
            http::Method::GET,
            "http://fixture.invalid/cover",
            Default::default(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let transport = http_obfs(Box::new(raw), &options, handshake.request(), deadline)
            .await
            .unwrap();

        // Observe the real HTTP header and complete authenticated request before
        // advancing the clock. An unread or partial request is not this case.
        expect_committed_http_request(&mut peer, &vector.request).await;

        let stream = VmessStream::new(transport, handshake).with_whole_close();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let before = b"upload before delayed HTTP response";
        writer.write_all(before).await.unwrap();
        writer.flush().await.unwrap();
        // The fixture is AES-GCM, without padding or authenticated lengths:
        // consume its actual two-byte length and tag-bearing encoded record.
        let mut uploaded = vec![0; before.len() + 2 + 16];
        peer.read_exact(&mut uploaded).await.unwrap();

        let mut reply = vec![0; vector.payload.len()];
        let mut pending = Box::pin(reader.read_exact(&mut reply));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(11)).await;
        let after_deadline = futures_util::poll!(pending.as_mut());
        let remained_pending = after_deadline.is_pending();
        let result = match after_deadline {
            Poll::Ready(result) => result,
            Poll::Pending => {
                let after = b"upload continues after setup deadline";
                writer.write_all(after).await.unwrap();
                writer.flush().await.unwrap();
                uploaded.resize(after.len() + 2 + 16, 0);
                peer.read_exact(&mut uploaded).await.unwrap();
                peer.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n",
                )
                .await
                .unwrap();
                peer.write_all(&vector.response).await.unwrap();
                pending.as_mut().await
            }
        };
        drop(pending);

        // Clean up both outcomes before asserting the regression. Old code
        // must report TimedOut here, rather than hanging the fixture or relying
        // on a task abort to make its peer disappear.
        let closed = writer.shutdown().await;
        drop(reader);
        drop(writer);
        let mut byte = [0; 1];
        let peer_eof = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer_eof, 0);
        assert!(
            remained_pending,
            "committed HTTP request expired before the peer's first response: {:?}",
            result.as_ref().err().map(std::io::Error::kind)
        );
        result.unwrap();
        assert_eq!(reply, vector.payload);
        closed.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn vmess_committed_http_response_wait_is_cancelled_by_node_stop() {
        use crate::{
            outbound::owned_stream::OwnedStream,
            transport::{HttpObfsOptions, http_obfs},
        };
        use std::{
            future::Future,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::{Context, Wake, Waker},
        };
        use tokio::time::{Duration, Instant};
        use tokio_util::sync::CancellationToken;

        #[derive(Default)]
        struct ReaderWake(AtomicUsize);
        impl Wake for ReaderWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (handshake, vector) = fixture();
        let (raw, mut peer) = tokio::io::duplex(4096);
        let node = CancellationToken::new();
        let owned = OwnedStream::new(Box::new(raw), node.clone());
        let options = HttpObfsOptions::new(
            http::Method::GET,
            "http://fixture.invalid/cover",
            Default::default(),
        )
        .unwrap();
        let transport = http_obfs(
            Box::new(owned),
            &options,
            handshake.request(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        expect_committed_http_request(&mut peer, &vector.request).await;
        let mut stream = VmessStream::new(transport, handshake).with_whole_close();
        let mut pending = Box::pin(stream.read_u8());
        let reader_wake = Arc::new(ReaderWake::default());
        let waker = Waker::from(reader_wake.clone());
        let mut context = Context::from_waker(&waker);
        assert!(pending.as_mut().poll(&mut context).is_pending());
        tokio::time::advance(Duration::from_secs(11)).await;
        let waiting = pending.as_mut().poll(&mut context).is_pending();
        reader_wake.0.store(0, Ordering::SeqCst);
        node.cancel();
        let reader_woken = reader_wake.0.load(Ordering::SeqCst) > 0;
        let cancelled = tokio::time::timeout(Duration::from_secs(1), pending.as_mut()).await;
        drop(pending);
        // Verify cancellation released the physical IO while its outer
        // VmessStream remains alive; dropping it must not create this EOF.
        let peer_eof = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0; 1])).await;
        drop(stream);
        assert_eq!(peer_eof.unwrap().unwrap(), 0);
        assert!(
            reader_woken,
            "node Stop did not wake the pending HTTP reader"
        );
        assert!(
            waiting,
            "committed response wait still used the setup deadline"
        );
        assert_eq!(
            cancelled.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn vmess_delayed_official_response_still_authenticates_before_delivery() {
        let (handshake, mut vector) = fixture();
        let (mut raw, mut peer) = tokio::io::duplex(4096);
        raw.write_all(handshake.request()).await.unwrap();
        raw.flush().await.unwrap();
        let mut request = vec![0; handshake.request().len()];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(request, vector.request);
        let mut stream = VmessStream::new(Box::new(raw), handshake);
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        // Alter the actual response header's AEAD tag, preserving all lengths.
        vector.response[17] ^= 1;
        peer.write_all(&vector.response).await.unwrap();
        let mut reply = [0; 128];
        assert_eq!(
            stream.read(&mut reply).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(reply.iter().all(|byte| *byte == 0));
        assert!(
            stream
                .write_all(b"cannot continue after authentication failure")
                .await
                .is_err()
        );
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
}
