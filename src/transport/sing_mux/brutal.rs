//! Mihomo sing-mux's one control exchange, before business admission.
use crate::dispatch::BoxStream;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DOMAIN: &[u8] = b"_BrutalBwExchange";
const MAX_ERROR_BYTES: u64 = 256;

pub(super) async fn exchange(io: &mut BoxStream, up: u64, down: u64) -> io::Result<u64> {
    exchange_inner(io, up, down)
        .await
        .map_err(|error| io::Error::new(error.kind(), "sing-mux Brutal negotiation failed"))
}

async fn exchange_inner(io: &mut BoxStream, up: u64, down: u64) -> io::Result<u64> {
    // This reserved target has port zero; it is protocol control, never a
    // routable business Destination or a request for the local DNS resolver.
    let mut request = [0_u8; 2 + 2 + DOMAIN.len() + 2 + 8];
    request[2] = crate::socks5::ADDRESS_DOMAIN;
    request[3] = DOMAIN.len() as u8;
    request[4..4 + DOMAIN.len()].copy_from_slice(DOMAIN);
    request[6 + DOMAIN.len()..].copy_from_slice(&down.to_be_bytes());
    io.write_all(&request).await?;
    io.flush().await?;
    match io.read_u8().await? {
        0 => {}
        1 => {
            discard_error(io).await?;
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        _ => return Err(io::ErrorKind::InvalidData.into()),
    }
    match io.read_u8().await? {
        1 => Ok(up.min(io.read_u64().await?)),
        0 => {
            discard_error(io).await?;
            Err(io::ErrorKind::ConnectionRefused.into())
        }
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

async fn discard_error(io: &mut BoxStream) -> io::Result<()> {
    let mut length = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = io.read_u8().await?;
        if shift == 63 && byte > 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        length |= u64::from(byte & 0x7f) << shift;
        if length > MAX_ERROR_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if byte & 0x80 == 0 {
            let mut message = [0; MAX_ERROR_BYTES as usize];
            io.read_exact(&mut message[..length as usize]).await?;
            return Ok(());
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn brutal_exchange_handles_fragmented_reply_and_padding() {
        for padding in [false, true] {
            let (client, server) = tokio::io::duplex(4096);
            let mut client: BoxStream = Box::new(client);
            let mut server: BoxStream = Box::new(server);
            if padding {
                client = Box::new(super::super::padding::Padding::new(client));
                server = Box::new(super::super::padding::Padding::new(server));
            }
            let peer = async {
                let mut request = [0; 31];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..4], &[0, 0, 3, 17]);
                assert_eq!(&request[4..21], DOMAIN);
                assert_eq!(&request[21..23], &[0, 0]);
                assert_eq!(
                    u64::from_be_bytes(request[23..].try_into().unwrap()),
                    900_000
                );
                for byte in [0, 1].into_iter().chain(700_000_u64.to_be_bytes()) {
                    server.write_all(&[byte]).await.unwrap();
                    server.flush().await.unwrap();
                    tokio::task::yield_now().await;
                }
            };
            let (rate, ()) = tokio::join!(exchange(&mut client, 800_000, 900_000), peer);
            assert_eq!(rate.unwrap(), 700_000);
        }
    }

    #[tokio::test]
    async fn brutal_rejects_bounded_errors_truncation_and_invalid_status() {
        for response in [
            b"\x00\x00\x06secret".as_slice(),
            b"\x01\x06secret",
            b"\x00\x00\x81\x02", // 257-byte error declaration.
            b"\x00\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02",
            b"\x00\x01\x00", // Truncated negotiated rate.
            b"\x00\x02",     // Non-boolean success.
        ] {
            let (client, mut server) = tokio::io::duplex(64);
            let mut client: BoxStream = Box::new(client);
            let peer = async {
                server.read_exact(&mut [0; 31]).await.unwrap();
                server.write_all(response).await.unwrap();
                server.shutdown().await.unwrap();
            };
            let (result, ()) = tokio::join!(exchange(&mut client, 1, 1), peer);
            assert_eq!(
                result.unwrap_err().to_string(),
                "sing-mux Brutal negotiation failed"
            );
        }
    }
}
