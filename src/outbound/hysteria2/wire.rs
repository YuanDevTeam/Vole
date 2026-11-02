use crate::session::Destination;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) fn tcp_request(destination: &Destination) -> io::Result<Vec<u8>> {
    let address = destination.authority();
    if destination.port() == 0 || address.len() > 2048 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = Vec::with_capacity(address.len() + 12);
    encode_varint(0x401, &mut bytes);
    encode_varint(address.len() as u64, &mut bytes);
    bytes.extend_from_slice(address.as_bytes());
    encode_varint(0, &mut bytes);
    Ok(bytes)
}

pub(super) async fn tcp_response(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let status = reader.read_u8().await?;
    let mut scratch = [0; crate::limits::HY2_RESPONSE_PADDING];
    for limit in [
        crate::limits::HY2_RESPONSE_MESSAGE,
        crate::limits::HY2_RESPONSE_PADDING,
    ] {
        let length = read_varint(reader).await?;
        if length > limit as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        reader.read_exact(&mut scratch[..length as usize]).await?;
    }
    if status != 0 {
        return Err(io::ErrorKind::ConnectionRefused.into());
    }
    Ok(())
}

pub(super) fn encode_varint(value: u64, output: &mut Vec<u8>) {
    if value < 64 {
        output.push(value as u8);
    } else if value < 16384 {
        output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<u64> {
    let first = reader.read_u8().await?;
    let mut value = u64::from(first & 0x3f);
    for _ in 1..(1 << (first >> 6)) {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_wire_matches_the_protocol_and_preserves_server_first_bytes() {
        let destination = Destination::domain("x", 1).unwrap();
        assert_eq!(tcp_request(&destination).unwrap(), b"\x44\x01\x03x:1\x00");
        let mut response = &b"\0\x02ok\x03padserver-first"[..];
        tcp_response(&mut response).await.unwrap();
        assert_eq!(response, b"server-first");
        for (bytes, kind) in [
            (&b"\x01\0\0"[..], io::ErrorKind::ConnectionRefused),
            (&b"\0\x40"[..], io::ErrorKind::UnexpectedEof),
            (&b"\0\x48\x01"[..], io::ErrorKind::InvalidData),
            (&b"\0\0\x50\x01"[..], io::ErrorKind::InvalidData),
        ] {
            assert_eq!(
                tcp_response(&mut &bytes[..]).await.unwrap_err().kind(),
                kind
            );
        }
    }
}
