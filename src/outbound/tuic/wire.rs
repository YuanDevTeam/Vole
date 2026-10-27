//! Minimal v5 command encoding. Crypto and QUIC remain in official libraries.
use crate::session::Destination;
use bytes::{Buf, Bytes};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) fn address(peer: &Destination, out: &mut Vec<u8>) -> io::Result<()> {
    if peer.port() == 0
        && !matches!(peer, Destination::Domain { host, .. } if host == crate::outbound::uot::MAGIC_DESTINATION)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    match peer {
        Destination::Ip(peer) => match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                out.push(2);
                out.extend_from_slice(&ip.octets());
            }
        },
        Destination::Domain { host, .. } => {
            if host.is_empty() || host.len() > 255 || host.bytes().any(|v| v.is_ascii_control()) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            out.extend_from_slice(&[0, host.len() as u8]);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    Ok(())
}

pub(super) fn connect(peer: &Destination) -> io::Result<Vec<u8>> {
    let mut bytes = vec![5, 1];
    address(peer, &mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
pub(super) fn packets(
    association: u16,
    packet: u16,
    peer: &Destination,
    payload: &[u8],
    limit: usize,
) -> io::Result<Vec<Bytes>> {
    packets_with_payload_limit(association, packet, peer, payload, limit, usize::MAX)
}

pub(super) fn packets_with_payload_limit(
    association: u16,
    packet: u16,
    peer: &Destination,
    payload: &[u8],
    limit: usize,
    payload_limit: usize,
) -> io::Result<Vec<Bytes>> {
    if payload.len() > u16::MAX as usize {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut target = Vec::new();
    address(peer, &mut target)?;
    let space = limit
        .checked_sub(10 + target.len())
        .ok_or(io::ErrorKind::InvalidInput)?
        .min(payload_limit);
    if space == 0 && !payload.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let count = payload.len().max(1).div_ceil(space.max(1));
    if count > 255 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let body =
            &payload[(index * space).min(payload.len())..((index + 1) * space).min(payload.len())];
        let mut bytes = vec![5, 2];
        bytes.extend_from_slice(&association.to_be_bytes());
        bytes.extend_from_slice(&packet.to_be_bytes());
        bytes.extend_from_slice(&[count as u8, index as u8]);
        bytes.extend_from_slice(&(body.len() as u16).to_be_bytes());
        if index == 0 {
            bytes.extend_from_slice(&target);
        } else {
            bytes.push(255);
        }
        bytes.extend_from_slice(body);
        out.push(bytes.into());
    }
    Ok(out)
}

pub(super) struct Fragment {
    pub association: u16,
    pub packet: u16,
    pub count: u8,
    pub index: u8,
    pub peer: Option<Destination>,
    pub payload: Bytes,
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn take(bytes: &mut Bytes, count: usize) -> io::Result<Bytes> {
    if bytes.len() < count {
        return Err(invalid());
    }
    Ok(bytes.split_to(count))
}

fn parse_address(bytes: &mut Bytes) -> io::Result<Option<Destination>> {
    let kind = take(bytes, 1)?[0];
    if kind == 255 {
        return Ok(None);
    }
    let host = match kind {
        0 => {
            let n = take(bytes, 1)?[0] as usize;
            take(bytes, n)?
        }
        1 => take(bytes, 4)?,
        2 => take(bytes, 16)?,
        _ => return Err(invalid()),
    };
    let mut port = take(bytes, 2)?;
    let port = port.get_u16();
    if port == 0 {
        return Err(invalid());
    }
    Ok(Some(match kind {
        0 => Destination::domain(std::str::from_utf8(&host).map_err(|_| invalid())?, port)
            .map_err(|_| invalid())?,
        1 => Destination::Ip(std::net::SocketAddr::new(
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(host.as_ref()).unwrap()).into(),
            port,
        )),
        2 => Destination::Ip(std::net::SocketAddr::new(
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(host.as_ref()).unwrap()).into(),
            port,
        )),
        _ => unreachable!(),
    }))
}

pub(super) fn decode(mut bytes: Bytes) -> io::Result<Fragment> {
    let mut head = take(&mut bytes, 10)?;
    if head.get_u8() != 5 || head.get_u8() != 2 {
        return Err(invalid());
    }
    let association = head.get_u16();
    let packet = head.get_u16();
    let count = head.get_u8();
    let index = head.get_u8();
    let size = head.get_u16();
    if count == 0 || index >= count {
        return Err(invalid());
    }
    let peer = parse_address(&mut bytes)?;
    if (index == 0) != peer.is_some() || bytes.len() != size as usize {
        return Err(invalid());
    }
    Ok(Fragment {
        association,
        packet,
        count,
        index,
        peer,
        payload: bytes,
    })
}

/// Validate the association/size before allocating payload storage. One command
/// per uni stream, bounded by the same receiver budget as DATAGRAM packets.
pub(super) async fn read_packet(
    mut stream: impl AsyncRead + Unpin,
    allowed: impl Fn(u16) -> Option<u16>,
) -> io::Result<Fragment> {
    let mut head = [0; 10];
    stream.read_exact(&mut head).await?;
    if head[..2] != [5, 2] || head[6] == 0 || head[7] >= head[6] {
        return Err(invalid());
    }
    let id = u16::from_be_bytes([head[2], head[3]]);
    let budget = allowed(id).ok_or_else(invalid)?;
    let size = u16::from_be_bytes([head[8], head[9]]) as usize;
    if size > budget as usize {
        return Err(invalid());
    }
    let kind = stream.read_u8().await?;
    let mut raw = head.to_vec();
    raw.push(kind);
    let rest = match kind {
        0 => {
            let len = stream.read_u8().await?;
            raw.push(len);
            len as usize + 2
        }
        1 => 6,
        2 => 18,
        255 => 0,
        _ => return Err(invalid()),
    };
    let start = raw.len();
    raw.resize(start + rest, 0);
    stream.read_exact(&mut raw[start..]).await?;
    // Address validity before payload allocation.
    let target = parse_address(&mut Bytes::copy_from_slice(&raw[10..]))?;
    if (head[7] == 0) != target.is_some() {
        return Err(invalid());
    }
    let start = raw.len();
    raw.resize(start + size, 0);
    stream.read_exact(&mut raw[start..]).await?;
    // TUIC uni packets end at their declared payload size. Dropping the
    // reader retires this packet without waiting for a separately delivered FIN.
    decode(raw.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[test]
    fn native_packet_has_one_address_and_exact_fragment_lengths() {
        let peer = Destination::Ip("192.0.2.1:53".parse().unwrap());
        let actual = packets(0x1234, 0xabcd, &peer, b"abcde", 19).unwrap();
        assert_eq!(
            actual.iter().map(|b| b.as_ref()).collect::<Vec<_>>(),
            [
                &b"\x05\x02\x12\x34\xab\xcd\x03\x00\x00\x02\x01\xc0\x00\x02\x01\x00\x35ab"[..],
                &b"\x05\x02\x12\x34\xab\xcd\x03\x01\x00\x02\xffcd"[..],
                &b"\x05\x02\x12\x34\xab\xcd\x03\x02\x00\x01\xffe"[..],
            ]
        );
    }

    #[test]
    fn address_and_packet_bounds_are_wire_exact_and_fail_closed() {
        assert_eq!(
            connect(&Destination::domain("x", 80).unwrap()).unwrap(),
            b"\x05\x01\x00\x01x\x00\x50"
        );
        let mut ipv6 = vec![5, 1, 2];
        ipv6.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53]);
        assert_eq!(
            connect(&Destination::Ip("[::1]:53".parse().unwrap())).unwrap(),
            ipv6
        );
        let peer = Destination::Ip("192.0.2.1:53".parse().unwrap());
        assert_eq!(packets(0, 0, &peer, &[], 17).unwrap()[0].len(), 17);
        assert!(packets(0, 0, &peer, &[], 16).is_err());
        assert_eq!(packets(0, 0, &peer, &[1; 255], 18).unwrap().len(), 255);
        assert!(packets(0, 0, &peer, &[1; 256], 18).is_err());
        assert!(packets(0, 0, &peer, &vec![1; 65536], 66000).is_err());
        let literal = &b"\x05\x02\x00\x00\xff\xff\x01\x00\x00\x01\x01\xc0\x00\x02\x01\x00\x35x"[..];
        assert_eq!(
            decode(Bytes::copy_from_slice(literal)).unwrap().payload,
            b"x"[..]
        );
        for length in 0..literal.len() {
            assert!(decode(Bytes::copy_from_slice(&literal[..length])).is_err());
        }
        for (position, value) in [(0, 4), (1, 4), (6, 0), (7, 1), (9, 2), (10, 255), (16, 0)] {
            let mut bad = literal.to_vec();
            bad[position] = value;
            assert!(decode(bad.into()).is_err());
        }
        let mut bad = literal.to_vec();
        bad.push(0);
        assert!(decode(bad.into()).is_err());
        for host in ["", "bad\0name"] {
            assert!(
                connect(&Destination::Domain {
                    host: host.into(),
                    port: 80
                })
                .is_err()
            );
        }
    }

    #[test]
    fn only_uot_v2_connect_allows_a_zero_port() {
        assert_eq!(
            connect(&crate::outbound::uot::magic_destination()).unwrap(),
            b"\x05\x01\x00\x17sp.v2.udp-over-tcp.arpa\x00\x00"
        );
        for peer in [
            Destination::Domain {
                host: "sp.udp-over-tcp.arpa".into(),
                port: 0,
            },
            Destination::Domain {
                host: "peer.invalid".into(),
                port: 0,
            },
            Destination::Ip("192.0.2.1:0".parse().unwrap()),
        ] {
            assert!(connect(&peer).is_err());
        }
    }

    #[test]
    fn configured_native_fragment_payload_and_quic_unfragmented_packet() {
        let peer = Destination::Ip("[::1]:53".parse().unwrap());
        for message_limit in [1200, 65535 + 512] {
            let packets =
                packets_with_payload_limit(1, 2, &peer, b"abcdefgh", message_limit, 3).unwrap();
            assert_eq!(packets.len(), 3);
            let pieces: Vec<_> = packets
                .into_iter()
                .map(|packet| decode(packet).unwrap())
                .collect();
            assert_eq!(
                pieces
                    .iter()
                    .map(|piece| piece.payload.as_ref())
                    .collect::<Vec<_>>(),
                vec![&b"abc"[..], &b"def"[..], &b"gh"[..]]
            );
            assert!(pieces.iter().all(|piece| piece.count == 3));
            assert_eq!(pieces[0].peer, Some(peer.clone()));
            assert!(pieces[1].peer.is_none());
            let quic =
                packets_with_payload_limit(1, 2, &peer, b"abcdefgh", 65535 + 512, usize::MAX)
                    .unwrap();
            assert_eq!(quic.len(), 1);
            let packet = decode(quic.into_iter().next().unwrap()).unwrap();
            assert_eq!(packet.payload.as_ref(), b"abcdefgh");
            assert_eq!(packet.count, 1);
        }
    }

    #[tokio::test]
    async fn uni_parser_rejects_unknown_owner_before_reading_body_and_declared_limit() {
        let (client, mut peer) = tokio::io::duplex(64);
        peer.write_all(b"\x05\x02\xff\xff\x00\x00\x01\x00\xff\xff")
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                read_packet(client, |_| None)
            )
            .await
            .unwrap()
            .is_err()
        );
        let literal = &b"\x05\x02\x00\x01\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x35a"[..];
        assert!(read_packet(literal, |_| Some(0)).await.is_err());
    }

    #[tokio::test]
    async fn uni_parser_delivers_declared_payload_without_fin() {
        let literal = &b"\x05\x02\x00\x01\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x35a"[..];
        for suffix in [&b""[..], &b"x"[..]] {
            let (client, mut peer) = tokio::io::duplex(64);
            peer.write_all(literal).await.unwrap();
            peer.write_all(suffix).await.unwrap();
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(20),
                read_packet(client, |id| if id == 1 { Some(1) } else { None }),
            )
            .await;
            // Keep the real writer open until parsing completes; no FIN or
            // background task can make the old EOF-waiting parser pass.
            drop(peer);
            let fragment = result
                .expect("declared UDP payload waited for FIN")
                .unwrap();
            assert_eq!(fragment.association, 1);
            assert_eq!(fragment.packet, 0);
            assert_eq!(fragment.count, 1);
            assert_eq!(fragment.index, 0);
            assert_eq!(
                fragment.peer,
                Some(Destination::Domain {
                    host: "x".into(),
                    port: 53,
                })
            );
            assert_eq!(fragment.payload.as_ref(), b"a");
        }
    }

    #[tokio::test]
    async fn uni_parser_rejects_truncated_declared_payload() {
        let truncated = &b"\x05\x02\x00\x01\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x35"[..];
        assert!(read_packet(truncated, |_| Some(1)).await.is_err());
    }
}
