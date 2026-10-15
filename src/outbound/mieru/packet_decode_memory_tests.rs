//! Observe the production parser's destination buffer without opening I/O.
use super::*;
use std::{pin::Pin, sync::atomic::AtomicUsize};
use tokio::io::ReadBuf;

struct BodyRead<'a> {
    wire: &'a [u8],
    body_length: usize,
    address: Arc<AtomicUsize>,
}
impl AsyncRead for BodyRead<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == this.body_length {
            this.address
                .store(buffer.filled().as_ptr() as usize, Ordering::SeqCst);
        }
        Pin::new(&mut this.wire).poll_read(cx, buffer)
    }
}

#[tokio::test]
async fn mieru_packet_payload_reuses_the_receive_allocation() {
    let remote = Destination::Ip("198.51.100.1:53".parse().unwrap());
    let body = socks5::encode_udp_packet(&remote, &[7; 1200], usize::from(u16::MAX)).unwrap();
    let mut frame = vec![0];
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(&body);
    frame.push(255);
    let address = Arc::new(AtomicUsize::new(0));
    let mut input = BodyRead {
        wire: &frame,
        body_length: body.len(),
        address: address.clone(),
    };
    let packet = read_packet(&mut input, 1452).await.unwrap();
    let body_address = address.load(Ordering::SeqCst);
    drop(input);
    drop(frame);
    assert_eq!(packet.remote, remote);
    assert_eq!(packet.payload.as_ref(), &[7; 1200]);
    assert_ne!(body_address, 0);
    assert_eq!(
        packet.payload.as_ptr() as usize,
        body_address + 10,
        "parser duplicates the received payload allocation"
    );
}
