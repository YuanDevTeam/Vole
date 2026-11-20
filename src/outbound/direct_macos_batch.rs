//! Bounded ready UDP prefixes on an already protected socket.
use crate::session::Datagram;
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};

pub(super) fn send_owned(
    socket: Arc<crate::dialer::PhysicalDatagram>,
    packets: Vec<Datagram>,
) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
    send_with(packets, move |cx, payload, peer| {
        // Tokio owns nonblocking readiness and cooperative-budget handling.
        // This capture retains the original protected socket until operation Drop.
        socket.poll_send_to(cx, payload, peer)
    })
}

#[cfg(any(
    feature = "outbound-masque",
    feature = "outbound-wireguard",
    feature = "outbound-tuic"
))]
pub(super) fn send_connected_owned(
    socket: Arc<crate::dialer::PhysicalDatagram>,
    peer: SocketAddr,
    packets: Vec<Datagram>,
) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
    send_connected_with(packets, peer, move |cx, payload| {
        socket.poll_send(cx, payload)
    })
}

#[cfg(any(
    feature = "outbound-masque",
    feature = "outbound-wireguard",
    feature = "outbound-tuic"
))]
fn send_connected_with(
    packets: Vec<Datagram>,
    peer: SocketAddr,
    mut send: impl FnMut(&mut Context<'_>, &[u8]) -> Poll<io::Result<usize>> + Send + 'static,
) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
    if crate::dispatch::datagram_batch_peer(&packets) != Some(peer) {
        return Err(packets);
    }
    send_with(packets, move |cx, payload, _| send(cx, payload))
}

fn send_with(
    packets: Vec<Datagram>,
    mut send: impl FnMut(&mut Context<'_>, &[u8], SocketAddr) -> Poll<io::Result<usize>>
    + Send
    + 'static,
) -> Result<crate::dispatch::OwnedDatagramBatchSend, Vec<Datagram>> {
    let Some(peer) = crate::dispatch::datagram_batch_peer(&packets) else {
        return Err(packets);
    };
    Ok(Box::pin(std::future::poll_fn(move |cx| {
        let mut accepted = 0;
        // Admission bounds this poll to four complete packets and 8 KiB.
        // The parent retains its FIFO until this exact positive prefix completes.
        for packet in &packets {
            match send(cx, &packet.payload, peer) {
                Poll::Ready(Ok(length)) if length == packet.payload.len() => accepted += 1,
                Poll::Ready(Ok(_)) => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending if accepted != 0 => return Poll::Ready(Ok(accepted)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(accepted))
    })))
}

#[cfg(test)]
#[path = "direct_macos_batch_memory_tests.rs"]
mod tests;
