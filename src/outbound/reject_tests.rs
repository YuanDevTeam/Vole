use super::*;
use crate::session::{DatagramSession, Destination, InboundKind, InboundMetadata};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn session() -> StreamSession {
    StreamSession {
        metadata: InboundMetadata::new(443),
        inbound: InboundKind::Tun,
        source: "192.0.2.10:12345".parse().unwrap(),
        destination: Destination::domain("rejected.test", 443).unwrap(),
        sniffed_domain: None,
    }
}

#[tokio::test]
async fn named_reject_ends_tcp_without_resolving_the_destination() {
    let node = RejectOutbound::default();
    let mut stream = node
        .connect_stream(session(), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(
        stream.write(b"request").await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    node.begin_shutdown();
    assert!(
        node.connect_stream(session(), &EstablishContext::default())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn reject_drop_holds_first_write_and_read_until_one_absolute_deadline() {
    let node = RejectOutbound::drop_connections();
    let stream = node
        .connect_stream(session(), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut byte = [0];
    let read = reader.read(&mut byte);
    let write = writer.write(b"client first");
    tokio::pin!(read, write);
    assert!(futures_util::poll!(&mut read).is_pending());
    assert!(futures_util::poll!(&mut write).is_pending());
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(futures_util::poll!(&mut read).is_pending());
    assert!(futures_util::poll!(&mut write).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(read.await.unwrap(), 0);
    assert_eq!(
        write.await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test(start_paused = true)]
async fn reject_drop_stop_wakes_both_pending_directions_without_waiting() {
    let node = RejectOutbound::drop_connections();
    let stream = node
        .connect_stream(session(), &EstablishContext::default())
        .await
        .unwrap()
        .io;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut byte = [0];
    let read = reader.read(&mut byte);
    let write = writer.write(b"client first");
    tokio::pin!(read, write);
    assert!(futures_util::poll!(&mut read).is_pending());
    assert!(futures_util::poll!(&mut write).is_pending());
    let stopped = Instant::now();
    node.begin_shutdown();
    assert_eq!(read.await.unwrap(), 0);
    assert!(write.await.is_err());
    assert_eq!(Instant::now(), stopped);
}

#[tokio::test(start_paused = true)]
async fn reject_drop_udp_ends_immediately_instead_of_adding_the_tcp_delay() {
    let node = RejectOutbound::drop_connections();
    let request = DatagramRequest::new(DatagramSession::new(InboundKind::Tun, session().source));
    let mut transport = node
        .open_datagram(request, &EstablishContext::default())
        .await
        .unwrap();
    transport
        .send(Datagram {
            remote: session().destination,
            payload: Bytes::from_static(b"packet"),
            sniffed_domain: None,
        })
        .await
        .unwrap();
    let before = Instant::now();
    assert!(transport.receive().await.is_err());
    assert_eq!(Instant::now(), before);
}
