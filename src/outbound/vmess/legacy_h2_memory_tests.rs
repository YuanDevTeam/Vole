//! Post-response-authentication seam only: no full VMess header authentication,
//! official peer, business HTTP cache, socket or performance acceptance.
use super::*;
use crate::session::Destination;
use futures_util::FutureExt;
use std::{
    future::{Future, poll_fn},
    panic::AssertUnwindSafe,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::oneshot,
    time::{Instant, timeout},
};

const ENTITY: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(10);

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn body_codec() -> BodyCodec {
    BodyCodec::new(
        BodyOptions::new(BodyCipher::Aes128Gcm, false, false).unwrap(),
        Command::Tcp,
        &[7; 16],
        [9; 16],
        &[7; 16],
        [9; 16],
    )
}
fn post_auth(io: BoxStream) -> VmessStream {
    let handshake = ClientHandshake::new(
        &super::super::VmessIdentity::new(uuid::Uuid::from_bytes([7; 16])),
        Command::Tcp,
        &Destination::domain("body.test", 443).unwrap(),
        BodyOptions::new(BodyCipher::Aes128Gcm, false, false).unwrap(),
    )
    .unwrap();
    let mut stream = VmessStream::new(io, handshake).with_whole_close();
    stream.read = body_codec();
    stream.write = body_codec();
    stream.stage = ReadStage::Length;
    stream.handshake = None;
    stream
}

async fn send_entity(
    send: &mut h2::SendStream<Bytes>,
    codec: &mut BodyCodec,
    byte: u8,
    blocked: &mut Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    for _ in 0..ENTITY / WRITE_CHUNK {
        let mut wire = codec.encode(&[byte; WRITE_CHUNK])?;
        while !wire.is_empty() {
            send.reserve_capacity(wire.len());
            let capacity = poll_fn(|cx| match send.poll_capacity(cx) {
                Poll::Pending => {
                    if let Some(signal) = blocked.take() {
                        let _ = signal.send(());
                    }
                    Poll::Pending
                }
                ready => ready,
            })
            .await
            .ok_or_else(invalid)?
            .map_err(|_| invalid())?;
            if capacity == 0 {
                tokio::task::yield_now().await;
                continue;
            }
            let count = capacity.min(wire.len());
            send.send_data(wire.split_to(count), false)
                .map_err(|_| invalid())?;
        }
    }
    Ok(())
}

async fn receive_entities(receive: &mut h2::RecvStream) -> io::Result<()> {
    let mut decoder = body_codec();
    let mut wire = BytesMut::new();
    let mut next = None;
    let mut consumed = 0;
    while consumed < 2 * ENTITY {
        let data = receive
            .data()
            .await
            .ok_or_else(invalid)?
            .map_err(|_| invalid())?;
        receive
            .flow_control()
            .release_capacity(data.len())
            .map_err(|_| invalid())?;
        wire.extend_from_slice(&data);
        loop {
            if next.is_none() {
                if wire.len() < decoder.length_size() {
                    break;
                }
                next = Some(decoder.decode_length(&mut wire.split_to(decoder.length_size()))?);
            }
            let (length, padding) = next.unwrap();
            if wire.len() < length {
                break;
            }
            let plain = decoder.decode_body(wire.split_to(length), padding)?;
            if plain.is_empty() {
                return Err(invalid());
            }
            for &byte in plain.iter() {
                let expected = if consumed < ENTITY { 0x31 } else { 0x32 };
                if consumed >= 2 * ENTITY || byte != expected {
                    return Err(invalid());
                }
                consumed += 1;
            }
            next = None;
            if consumed == 2 * ENTITY {
                break;
            }
        }
    }
    if next.is_some() || !wire.is_empty() {
        return Err(invalid());
    }
    Ok(())
}

async fn peer(
    raw: DuplexStream,
    read_allowed: oneshot::Receiver<()>,
    send_blocked: oneshot::Sender<()>,
) -> io::Result<()> {
    let mut connection = h2::server::Builder::new()
        .initial_window_size(128)
        .handshake::<_, Bytes>(raw)
        .await
        .map_err(|_| invalid())?;
    let (request, mut reply) = connection
        .accept()
        .await
        .ok_or_else(invalid)?
        .map_err(|_| invalid())?;
    if request.method() != "PUT" || request.uri().path() != "/h2-reuse" {
        return Err(invalid());
    }
    let mut receive = request.into_body();
    let mut send = reply
        .send_response(http::Response::new(()), false)
        .map_err(|_| invalid())?;
    let work = async move {
        let mut encoder = body_codec();
        // More than the client's initial DATA window: it must really stall
        // before the application starts consuming its first decoded entity.
        send_entity(&mut send, &mut encoder, 0x91, &mut Some(send_blocked)).await?;
        read_allowed.await.map_err(|_| invalid())?;
        receive_entities(&mut receive).await?;
        send_entity(&mut send, &mut encoder, 0x92, &mut None).await?;
        match receive.data().await {
            None | Some(Err(_)) => Ok(()), // Original Driver.stop/whole-close.
            Some(Ok(_)) => Err(invalid()),
        }
    };
    tokio::pin!(work);
    loop {
        tokio::select! {
            result = &mut work => return result,
            next = connection.accept() => {
                match next {
                    None | Some(Err(_)) => return work.await,
                    Some(Ok(_)) => return Err(invalid()),
                }
            }
        }
    }
}

#[tokio::test]
async fn legacy_h2_post_auth_two_entities_progress_both_ways_and_join_stop() {
    let (raw, server) = tokio::io::duplex(64);
    let (allow_read, read_allowed) = oneshot::channel();
    let (send_blocked, blocked) = oneshot::channel();
    let mut peer = tokio::spawn(peer(server, read_allowed, send_blocked));
    let mut owner = None;
    let outcome = AssertUnwindSafe(timeout(WAIT, async {
        let (raw, driver) = crate::transport::legacy_h2(
            Box::new(raw),
            "http://cover.test/h2-reuse",
            Instant::now() + WAIT,
        )
        .await?;
        owner = Some(driver);
        let (mut read, mut write) = tokio::io::split(post_auth(raw));
        let mut upload_bytes = vec![0x31; ENTITY];
        upload_bytes.extend_from_slice(&vec![0x32; ENTITY]);
        let mut upload = Box::pin(async {
            write.write_all(&upload_bytes).await?;
            write.flush().await
        });
        assert!(
            poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx)))
                .await
                .is_pending(),
            "withheld peer receive credit must block upload"
        );
        blocked.await.map_err(|_| invalid())?;
        let mut first = vec![0; ENTITY];
        read.read_exact(&mut first).await?;
        assert_eq!(first, vec![0x91; ENTITY]);
        assert!(
            poll_fn(|cx| Poll::Ready(upload.as_mut().poll(cx)))
                .await
                .is_pending(),
            "receive must progress while the independent upload remains blocked"
        );
        let mut second = vec![0; ENTITY];
        let mut download = Box::pin(read.read_exact(&mut second));
        assert!(
            poll_fn(|cx| Poll::Ready(download.as_mut().poll(cx)))
                .await
                .is_pending(),
            "the second response remains withheld until upload credit is released"
        );
        allow_read.send(()).map_err(|_| invalid())?;
        tokio::try_join!(upload.as_mut(), download.as_mut())?;
        drop((upload, download));
        assert_eq!(second, vec![0x92; ENTITY]);
        Ok::<_, io::Error>((read, write))
    }))
    .catch_unwind()
    .await;

    let mut panic = None;
    let (mut active, mut failure) = match outcome {
        Ok(Ok(Ok(halves))) => (Some(halves), None),
        Ok(Ok(Err(error))) => (None, Some(format!("body exchange: {:?}", error.kind()))),
        Ok(Err(_)) => (None, Some("body exchange deadline".into())),
        Err(error) => {
            panic = Some(error);
            (None, None)
        }
    };
    // Once connect returns its Driver, stop and await it before propagating an
    // exchange failure. Cancellation inside connect retains its production
    // Drop-abort fallback; this test does not prove a join for that path.
    // Always await our separately owned peer task.
    let stop_phase = AssertUnwindSafe(async {
        if let Some((read, write)) = active.as_mut() {
            let mut byte = [0];
            let mut pending = Box::pin(read.read(&mut byte));
            let before = poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx))).await;
            let waiting = before.is_pending();
            if !waiting {
                failure = Some("reader ended before Stop".into());
            }
            let stopped = if let Some(driver) = owner.take() {
                driver.stop().await
            } else {
                Err(invalid())
            };
            if stopped.is_err() {
                failure = Some("carrier Stop join failed".into());
            }
            if waiting {
                if !matches!(timeout(WAIT, pending).await, Ok(Ok(0))) {
                    failure = Some("Stop did not wake the live VMess reader to EOF".into());
                }
            } else {
                drop(pending);
            }
            let after_stop = timeout(WAIT, async {
                write.write_all(b"after-stop").await?;
                write.flush().await
            })
            .await;
            if !matches!(after_stop, Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe) {
                failure = Some("stopped VMess writer flush returned a different result".into());
            }
        } else if let Some(driver) = owner.take()
            && driver.stop().await.is_err()
        {
            failure = Some("failed exchange carrier Stop join failed".into());
        }
    })
    .catch_unwind()
    .await;
    if let Err(error) = stop_phase {
        if panic.is_none() {
            panic = Some(error);
        }
    }
    // A panic before taking the owner must still reach its actual stop barrier.
    if let Some(driver) = owner.take() {
        match AssertUnwindSafe(driver.stop()).catch_unwind().await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => failure = Some("cleanup carrier Stop join failed".into()),
            Err(error) => {
                if panic.is_none() {
                    panic = Some(error);
                }
            }
        }
    }
    drop(active);
    let joined = match timeout(WAIT, &mut peer).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(invalid()),
        Err(_) => {
            peer.abort();
            let _ = peer.await;
            Err(io::ErrorKind::TimedOut.into())
        }
    };
    if let Some(error) = panic {
        std::panic::resume_unwind(error);
    }
    assert!(
        joined.is_ok(),
        "peer must naturally exit after the actual Stop: {joined:?}"
    );
    assert!(failure.is_none(), "{failure:?}");
}
