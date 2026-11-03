use super::*;
use tokio::sync::oneshot;

fn request(path: &str) -> http::Request<()> {
    http::Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap()
}

async fn response(stream: &mut ServerStream, payload: Bytes) {
    stream
        .send_response(http::Response::builder().status(200).body(()).unwrap())
        .await
        .unwrap();
    stream.send_data(payload).await.unwrap();
    stream.finish().await.unwrap();
}

async fn receive(stream: &mut RequestStream) -> Vec<u8> {
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    let mut data = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        assert!(data.len() <= 64 * 1024);
    }
    let _ = stream.recv_trailers().await.unwrap();
    data
}

#[derive(Clone, Copy, Debug)]
enum ReadPhase {
    Headers,
    Body,
    Trailers,
}

async fn drop_pending_query(phase: ReadPhase, explicit_cancel: bool) {
    let mut pair = Pair::new(64 * 1024).await;
    let (mut client, mut server) = pair.h3().await;
    let native = pair.client.clone();
    let (first_ready, ready) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (observed, result) = oneshot::channel();
    pair.spawn(async move {
        let (request, mut first) = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().path(), "/cancel");
        assert!(first.recv_data().await.unwrap().is_none());
        if !matches!(phase, ReadPhase::Headers) {
            first
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
        }
        if matches!(phase, ReadPhase::Trailers) {
            first
                .send_data(Bytes::from_static(b"partial"))
                .await
                .unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-fixture", http::HeaderValue::from_static("trailer"));
            first.send_trailers(trailers).await.unwrap();
        }
        first_ready.send(()).unwrap();
        let (request, mut sibling) = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().path(), "/sibling");
        assert!(sibling.recv_data().await.unwrap().is_none());
        response(&mut sibling, Bytes::from_static(b"sibling-body")).await;
        released.await.unwrap();
        if matches!(phase, ReadPhase::Trailers) {
            // No DATA is legal after trailers. The sibling already proves the
            // connection remains usable; releasing this half completes cleanup.
            drop(first);
            observed.send(None).unwrap();
        } else {
            let outcome = async {
                if matches!(phase, ReadPhase::Headers) {
                    first
                        .send_response(http::Response::builder().status(200).body(()).unwrap())
                        .await?;
                }
                first.send_data(Bytes::from(vec![b'x'; 128 * 1024])).await
            }
            .await;
            let code = match outcome {
                Err(h3::error::StreamError::RemoteTerminate { code }) => code.value(),
                other => panic!("canceled receiver must stop peer upload: {other:?}"),
            };
            observed.send(Some(code)).unwrap();
        }
        // Keep polling H3 control until the fixture's synchronized Stop.
        let _ = server.accept().await;
    });
    settle(pair, async move {
        let mut stream = client.send_request(request("/cancel")).await.unwrap();
        let id = stream.id();
        stream.finish().await.unwrap();
        ready.await.unwrap();
        match phase {
            ReadPhase::Headers => {
                let mut reading = Box::pin(stream.recv_response());
                assert!(poll_fn(|cx| Poll::Ready(reading.as_mut().poll(cx).is_pending())).await);
                drop(reading);
            }
            ReadPhase::Body => {
                assert_eq!(stream.recv_response().await.unwrap().status(), 200);
                let mut reading = Box::pin(stream.recv_data());
                assert!(poll_fn(|cx| Poll::Ready(reading.as_mut().poll(cx).is_pending())).await);
                drop(reading);
            }
            ReadPhase::Trailers => {
                assert_eq!(stream.recv_response().await.unwrap().status(), 200);
                let mut body = Vec::new();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(body, b"partial");
                let mut reading = Box::pin(stream.recv_trailers());
                assert!(poll_fn(|cx| Poll::Ready(reading.as_mut().poll(cx).is_pending())).await);
                drop(reading);
            }
        }
        if explicit_cancel {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            assert_eq!(
                stream.id(),
                id,
                "a Pending read must not hide its stream ID"
            );
        }
        drop(stream);
        assert!(client.can_open_request());
        let mut sibling = client.send_request(request("/sibling")).await.unwrap();
        sibling.finish().await.unwrap();
        assert_eq!(receive(&mut sibling).await, b"sibling-body");
        assert!(native.close_reason().is_none());
        release.send(()).unwrap();
        if let Some(code) = result.await.unwrap() {
            assert_eq!(code, 0, "official raw receive Drop uses STOP_SENDING(0)");
        }
    })
    .await;
}

#[tokio::test]
async fn dropped_pending_headers_preserves_sibling_and_stop() {
    drop_pending_query(ReadPhase::Headers, false).await;
}

#[tokio::test]
async fn dropped_pending_body_preserves_sibling_and_stop() {
    drop_pending_query(ReadPhase::Body, false).await;
}

#[tokio::test]
async fn dropped_pending_trailers_preserves_sibling_and_stop() {
    drop_pending_query(ReadPhase::Trailers, false).await;
}

#[tokio::test]
async fn explicit_pending_body_cancel_preserves_sibling_and_stop() {
    drop_pending_query(ReadPhase::Body, true).await;
}

#[tokio::test]
async fn canceled_backpressured_headers_preserves_sibling_and_stop() {
    let mut pair = Pair::new(64).await;
    let (mut client, mut server) = pair.h3().await;
    let native = pair.client.clone();
    settle(pair, async move {
        let large = http::Request::get("https://localhost/cancel-headers")
            .header(
                "x-fixture",
                "abcdefghijklmNOPQRSTUVWXYZ0123456789".repeat(128),
            )
            .body(())
            .unwrap();
        let mut sending = Box::pin(client.send_request(large));
        assert!(
            poll_fn(|cx| Poll::Ready(sending.as_mut().poll(cx).is_pending())).await,
            "actual native 64-byte receive credit must block HEADERS transmission"
        );
        drop(sending);
        let rejected = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .err()
            .expect("the peer must reject the incomplete canceled HEADERS");
        assert!(
            !matches!(rejected, h3::error::StreamError::ConnectionError(_)),
            "canceling a request must not kill the physical connection: {rejected:?}"
        );
        assert!(native.close_reason().is_none());
        let exchange = async {
            let mut sibling = client.send_request(request("/sibling")).await.unwrap();
            sibling.finish().await.unwrap();
            assert_eq!(receive(&mut sibling).await, b"header-cancel-sibling");
        };
        let peer = async {
            let (request, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.uri().path(), "/sibling");
            assert!(stream.recv_data().await.unwrap().is_none());
            response(&mut stream, Bytes::from_static(b"header-cancel-sibling")).await;
            // Continue driving peer critical streams while the client finishes.
            let _ = server.accept().await;
        };
        // The peer accept loop stays alive through the full response; it can
        // then be canceled when the client has consumed body/trailers/EOF.
        tokio::pin!(peer);
        tokio::select! {
            () = exchange => {},
            () = &mut peer => panic!("peer completed before the sibling response"),
        }
    })
    .await;
}

#[tokio::test]
async fn upload_credit_recovers_all_data_and_fin_without_ack_barrier() {
    let mut pair = Pair::new(1024).await;
    let (mut client, mut server) = pair.h3().await;
    let payload = Bytes::from((0..65_673).map(|n| (n % 251) as u8).collect::<Vec<_>>());
    let expected = payload.clone();
    settle(pair, async move {
        let request = http::Request::post("https://localhost/upload")
            .body(())
            .unwrap();
        let stream = client.send_request(request).await.unwrap();
        let (mut upload, mut download) = stream.split();
        let exchange = async {
            let writing = async move {
                let mut sending = Box::pin(upload.send_data(payload));
                assert!(poll_fn(|cx| Poll::Ready(sending.as_mut().poll(cx).is_pending())).await);
                sending.as_mut().await.unwrap();
                drop(sending);
                upload.finish().await.unwrap();
                // Native FIN is enough here. Drop must preserve accepted data
                // while the shared physical connection continues to run.
                drop(upload);
            };
            let reading = async {
                assert_eq!(download.recv_response().await.unwrap().status(), 200);
                let mut body = Vec::new();
                while let Some(mut data) = download.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(body, b"upload-complete");
                assert!(download.recv_trailers().await.unwrap().is_none());
            };
            tokio::join!(writing, reading);
        };
        let peer = async {
            let (request, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::POST);
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                assert!(body.len() <= expected.len());
            }
            assert_eq!(body, expected);
            assert!(stream.recv_trailers().await.unwrap().is_none());
            response(&mut stream, Bytes::from_static(b"upload-complete")).await;
            let _ = server.accept().await;
        };
        tokio::pin!(peer);
        tokio::select! {
            () = exchange => {},
            () = &mut peer => panic!("peer completed before upload response"),
        }
    })
    .await;
}

#[tokio::test]
async fn dropped_backpressured_data_resets_upload_and_preserves_sibling() {
    let mut pair = Pair::new(1024).await;
    let (mut client, mut server) = pair.h3().await;
    let (accepted, ready) = oneshot::channel();
    let (observed, reset) = oneshot::channel();
    pair.spawn(async move {
        let (_, mut first) = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        accepted.send(()).unwrap();
        let error = first
            .recv_data()
            .await
            .err()
            .expect("unfinished DATA must reset");
        match error {
            h3::error::StreamError::RemoteTerminate { code } => {
                assert_eq!(code, h3::error::Code::H3_REQUEST_CANCELLED);
            }
            other => panic!("expected request cancellation reset, got {other:?}"),
        }
        observed.send(()).unwrap();
        let (_, mut sibling) = server
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert!(sibling.recv_data().await.unwrap().is_none());
        response(&mut sibling, Bytes::from_static(b"data-cancel-sibling")).await;
        let _ = server.accept().await;
    });
    settle(pair, async move {
        let mut stream = client
            .send_request(
                http::Request::post("https://localhost/cancel-data")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        ready.await.unwrap();
        let mut sending = Box::pin(stream.send_data(Bytes::from(vec![b'x'; 64 * 1024])));
        assert!(poll_fn(|cx| Poll::Ready(sending.as_mut().poll(cx).is_pending())).await);
        drop(sending);
        drop(stream);
        reset.await.unwrap();
        let mut sibling = client.send_request(request("/sibling")).await.unwrap();
        sibling.finish().await.unwrap();
        assert_eq!(receive(&mut sibling).await, b"data-cancel-sibling");
        assert!(client.can_open_request());
    })
    .await;
}
