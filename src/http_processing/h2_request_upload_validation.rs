//! Fixed real-duplex request-framing probes; no TLS authentication or sockets.
use super::*;
use crate::http_processing::body_budget::{Budget, BudgetedBytes, WORKSPACE};
use futures_util::future::poll_fn;
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

const REQUEST: &[u8] = b"\0x\xff";
const RESPONSE: &[u8] = b"request-framing-proof";
struct CountedIo {
    io: DuplexStream,
    live: Arc<AtomicUsize>,
}
impl CountedIo {
    fn new(io: DuplexStream, live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(1, Ordering::AcqRel);
        Self {
            io,
            live: live.clone(),
        }
    }
}
impl Drop for CountedIo {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}
impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
fn error<E>(_error: E) -> io::Error {
    failed()
}
struct Pair {
    sender: h2::client::SendRequest<Bytes>,
    client: h2::client::Connection<CountedIo, Bytes>,
    server: h2::server::Connection<CountedIo, Bytes>,
}
impl Pair {
    async fn new(live: &Arc<AtomicUsize>) -> io::Result<Self> {
        let (client, server) = tokio::io::duplex(8192);
        let (sender, mut client) = h2::client::handshake(CountedIo::new(client, live))
            .await
            .map_err(error)?;
        let mut handshake = Box::pin(h2::server::handshake(CountedIo::new(server, live)));
        let server = tokio::select! {biased;
            result=&mut handshake=>result.map_err(error)?,
            _=&mut client=>return Err(failed()),
        };
        drop(handshake);
        Ok(Self {
            sender,
            client,
            server,
        })
    }
    async fn accept(
        &mut self,
    ) -> io::Result<(Request<h2::RecvStream>, h2::server::SendResponse<Bytes>)> {
        poll_fn(|cx| {
            if Pin::new(&mut self.client).poll(cx).is_ready() {
                return Poll::Ready(Err(failed()));
            }
            self.server
                .poll_accept(cx)
                .map(|request| request.ok_or_else(failed)?.map_err(error))
        })
        .await
    }
    async fn drive<F: Future>(&mut self, work: F) -> io::Result<F::Output> {
        tokio::pin!(work);
        poll_fn(|cx| {
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(Ok(result));
            }
            if Pin::new(&mut self.client).poll(cx).is_ready()
                || self.server.poll_accept(cx).is_ready()
            {
                return Poll::Ready(Err(failed()));
            }
            work.as_mut().poll(cx).map(Ok)
        })
        .await
    }
}

#[derive(Clone, Copy)]
enum Input {
    Empty,
    Data,
    Trailers,
    InvalidTrailers,
    EndedH2,
    EmptyPrefix,
}
struct Case {
    id: &'static str,
    input: Input,
    expected: Option<u64>,
    headers_eos: bool,
    expected_error: Option<io::ErrorKind>,
}
async fn collect(mut body: h2::RecvStream, expected: &[u8]) -> io::Result<Option<HeaderMap>> {
    let mut offset = 0usize;
    while let Some(data) = body.data().await {
        let data = data.map_err(error)?;
        let end = offset.checked_add(data.len()).ok_or_else(failed)?;
        if end > expected.len() || data.as_ref() != &expected[offset..end] {
            return Err(failed());
        }
        offset = end;
        body.flow_control()
            .release_capacity(data.len())
            .map_err(error)?;
    }
    if offset != expected.len() {
        return Err(failed());
    }
    body.trailers().await.map_err(error)
}
async fn case(case: Case) -> io::Result<Value> {
    let budget = Budget::default();
    let live = Arc::new(AtomicUsize::new(0));
    let mut pair = Pair::new(&live).await?;
    let mut source_pair = None;
    let mut source_response = None;
    let mut source_reply = None;
    let mut last_owner = None;
    let result = async {
        let source = if matches!(case.input, Input::EndedH2) {
            let mut origin = Pair::new(&live).await?;
            let (response, upload) = origin
                .sender
                .send_request(
                    Request::builder()
                        .uri("https://source.invalid/empty")
                        .body(())
                        .map_err(error)?,
                    true,
                )
                .map_err(error)?;
            drop(upload);
            let (request, reply) = origin.accept().await?;
            if !request.body().is_end_stream() {
                return Err(failed());
            }
            source_response = Some(response);
            source_reply = Some(reply);
            source_pair = Some(origin);
            Source::h2(request.into_body())
        } else {
            let payload = if matches!(case.input, Input::Data) {
                REQUEST
            } else {
                &[]
            };
            let mut owned =
                BudgetedBytes::new(&budget, payload.len()).ok_or(io::ErrorKind::OutOfMemory)?;
            owned.extend(payload)?;
            let bytes = owned.into_bytes();
            last_owner = Some(bytes.clone());
            let trailers = if matches!(case.input, Input::Trailers | Input::InvalidTrailers) {
                let mut trailers = HeaderMap::new();
                trailers.insert("x-proof", "kept".parse().map_err(error)?);
                if matches!(case.input, Input::InvalidTrailers) {
                    trailers.insert("authorization", "synthetic".parse().map_err(error)?);
                }
                Some(trailers)
            } else {
                None
            };
            let mut source = Source::buffered(bytes, trailers);
            if matches!(case.input, Input::EmptyPrefix) {
                source.prefix = Some(Bytes::new());
            }
            source
        };
        let request = Request::builder()
            .method("POST")
            .uri("https://destination.invalid/submit")
            .body(())
            .map_err(error)?;
        let (response, mut uploaded, upload) =
            start_request(&mut pair.sender, request, source, case.expected, true)?;
        // Deliberately do not poll RequestUpload yet: the peer can only see
        // HEADERS, never a later empty DATA submitted by the relay.
        let gate_before = match uploaded.try_recv() {
            Ok(()) => true,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
            Err(_) => return Err(failed()),
        };
        let (request, mut reply) = pair.accept().await?;
        let headers_eos = request.body().is_end_stream();
        if case.expected_error.is_some() {
            let result = pair.drive(upload.run()).await?;
            let actual_error = result.as_ref().err().map(io::Error::kind);
            let gate_after = uploaded.try_recv().is_ok();
            // The real exchange exits on an upload error before a final head
            // and drops its response future/receive owners; do not join a
            // deliberately unclosed peer upload as if it could complete.
            drop(response);
            drop(request);
            drop(reply);
            return Ok((
                headers_eos,
                gate_before,
                actual_error == case.expected_error && !gate_after,
                actual_error,
            ));
        }
        let expected = if matches!(case.input, Input::Data) {
            REQUEST
        } else {
            &[]
        };
        let receiving = async {
            let trailers = collect(request.into_body(), expected).await?;
            let trailers_ok = if matches!(case.input, Input::Trailers) {
                trailers.as_ref().is_some_and(|t| {
                    t.get("x-proof").is_some_and(|v| v == "kept")
                        && !t.contains_key("authorization")
                })
            } else {
                trailers.is_none()
            };
            if !trailers_ok {
                return Err(failed());
            }
            let mut body = reply
                .send_response(
                    Response::builder()
                        .status(200)
                        .header("content-length", RESPONSE.len())
                        .body(())
                        .map_err(error)?,
                    false,
                )
                .map_err(error)?;
            body.send_data(Bytes::from_static(RESPONSE), true)
                .map_err(error)?;
            Ok::<_, io::Error>(())
        };
        let download = async {
            let response = response.await.map_err(error)?;
            if response.status() != 200 {
                return Err(failed());
            }
            if collect(response.into_body(), RESPONSE).await?.is_some() {
                return Err(failed());
            }
            Ok::<_, io::Error>(())
        };
        let (upload, receiving, download) = pair
            .drive(async { tokio::join!(upload.run(), receiving, download) })
            .await?;
        let gate_after = if gate_before {
            true
        } else {
            uploaded.try_recv().is_ok()
        };
        let result_ok = upload.is_ok() && receiving.is_ok() && download.is_ok() && gate_after;
        Ok::<_, io::Error>((headers_eos, gate_before, result_ok, None))
    }
    .await;
    drop(source_reply);
    drop(source_response);
    drop(source_pair);
    drop(pair);
    let io_released = live.load(Ordering::Acquire) == 0;
    let last_owner_available = last_owner.is_some();
    let last_owner_paid = last_owner_available.then(|| budget.reserve(WORKSPACE).is_none());
    drop(last_owner);
    let refunded = budget.reserve(WORKSPACE).is_some();
    let (headers_eos, gate_before, result_ok, actual_error) = result?;
    Ok(
        json!({"id":case.id,"passed":headers_eos==case.headers_eos && gate_before==case.headers_eos && result_ok && io_released && last_owner_paid.is_none_or(|paid|paid) && refunded,
        "headersEndStreamBeforeUploadPolled":headers_eos,"expectedHeadersEndStream":case.headers_eos,
        "uploadGateReadyBeforeUploadPolled":gate_before,"bodyTrailersOrExpectedErrorCorrect":result_ok,
        "errorKind":actual_error.map(|kind|format!("{kind:?}")),"expectedErrorKind":case.expected_error.map(|kind|format!("{kind:?}")),
        "ioOwnersReleased":io_released,"lastSharedBytesOwnerAvailable":last_owner_available,"lastSharedBytesOwnerStillPaid":last_owner_paid,"lastBodyOwnerRefunded":refunded}),
    )
}

pub(in crate::http_processing) async fn probe() -> io::Result<Value> {
    let cases = [
        Case {
            id: "buffered-empty-unknown-length",
            input: Input::Empty,
            expected: None,
            headers_eos: true,
            expected_error: None,
        },
        Case {
            id: "buffered-empty-zero-length",
            input: Input::Empty,
            expected: Some(0),
            headers_eos: true,
            expected_error: None,
        },
        Case {
            id: "native-h2-ended",
            input: Input::EndedH2,
            expected: None,
            headers_eos: true,
            expected_error: None,
        },
        Case {
            id: "nonempty-binary",
            input: Input::Data,
            expected: Some(REQUEST.len() as u64),
            headers_eos: false,
            expected_error: None,
        },
        Case {
            id: "trailers-validation-preserved",
            input: Input::Trailers,
            expected: Some(0),
            headers_eos: false,
            expected_error: None,
        },
        Case {
            id: "invalid-trailers-still-fail",
            input: Input::InvalidTrailers,
            expected: Some(0),
            headers_eos: false,
            expected_error: Some(io::ErrorKind::InvalidData),
        },
        Case {
            id: "empty-prefix-still-relayed",
            input: Input::EmptyPrefix,
            expected: Some(0),
            headers_eos: false,
            expected_error: None,
        },
        Case {
            id: "truncated-length-still-fails",
            input: Input::Empty,
            expected: Some(1),
            headers_eos: false,
            expected_error: Some(io::ErrorKind::ConnectionAborted),
        },
    ];
    let mut rows = Vec::with_capacity(cases.len());
    for current in cases {
        rows.push(case(current).await?);
    }
    let passed = rows.iter().all(|row| row["passed"] == true);
    Ok(
        json!({"id":"h2-empty-request-headers-eos","passed":passed,"caseCount":rows.len(),"cases":rows,
        "scope":"real duplex H2 and common production start_request/relay; no TLS authentication or network acceptance",
        "backgroundTasksSpawned":false,"externalIO":false}),
    )
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn ended_request_headers_eos_and_upload_gate_preserve_streaming_trailers_and_failure() {
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), super::probe())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["passed"], true, "{result}");
    }
}
