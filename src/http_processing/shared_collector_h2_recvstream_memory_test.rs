// Real H2 RecvStream + shared collector. No TLS/backend or host sockets.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn actual_shared_recvstream_returns_credit_replays_overflow_and_joins() {
    use crate::http_processing::{
        body::{Budget, BudgetedBytes, MAX_BODY, OriginalRequestMeta, Transaction, WireBodyMeta},
        h2_body::{Source, finish, prepare_shared, send_data},
        rules::Phase,
    };
    use hyper::body::Body as _;
    use url::Url;

    for known in [true, false] {
        let length = if known { 128 * 1024 } else { MAX_BODY + 123 };
        let expected_length = known.then_some(length as u64);
        let capacity = if known { length } else { MAX_BODY + 1 };
        let budget = Budget::default();
        let live = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let mut client_owner = None;
        let mut server_owner = None;
        let (client, server) = tokio::io::duplex(8192);
        let client = CountedIo::new(client, &live);
        let server = CountedIo::new(server, &live);
        let observed = timeout(Duration::from_secs(5), async {
            let (mut sender, connection) = ::h2::client::handshake(client)
                .await
                .map_err(|_| failed("real H2 client handshake"))?;
            let client_stop = stop.clone();
            client_owner = Some(tokio::spawn(async move {
                tokio::select! { biased;
                    _ = client_stop.cancelled() => Ok::<_, io::Error>("cancelled"),
                    result = connection => result.map(|_| "protocol-ended")
                        .map_err(|_| failed("real H2 client protocol")),
                }
            }));
            let mut connection = ::h2::server::Builder::new()
                .initial_window_size(32 * 1024)
                .initial_connection_window_size(64 * 1024)
                .handshake::<_, Bytes>(server)
                .await
                .map_err(|_| failed("real H2 server handshake"))?;
            sender = sender
                .ready()
                .await
                .map_err(|_| failed("real H2 request ready"))?;
            let mut request = http::Request::builder()
                .method("POST")
                .uri("https://shared-collector.invalid/body");
            if known {
                request = request.header("content-length", length);
            }
            let request = request.body(()).map_err(|_| failed("real H2 request"))?;
            let (response, mut upload) = sender
                .send_request(request, false)
                .map_err(|_| failed("real H2 request headers"))?;
            let (request, mut reply) = connection
                .accept()
                .await
                .ok_or_else(|| failed("real H2 request missing"))?
                .map_err(|_| failed("real H2 accept"))?;
            let server_stop = stop.clone();
            server_owner = Some(tokio::spawn(async move {
                loop {
                    tokio::select! { biased;
                        _ = server_stop.cancelled() => return Ok::<_, io::Error>("cancelled"),
                        request = connection.accept() => match request {
                            None => return Ok("protocol-ended"),
                            Some(Err(_)) => return Err(failed("real H2 server protocol")),
                            Some(Ok(_)) => return Err(failed("unexpected sibling request")),
                        },
                    }
                }
            }));
            let sending = async {
                send_data(&mut upload, Bytes::from(vec![b'a'; length])).await?;
                let trailers = if known {
                    None
                } else {
                    let mut fields = http::HeaderMap::new();
                    fields.insert("x-final", "kept".parse().map_err(|_| failed("trailer"))?);
                    Some(fields)
                };
                finish(&mut upload, trailers, false)?;
                drop(upload);
                let response = response.await.map_err(|_| failed("response missing"))?;
                if response.status() != http::StatusCode::OK || !response.body().is_end_stream() {
                    return Err(failed("response not complete"));
                }
                Ok::<_, io::Error>(())
            };
            let collecting = async {
                let mut fields = vec![("X-Independent".into(), "kept".into())];
                if known {
                    fields.push(("Content-Length".into(), length.to_string()));
                }
                let before = fields.clone();
                let meta = OriginalRequestMeta::new("POST", &fields);
                let wire =
                    WireBodyMeta::new(&fields, &meta, Phase::Request, None, expected_length, false);
                let url = Url::parse("https://shared-collector.invalid/body")
                    .map_err(|_| failed("test URL"))?;
                let transaction =
                    Transaction::begin_shared(&budget, &[], &url, Phase::Request, &wire, true)
                        .map_err(|_| failed("actual shared collector admission"))?;
                let prepared = prepare_shared(
                    Source::h2(request.into_body()),
                    transaction,
                    expected_length,
                    false,
                    &mut fields,
                )
                .await?;
                let entity_present = prepared.entity.is_some();
                let expected_preserved = prepared.expected == expected_length;
                drop(prepared.entity);
                let mut source = prepared.source;
                let mut received = 0;
                let mut data_correct = true;
                let mut trailer_present = false;
                let mut last_slice = None;
                while let Some(frame) = poll_fn(|cx| Pin::new(&mut source).poll_frame(cx)).await {
                    let frame = frame?;
                    match frame.into_data() {
                        Ok(data) => {
                            received += data.len();
                            data_correct &= data.iter().all(|byte| *byte == b'a');
                            if last_slice.is_none() && !data.is_empty() {
                                last_slice = Some(data.slice(..1));
                            }
                        }
                        Err(frame) => {
                            if let Ok(fields) = frame.into_trailers() {
                                trailer_present =
                                    fields.get("x-final").is_some_and(|value| value == "kept");
                            }
                        }
                    }
                }
                drop(source);
                reply
                    .send_response(http::Response::new(()), true)
                    .map_err(|_| failed("response headers"))?;
                Ok::<_, io::Error>((
                    entity_present,
                    expected_preserved,
                    fields == before,
                    received,
                    data_correct,
                    trailer_present,
                    last_slice,
                ))
            };
            let (_, facts) = tokio::try_join!(sending, collecting)?;
            drop(sender);
            Ok::<_, io::Error>(facts)
        })
        .await;

        // All paths cancel and actually join both H2/duplex owners first.
        // The retained Bytes below owns only paid body backing, not protocol IO.
        stop.cancel();
        let server_join = match server_owner {
            Some(owner) => Some(joined(owner).await),
            None => None,
        };
        let client_join = match client_owner {
            Some(owner) => Some(joined(owner).await),
            None => None,
        };
        assert!(matches!(&server_join, Some(Ok(Ok(_)))), "{server_join:?}");
        assert!(matches!(&client_join, Some(Ok(Ok(_)))), "{client_join:?}");
        assert_eq!(live.load(Ordering::Acquire), 0);
        let facts = observed
            .expect("fixed memory harness deadline")
            .expect("actual shared collection and wire transfer");
        let (entity, expected, fields, received, data, trailers, last) = facts;
        assert_eq!(entity, known);
        assert!(expected && fields && data);
        assert_eq!(received, length);
        assert_eq!(trailers, !known);
        let last = last.expect("real source DATA retains a paid raw slice");
        assert_eq!(last.as_ref(), b"a");
        assert_eq!(
            budget.used(),
            BudgetedBytes::allocation_cost(capacity).unwrap()
        );
        drop(last);
        assert_eq!(budget.used(), 0);
    }
}
