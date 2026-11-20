//! Real TUIC authentication, Connect and UoT over the existing bounded memory peer.
use super::*;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
struct Evidence {
    tags: [u8; 9],
    pools_before_retirement: usize,
    pools_with_retired: usize,
    pools_with_one_old_owner: usize,
    pools_after_old_owners: usize,
    remaining_paths: usize,
}

#[derive(Debug)]
struct Case {
    mode: &'static str,
    evidence: Result<Evidence, String>,
    stopped_reads: bool,
    stop_elapsed: Duration,
    probe_idle: bool,
    peers_joined: bool,
    endpoints_idle: bool,
}

// Independent bounded wire peer. Every response includes its physical path tag;
// no lane index, pointer equality or production selection helper is consulted.
async fn echo_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    tag: u8,
) -> Result<(), String> {
    let mut prefix = [0; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|e| e.to_string())?;
    if prefix[..3] != [5, 1, 0] || usize::from(prefix[3]) > 32 {
        return Err("invalid TUIC Connect prefix".into());
    }
    let mut target = [0; 34];
    let length = usize::from(prefix[3]) + 2;
    recv.read_exact(&mut target[..length])
        .await
        .map_err(|e| e.to_string())?;
    let uot = if &target[..length] == b"x\0P" {
        false
    } else if &target[..length] == b"sp.v2.udp-over-tcp.arpa\0\0" {
        true
    } else {
        return Err("unexpected Connect target".into());
    };
    if uot {
        let mut request = [0; 8];
        recv.read_exact(&mut request)
            .await
            .map_err(|e| e.to_string())?;
        if request != [0, 1, 1, 2, 3, 4, 0, 53] {
            return Err("invalid UoT datagram-mode request".into());
        }
    }
    let mut first = [0; 1];
    while let Ok(Some(1)) = recv.read(&mut first).await {
        if uot {
            let mut rest = [0; 9];
            recv.read_exact(&mut rest)
                .await
                .map_err(|e| e.to_string())?;
            if first[0] != 0 || rest[..8] != [1, 2, 3, 4, 0, 53, 0, 1] {
                return Err("invalid bounded UoT frame".into());
            }
            send.write_all(&[0, 1, 2, 3, 4, 0, 53, 0, 2, tag, rest[8]])
                .await
                .map_err(|e| e.to_string())?;
        } else {
            send.write_all(&[tag, first[0]])
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    let _ = send.finish();
    Ok(())
}

fn serve(
    endpoint: quinn::Endpoint,
    tag: u8,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        // The shared helper checks the UUID and the exporter from this actual
        // TLS connection before any application response can be produced.
        let connection = tokio::select! { biased;
            () = stop.cancelled() => return Ok(()),
            connection = authenticated(&endpoint) => connection,
        };
        let mut streams = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                () = stop.cancelled() => {
                    connection.close(0_u8.into(), b"");
                    break;
                }
                _ = connection.closed() => break,
                stream = connection.accept_bi() => {
                    let Ok((send, recv)) = stream else { break; };
                    streams.spawn(echo_stream(send, recv, tag));
                }
            }
        }
        let mut result = Ok(());
        while let Some(joined) = streams.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => result = Err(error),
                Err(error) => result = Err(error.to_string()),
            }
        }
        result
    })
}

async fn tcp_echo(stream: &mut vole::dispatch::BoxStream, byte: u8) -> Result<u8, String> {
    stream.write_all(&[byte]).await.map_err(|e| e.to_string())?;
    let mut reply = [0; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| e.to_string())?;
    if reply[1] != byte {
        return Err("TCP payload changed".into());
    }
    Ok(reply[0])
}

async fn uot_echo(stream: &mut Box<dyn DatagramTransport>, byte: u8) -> Result<u8, String> {
    stream
        .send(Datagram {
            remote: Destination::Ip("1.2.3.4:53".parse().unwrap()),
            payload: bytes::Bytes::copy_from_slice(&[byte]),
            sniffed_domain: None,
        })
        .await
        .map_err(|e| e.to_string())?;
    let reply = stream.receive().await.map_err(|e| e.to_string())?;
    if reply.remote != Destination::Ip("1.2.3.4:53".parse().unwrap())
        || reply.payload.len() != 2
        || reply.payload[1] != byte
    {
        return Err("UoT payload or reply source changed".into());
    }
    Ok(reply.payload[0])
}

async fn exercise(
    outbound: &TuicOutbound,
    paths: &Paths,
    probe: &ResourceProbe,
) -> Result<
    (
        Evidence,
        vole::dispatch::BoxStream,
        Box<dyn DatagramTransport>,
    ),
    String,
> {
    let context = EstablishContext::with_timeout(Duration::from_secs(2));
    let mut tcp = outbound
        .connect_stream(request(), &context)
        .await
        .map_err(|e| e.to_string())?
        .io;
    let tcp_tag = tcp_echo(&mut tcp, b'a').await?;
    let mut first = outbound
        .open_datagram(udp_request(), &EstablishContext::default())
        .await
        .map_err(|e| e.to_string())?;
    let first_tag = uot_echo(&mut first, b'p').await?;
    let mut held = outbound
        .open_datagram(udp_request(), &EstablishContext::default())
        .await
        .map_err(|e| e.to_string())?;
    let held_tag = uot_echo(&mut held, b'q').await?;
    let mut third = outbound
        .open_datagram(udp_request(), &EstablishContext::default())
        .await
        .map_err(|e| e.to_string())?;
    let third_tag = uot_echo(&mut third, b'v').await?;
    let pools_before_retirement = probe.snapshot().current(ResourceKind::Pool);
    let mut fresh = outbound
        .open_datagram(udp_request(), &EstablishContext::default())
        .await
        .map_err(|e| e.to_string())?;
    let fresh_tag = uot_echo(&mut fresh, b'r').await?;
    let pools_with_retired = probe.snapshot().current(ResourceKind::Pool);
    // New TCP after UoT retirement must still reuse the original TCP lane.
    let mut sibling = outbound
        .connect_stream(request(), &EstablishContext::default())
        .await
        .map_err(|e| e.to_string())?
        .io;
    let sibling_tag = tcp_echo(&mut sibling, b'x').await?;
    drop(sibling);
    let old_tag = uot_echo(&mut first, b's').await?;
    let tcp_after = tcp_echo(&mut tcp, b'b').await?;
    held.close().await.map_err(|e| e.to_string())?;
    drop(held);
    third.close().await.map_err(|e| e.to_string())?;
    drop(third);
    let pools_with_one_old_owner = probe.snapshot().current(ResourceKind::Pool);
    let after_sibling_close = uot_echo(&mut first, b't').await?;
    first.close().await.map_err(|e| e.to_string())?;
    drop(first);
    // Allow the existing five-second FIN ownership ceiling; do not assume that
    // local shutdown is immediate peer ACK or change the production grace.
    tokio::time::timeout(Duration::from_secs(6), async {
        while probe.snapshot().current(ResourceKind::Pool) > 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "retired owner did not release".to_owned())?;
    Ok((
        Evidence {
            tags: [
                tcp_tag,
                first_tag,
                held_tag,
                third_tag,
                sibling_tag,
                fresh_tag,
                old_tag,
                tcp_after,
                after_sibling_close,
            ],
            pools_before_retirement,
            pools_with_retired,
            pools_with_one_old_owner,
            pools_after_old_owners: probe.snapshot().current(ResourceKind::Pool),
            remaining_paths: paths.0.lock().unwrap().len(),
        },
        tcp,
        fresh,
    ))
}

async fn case(mode: &'static str) -> Case {
    let (mut config, tcp_path, tcp_ep) = fixture_parts(1400, true, 8, "cubic", mode);
    let (_, uot_path, uot_ep) = fixture_parts(1400, true, 8, "cubic", mode);
    let (_, fresh_path, fresh_ep) = fixture_parts(1400, true, 8, "cubic", mode);
    config.udp_over_stream = true;
    config.disable_mtu_discovery = true;
    // Three owners let the legacy shared pool complete every operation too;
    // only observed connection tags/counts should produce its semantic RED.
    config.max_open_streams = 3;
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([
        tcp_path, uot_path, fresh_path,
    ]))));
    let outbound =
        TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths.clone())).unwrap();
    let endpoints = [tcp_ep, uot_ep, fresh_ep];
    let peer_stop = CancellationToken::new();
    let peers: Vec<_> = endpoints
        .iter()
        .enumerate()
        .map(|(tag, ep)| serve(ep.clone(), tag as u8, peer_stop.clone()))
        .collect();
    let probe = ResourceProbe::default();
    let (evidence, stopped_reads, stop_elapsed, probe_idle) = probe
        .scope(async {
            // The baseline shared implementation can perform the same complete
            // workload. Its RED is the observed tags/counts after all cleanup.
            let mut outcome =
                tokio::time::timeout(Duration::from_secs(12), exercise(&outbound, &paths, &probe))
                    .await
                    .map_err(|_| "client exercise deadline".to_owned())
                    .and_then(|v| v);
            let before = tokio::time::Instant::now();
            outbound.shutdown().await;
            let stop_elapsed = before.elapsed();
            let stopped_reads = if let Ok((_, tcp, fresh)) = &mut outcome {
                let tcp_stopped = tokio::time::timeout(Duration::from_secs(1), tcp.read_u8())
                    .await
                    .is_ok_and(|v| v.is_err());
                let uot_stopped = tokio::time::timeout(Duration::from_secs(1), fresh.receive())
                    .await
                    .is_ok_and(|v| v.is_err());
                tcp_stopped && uot_stopped
            } else {
                false
            };
            let evidence = outcome.map(|(evidence, tcp, fresh)| {
                drop((tcp, fresh));
                evidence
            });
            (
                evidence,
                stopped_reads,
                stop_elapsed,
                probe.snapshot().is_idle(),
            )
        })
        .await;
    for endpoint in &endpoints {
        endpoint.close(0_u8.into(), b"");
    }
    peer_stop.cancel();
    let mut peers_joined = true;
    for peer in peers {
        peers_joined &= matches!(peer.await, Ok(Ok(())));
    }
    let mut endpoints_idle = true;
    for endpoint in &endpoints {
        endpoints_idle &= tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
            .await
            .is_ok();
    }
    drop((endpoints, outbound, paths));
    Case {
        mode,
        evidence,
        stopped_reads,
        stop_elapsed,
        probe_idle,
        peers_joined,
        endpoints_idle,
    }
}

#[tokio::test]
async fn tuic_uot_lane_reuses_each_class_retires_with_old_owners_and_joins_stop() {
    // Both modes complete and stop before the first verdict, including RED.
    let cases = [case("native").await, case("quic").await];
    for case in cases {
        assert!(case.peers_joined && case.endpoints_idle, "{case:?}");
        assert!(case.probe_idle && case.stopped_reads, "{case:?}");
        assert!(case.stop_elapsed < Duration::from_secs(2), "{case:?}");
        let evidence = case.evidence.as_ref().expect("completed memory exchange");
        assert_eq!(
            evidence.tags,
            [0, 1, 1, 1, 0, 2, 1, 0, 1],
            "mode={}",
            case.mode
        );
        assert_eq!(evidence.pools_before_retirement, 2);
        assert_eq!(evidence.pools_with_retired, 3);
        assert_eq!(evidence.pools_with_one_old_owner, 3);
        assert_eq!(evidence.pools_after_old_owners, 2);
        assert_eq!(evidence.remaining_paths, 0);
    }
}
