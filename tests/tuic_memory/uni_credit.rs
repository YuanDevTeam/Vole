//! Actual TUIC UDP-lane UNI credit over bounded memory packets.
use super::*;

#[cfg(target_os = "macos")]
#[tokio::test]
async fn quic_udp_advertised_uni_credit_is_128_and_recycles_at_17() {
    #[derive(Debug, Default)]
    struct CreditObservation {
        admitted: usize,
        remote_bidi_refused: bool,
        initial_129_pending: bool,
        after_16_pending: usize,
        replenished_batches: usize,
        replenished_streams: usize,
        final_129_pending: bool,
        all_steps_completed: bool,
    }

    let (mut config, packets, endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    // Keep owner admission independent of remotely initiated stream credit.
    config.max_open_streams = i64::MAX as usize - 1;
    let outbound = TuicOutbound::new_with_path(
        &config,
        UpstreamPath::proxy(Arc::new(MemoryUpstream(Mutex::new(Some(packets))))),
    )
    .unwrap();
    let ep = endpoint.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let mut peer = tokio::spawn(async move {
        // This existing helper verifies the unchanged authentication fixture;
        // none of the intended C8 semantic RED paths assert inside the peer.
        let connection = authenticated(&ep).await;
        let mut observed = CreditObservation::default();
        let mut held = VecDeque::new();
        // Keep the entire credit observation below the original decoder TTL,
        // so a slow observation cannot borrow credits from five-second expiry.
        let completed = tokio::time::timeout(Duration::from_secs(3), async {
            observed.remote_bidi_refused =
                tokio::time::timeout(Duration::from_millis(50), connection.open_bi())
                    .await
                    .is_err();
            if !observed.remote_bidi_refused {
                return Err(());
            }
            // Independent expected contract, never read the implementation's
            // advertised-credit or decoder constants to manufacture a PASS.
            // One total admission deadline bounds the old C8 RED at open 33;
            // it cannot wait 128 times for a per-stream timeout.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            for _ in 0..128 {
                let stream = tokio::time::timeout_at(deadline, connection.open_uni())
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                held.push_back(stream);
                observed.admitted += 1;
            }
            observed.initial_129_pending =
                tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                    .await
                    .is_err();
            if !observed.initial_129_pending {
                return Err(());
            }
            // No stream data was sent before the 128/129 boundary check.
            // Receiving the highest ID now implicitly opens all earlier gaps.
            tokio::time::timeout(
                Duration::from_secs(1),
                held.back_mut().ok_or(())?.write_all(&[5]),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;

            // Exact Quinn batches MAX_STREAMS only after more than C/8 have
            // been freed. For C=128, 16 is insufficient and the 17th releases
            // one bounded batch. Two cycles prove recycling without a grid.
            for _ in 0..2 {
                for _ in 0..16 {
                    let mut stream = held.pop_front().ok_or(())?;
                    stream.finish().map_err(|_| ())?;
                }
                let pending =
                    tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                        .await
                        .is_err();
                if !pending {
                    return Err(());
                }
                observed.after_16_pending += 1;
                let mut stream = held.pop_front().ok_or(())?;
                stream.finish().map_err(|_| ())?;
                drop(stream);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                for _ in 0..17 {
                    let mut next = tokio::time::timeout_at(deadline, connection.open_uni())
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    tokio::time::timeout_at(deadline, next.write_all(&[5]))
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                    held.push_back(next);
                    observed.replenished_streams += 1;
                }
                observed.replenished_batches += 1;
            }
            observed.final_129_pending =
                tokio::time::timeout(Duration::from_millis(100), connection.open_uni())
                    .await
                    .is_err();
            if !observed.final_129_pending {
                return Err(());
            }
            Ok::<(), ()>(())
        })
        .await;
        observed.all_steps_completed = matches!(completed, Ok(Ok(())));
        // The expected old-source failure drops all held send owners, reports
        // its false observations, then waits for the real parent-owned close.
        drop(held);
        let _ = ready.send(observed);
        connection.closed().await;
    });
    let probe = ResourceProbe::default();
    let (opened, observed, stopped) = probe
        .scope(async {
            let opened = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await;
            let was_opened = opened.is_ok();
            // Covers both 2-second credit waits and the fixed finite checks.
            let observed = tokio::time::timeout(Duration::from_secs(8), wait)
                .await
                .ok()
                .and_then(Result::ok);
            outbound.begin_shutdown();
            drop(opened);
            endpoint.close(0_u8.into(), b"");
            let stopped = tokio::time::timeout(Duration::from_secs(2), outbound.shutdown())
                .await
                .is_ok();
            (was_opened, observed, stopped)
        })
        .await;
    // Do not use the original finish() helper here: its join unwrap precedes
    // endpoint.wait_idle, while this RED control must attempt every join first.
    let peer_joined = match tokio::time::timeout(Duration::from_secs(2), &mut peer).await {
        Ok(result) => result.is_ok(),
        Err(_) => {
            peer.abort();
            let _ = peer.await;
            false
        }
    };
    let endpoint_idle = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .is_ok();
    drop(endpoint);
    drop(outbound);
    let resources_idle = probe.snapshot().is_idle();
    // Every expected semantic RED assertion happens after owned closure.
    assert!(
        opened && stopped && peer_joined && endpoint_idle && resources_idle,
        "actual fixture/Stop/peer/endpoint closure failed: {:?}",
        probe.snapshot()
    );
    let observed = observed.expect("joined peer did not publish its bounded observation");
    assert!(
        observed.remote_bidi_refused
            && observed.admitted == 128
            && observed.initial_129_pending
            && observed.after_16_pending == 2
            && observed.replenished_batches == 2
            && observed.replenished_streams == 34
            && observed.final_129_pending
            && observed.all_steps_completed,
        "actual UDP-lane UNI permission must be 128 with bounded 17-credit recycling: {observed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn quic_udp_uni_credit_keeps_32_decoders_and_original_admission_ttl() {
    let (mut config, udp_path, endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    let (_, tcp_path, tcp_endpoint) = fixture_parts(1400, true, 8, "cubic", "quic");
    config.disable_mtu_discovery = true;
    let paths = Arc::new(Paths(Mutex::new(VecDeque::from([udp_path, tcp_path]))));
    let outbound = TuicOutbound::new_with_path(&config, UpstreamPath::proxy(paths)).unwrap();
    let ep = endpoint.clone();
    let (ready, wait) = tokio::sync::oneshot::channel();
    let (wave, wave_wait) = tokio::sync::oneshot::channel();
    let mut peer = tokio::spawn(async move {
        let connection = authenticated(&ep).await;
        let setup = tokio::time::timeout(Duration::from_secs(2), async {
            // The real outbound first packet proves association zero exists.
            let mut first = connection.accept_uni().await.map_err(|_| ())?;
            let first = first.read_to_end(64).await.map_err(|_| ())?;
            if first.get(..4) != Some(b"\x05\x02\x00\x00".as_slice()) {
                return Err(());
            }
            let mut partial = Vec::new();
            for packet in 0..32_u16 {
                let mut stream = connection.open_uni().await.map_err(|_| ())?;
                let mut header =
                    b"\x05\x02\x00\x00\x00\x00\x01\x00\x00\x01\x00\x01x\x00\x50".to_vec();
                header[4..6].copy_from_slice(&packet.to_be_bytes());
                stream.write_all(&header).await.map_err(|_| ())?;
                // Valid association/address, declared one-byte body absent.
                partial.push(stream);
            }
            let mut marker = connection.open_uni().await.map_err(|_| ())?;
            marker
                .write_all(b"\x05\x02\x00\x00\x00\x20\x01\x00\x00\x01\x00\x01x\x00\x50m")
                .await
                .map_err(|_| ())?;
            marker.finish().map_err(|_| ())?;
            // Same-connection receipt barrier, not application consumption:
            // FIN plus all marker bytes must be ACKed before ready is true.
            // This is covered by the original two-second setup deadline.
            if !matches!(marker.stopped().await, Ok(None)) {
                return Err(());
            }
            Ok::<_, ()>(partial)
        })
        .await;
        match setup {
            Ok(Ok(partial)) => {
                let _ = ready.send(true);
                // One shared deadline across the whole first wave. Sequential
                // per-stream six-second budgets would hide extra TTL waves.
                let stopped = tokio::time::timeout(Duration::from_secs(6), async {
                    for stream in &partial {
                        if !matches!(stream.stopped().await, Ok(Some(code)) if code == 0_u8.into())
                        {
                            return false;
                        }
                    }
                    true
                })
                .await
                .unwrap_or(false);
                let _ = wave.send(stopped);
                // Answer STOP via normal peer owner release; no fake FIN ACK.
                drop(partial);
            }
            _ => {
                // Old C8 reaches its 33rd-open timeout here. Keep a semantic
                // false result, then allow the parent to close every owner.
                let _ = ready.send(false);
                let _ = wave.send(false);
            }
        }
        connection.closed().await;
    });
    let tcp_ep = tcp_endpoint.clone();
    let mut tcp_peer = tokio::spawn(async move {
        let connection = authenticated(&tcp_ep).await;
        let echoed = tokio::time::timeout(Duration::from_secs(4), async {
            let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| ())?;
            let mut request = [0; 8];
            recv.read_exact(&mut request).await.map_err(|_| ())?;
            if &request != b"\x05\x01\x00\x01x\x00\x50a" {
                return Err(());
            }
            send.write_all(b"a").await.map_err(|_| ())?;
            Ok::<_, ()>(())
        })
        .await;
        connection.closed().await;
        matches!(echoed, Ok(Ok(())))
    });
    let probe = ResourceProbe::default();
    let facts = probe
        .scope(async {
            let mut udp = outbound
                .open_datagram(udp_request(), &EstablishContext::default())
                .await
                .ok();
            let sent = if let Some(udp) = &mut udp {
                udp.send(Datagram {
                    remote: request().destination,
                    payload: bytes::Bytes::from_static(b"start"),
                    sniffed_domain: None,
                })
                .await
                .is_ok()
            } else {
                false
            };
            let prepared = tokio::time::timeout(Duration::from_secs(3), wait)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false);
            let mut early_pending = false;
            if prepared && let Some(udp) = &mut udp {
                early_pending = tokio::time::timeout(Duration::from_millis(100), udp.receive())
                    .await
                    .is_err();
            }
            // Check UDP blocking first. All TCP establishment/write/echo work
            // has one budget, so it cannot consume the first five-second TTL.
            let tcp_attempt = tokio::time::timeout(Duration::from_secs(1), async {
                let mut tcp = outbound
                    .connect_stream(
                        request(),
                        &EstablishContext::with_timeout(Duration::from_secs(1)),
                    )
                    .await
                    .map_err(|_| ())?
                    .io;
                tcp.write_all(b"a").await.map_err(|_| ())?;
                if tcp.read_u8().await.map_err(|_| ())? != b'a' {
                    return Err(());
                }
                Ok::<_, ()>(tcp)
            })
            .await;
            let (tcp, tcp_echo) = match tcp_attempt {
                Ok(Ok(tcp)) => (Some(tcp), true),
                _ => (None, false),
            };
            let mut marker_delivered = false;
            if early_pending && let Some(udp) = &mut udp {
                marker_delivered = matches!(
                    tokio::time::timeout(Duration::from_secs(6), udp.receive()).await,
                    Ok(Ok(packet)) if packet.payload.as_ref() == b"m"
                );
            }
            let first_wave = tokio::time::timeout(Duration::from_secs(7), wave_wait)
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false);
            outbound.begin_shutdown();
            drop(udp);
            drop(tcp);
            endpoint.close(0_u8.into(), b"");
            tcp_endpoint.close(0_u8.into(), b"");
            let stopped = tokio::time::timeout(Duration::from_secs(2), outbound.shutdown())
                .await
                .is_ok();
            (
                sent,
                prepared,
                tcp_echo,
                early_pending,
                marker_delivered,
                first_wave,
                stopped,
            )
        })
        .await;
    let peer_joined = match tokio::time::timeout(Duration::from_secs(2), &mut peer).await {
        Ok(result) => result.is_ok(),
        Err(_) => {
            peer.abort();
            let _ = peer.await;
            false
        }
    };
    let tcp_joined = match tokio::time::timeout(Duration::from_secs(2), &mut tcp_peer).await {
        Ok(result) => result.unwrap_or(false),
        Err(_) => {
            tcp_peer.abort();
            let _ = tcp_peer.await;
            false
        }
    };
    let idle = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle())
        .await
        .is_ok();
    let tcp_idle = tokio::time::timeout(Duration::from_secs(2), tcp_endpoint.wait_idle())
        .await
        .is_ok();
    drop((endpoint, tcp_endpoint, outbound));
    assert!(
        facts.6 && peer_joined && tcp_joined && idle && tcp_idle && probe.snapshot().is_idle(),
        "all real fixture owners must close before semantic assertions: {facts:?}"
    );
    assert!(
        facts.0 && facts.1 && facts.2 && facts.3 && facts.4 && facts.5,
        "the 33rd complete packet must wait for the original first 32 decoder TTLs: {facts:?}"
    );
}
