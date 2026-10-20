//! HTTP/3 over caller-owned Quinn and the controlled datagram seam.
use super::{ConnectionGuard, DriverOwner, SendRequest, connection_closed};
use crate::{
    dispatch::{DatagramBudget, DatagramTransport},
    transport::{
        quic::{self, OwnedRuntime},
        quinn_h3,
    },
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::oneshot, time::Instant};
use tokio_util::sync::CancellationToken;

pub(crate) struct QuicTransport {
    pub transport: Box<dyn DatagramTransport>,
    pub peer: SocketAddr,
    pub budget: DatagramBudget,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: String,
}

#[derive(Clone, Debug)]
pub(super) struct Sender {
    pub requests: quinn_h3::Client,
    pub runtime: Arc<OwnedRuntime>,
    #[cfg(feature = "interop-test")]
    pub observation: quinn::Connection,
}

pub(super) async fn connect(
    raw: QuicTransport,
    keepalive: i32,
    owner: &DriverOwner,
) -> io::Result<(SendRequest, Arc<ConnectionGuard>)> {
    let cancel = owner.cancellation.child_token();
    let stop = cancel.clone();
    let (ready, response) = oneshot::channel();
    let guard = owner.spawn_managed(
        async move {
            // Native IO remains alive during retirement; only its owner cancels
            // and joins it after the bounded close exchange.
            let runtime = Arc::new(OwnedRuntime::new(CancellationToken::new()));
            let QuicTransport {
                transport,
                peer,
                budget,
                tls,
                server_name,
            } = raw;
            let mut upstream = Some(transport);
            let mut ready = Some(ready);
            let mut datagram = None;
            let mut endpoint = None;
            let mut close_deadline = None;
            let prepared = async {
                let mut tls = (*tls).clone();
                tls.resumption = rustls::client::Resumption::disabled();
                tls.enable_early_data = false;
                let crypto =
                    quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(failure)?;
                if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                // Validate before transferring upstream ownership to attach.
                budget
                    .intersect(upstream.as_ref().unwrap().payload_budget(&peer.into()))
                    .quic_payload_limit()?;
                let (socket, driver) =
                    quic::attach_quinn(upstream.take().unwrap(), peer, budget).await?;
                datagram = Some(driver);
                let path = socket.budget();
                path.quic_payload_limit()?;
                let mut discovery = quinn::MtuDiscoveryConfig::default();
                discovery.upper_bound(path.transmit());
                let mut limits = quinn::TransportConfig::default();
                socket.configure_transport(&mut limits);
                limits
                    .initial_mtu(crate::dispatch::QUIC_MIN_PAYLOAD_BYTES)
                    .min_mtu(crate::dispatch::QUIC_MIN_PAYLOAD_BYTES)
                    .mtu_discovery_config(Some(discovery))
                    .max_concurrent_bidi_streams(0_u8.into())
                    .max_concurrent_uni_streams((crate::limits::XHTTP_H3_UNI_STREAMS as u32).into())
                    .stream_receive_window((crate::limits::XHTTP_H3_STREAM_WINDOW as u32).into())
                    .receive_window((crate::limits::XHTTP_H3_CONNECTION_WINDOW as u32).into())
                    .send_window(crate::limits::XHTTP_H3_SEND_WINDOW as u64)
                    .datagram_receive_buffer_size(None)
                    .datagram_send_buffer_size(0)
                    .max_idle_timeout(Some(Duration::from_secs(300).try_into().map_err(failure)?))
                    .keep_alive_interval((keepalive >= 0).then(|| {
                        Duration::from_secs(if keepalive == 0 { 10 } else { keepalive as u64 })
                    }));
                let mut client = quinn::ClientConfig::new(Arc::new(crypto));
                client.transport_config(Arc::new(limits));
                let mut config = quinn::EndpointConfig::default();
                config
                    .max_udp_payload_size(path.receive())
                    .map_err(failure)?;
                let mut native = quinn::Endpoint::new_with_abstract_socket(
                    config,
                    None,
                    socket.clone(),
                    runtime.clone(),
                )?;
                native.set_default_client_config(client);
                endpoint = Some(native);
                let connection = endpoint
                    .as_ref()
                    .unwrap()
                    .connect(peer, &server_name)
                    .map_err(failure)?
                    .await
                    .map_err(failure)?;
                let handshake = connection
                    .handshake_data()
                    .ok_or_else(connection_closed)?
                    .downcast::<quinn::crypto::rustls::HandshakeData>()
                    .map_err(|_| connection_closed())?;
                if handshake.protocol.as_deref() != Some(b"h3") {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // rustls rejects an unaccepted ECH offer at Finished processing.
                let (requests, control) = quinn_h3::attach(
                    connection.clone(),
                    u64::from(super::MAX_H2_HEADER_LIST_SIZE),
                )
                .await
                .map_err(failure)?;
                Ok::<_, io::Error>((connection, requests, control, socket))
            };
            let prepared = tokio::select! {biased;
                () = stop.cancelled() => Err(connection_closed()),
                result = prepared => result,
            };
            let error = match prepared {
                Ok((connection, requests, mut control, socket)) => {
                    // h3 closes native QUIC when its last sender is dropped.
                    // Keep a sender until retirement IO has finished.
                    let keep_requests = requests.clone();
                    let published = ready
                        .take()
                        .unwrap()
                        .send(Ok(Sender {
                            requests,
                            runtime: runtime.clone(),
                            #[cfg(feature = "interop-test")]
                            observation: connection.clone(),
                        }))
                        .is_ok();
                    if published {
                        let retiring = tokio::select! {biased;
                            () = stop.cancelled() => true,
                            _ = control.wait_idle() => false,
                        };
                        if retiring {
                            keep_requests.retire();
                            let deadline = Instant::now() + quic::CLOSE_TIMEOUT;
                            close_deadline = Some(deadline);
                            retire_io(&mut control, &connection, &socket, deadline).await;
                        }
                    }
                    drop(keep_requests);
                    None
                }
                Err(error) => Some(error),
            };
            if let Some(endpoint) = endpoint {
                let deadline =
                    close_deadline.unwrap_or_else(|| Instant::now() + quic::CLOSE_TIMEOUT);
                endpoint.close(0_u8.into(), b"");
                let _ = tokio::time::timeout_at(deadline, endpoint.wait_idle()).await;
            }
            runtime.stop().await;
            if let Some(driver) = datagram {
                let _ = driver.stop().await;
            }
            if let Some(mut upstream) = upstream {
                let _ = tokio::time::timeout(quic::CLOSE_TIMEOUT, upstream.close()).await;
            }
            if let Some(ready) = ready {
                let _ = ready.send(Err(error.unwrap_or_else(connection_closed)));
            }
        },
        cancel,
    )?;
    let sender = response.await.map_err(|_| connection_closed())??;
    Ok((SendRequest::H3(sender), Arc::new(guard)))
}

pub(super) fn failure(_: impl std::fmt::Display) -> io::Error {
    io::Error::other("XHTTP HTTP/3 exchange failed")
}

// Follow real upstream TX progress while retaining native/H3 ownership. Keep
// room for CONNECTION_CLOSE within the original deadline; no ACK is inferred
// from quiet time, and stalled/continuously busy paths still stop at that bound.
async fn retire_io(
    control: &mut quinn_h3::ControlDriver,
    connection: &quinn::Connection,
    socket: &quic::DatagramSocket,
    deadline: Instant,
) {
    let grace = || {
        connection
            .rtt()
            .saturating_mul(2)
            .saturating_add(Duration::from_millis(25))
            .min(quic::CLOSE_TIMEOUT)
    };
    let mut sent = socket.stats().sent;
    let mut quiet = (Instant::now() + grace()).min(deadline);
    loop {
        let now = Instant::now();
        let actual = socket.stats().sent;
        if actual != sent {
            sent = actual;
            quiet = (now + grace()).min(deadline);
        }
        if now >= quiet || now >= deadline {
            return;
        }
        // A local timer avoids replacing Quinn's writer AtomicWaker with a
        // second poll_transmitted waiter; no extra task or packet queue.
        let check = (now + Duration::from_millis(10)).min(quiet).min(deadline);
        tokio::select! {biased;
            _ = control.wait_idle() => return,
            _ = connection.closed() => return,
            () = tokio::time::sleep_until(check) => {},
        }
    }
}
