use super::{
    datagram::{Registry, local_destination},
    engine::Ready,
};
use crate::{
    config::WireGuardOutboundConfig,
    dispatch::{DatagramBudget, DatagramTransport, DispatchError},
    outbound::{DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest, EstablishContext, UpstreamPath},
    session::{Datagram, DatagramSession, Destination},
};
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519,
};
use bytes::Bytes;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use vole_netstack::{Packet, PacketSink, parse_udp_packet_view};

#[allow(clippy::too_many_arguments)]
pub(super) async fn drive(
    config: Arc<WireGuardOutboundConfig>,
    server: Destination,
    upstream: UpstreamPath,
    session: DatagramSession,
    context: EstablishContext,
    cancel: CancellationToken,
    mut packets: mpsc::Receiver<Packet>,
    ready: watch::Sender<Ready>,
    sink: PacketSink,
    registry: Arc<Registry>,
) {
    let wire_size = config.mtu + 32;
    let request =
        DatagramRequest::new(session).with_budget(DatagramBudget::new(wire_size, wire_size));
    let setup = async {
        let server = upstream.datagram_server(&server, &context).await?;
        let endpoint = context
            .resolution()
            .resolve_proxy(&server, context.deadline())
            .await?
            .addresses
            .into_iter()
            .next()
            .ok_or(DispatchError::HostUnreachable)?;
        let transport = upstream.open_datagram(request, &context).await?;
        Ok((endpoint, transport))
    };
    let result = tokio::select! {biased;()=cancel.cancelled()=>Err(DispatchError::NotAllowed),result=context.run("WireGuard outer UDP",setup)=>result};
    if let Ok((endpoint, mut transport)) = result {
        let budget = transport.payload_budget(&Destination::Ip(endpoint));
        if budget.transmit() >= wire_size && budget.receive() >= wire_size {
            let mut tunn = Tunn::new(
                x25519::StaticSecret::from(config.private_key.bytes()),
                x25519::PublicKey::from(config.public_key.bytes()),
                config.pre_shared_key.as_ref().map(|key| key.bytes()),
                Some(config.persistent_keepalive),
                rand::random::<u32>() >> 8,
                None,
            );
            let mut scratch = vec![0; usize::from(wire_size).max(148)];
            let initial = tunn.format_handshake_initiation(&mut scratch, true);
            let initial = handle(
                initial,
                &config,
                endpoint,
                transport.as_mut(),
                &cancel,
                context.deadline(),
                &sink,
                &registry,
            )
            .await;
            if initial.is_ok() {
                let _ = run_peer(
                    &mut tunn,
                    &config,
                    endpoint,
                    transport.as_mut(),
                    &cancel,
                    &context,
                    &mut packets,
                    &ready,
                    &sink,
                    &registry,
                    &mut scratch,
                )
                .await;
            }
        }
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), transport.close()).await;
    }
    ready.send_replace(Ready::Failed);
    cancel.cancel();
}

#[allow(clippy::too_many_arguments)]
async fn run_peer(
    tunn: &mut Tunn,
    config: &WireGuardOutboundConfig,
    endpoint: SocketAddr,
    transport: &mut dyn DatagramTransport,
    cancel: &CancellationToken,
    context: &EstablishContext,
    packets: &mut mpsc::Receiver<Packet>,
    ready: &watch::Sender<Ready>,
    sink: &PacketSink,
    registry: &Registry,
    scratch: &mut [u8],
) -> Result<(), DispatchError> {
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut established = false;
    loop {
        let deadline = if established {
            Instant::now() + DEFAULT_ESTABLISH_TIMEOUT
        } else {
            context.deadline()
        };
        let result = tokio::select! {biased;
            ()=cancel.cancelled()=>return Err(DispatchError::ConnectionRefused),
            ()=tokio::time::sleep_until(context.deadline()),if !established=>return Err(DispatchError::TimedOut),
            datagram=transport.receive()=> {
                let datagram=datagram?;
                if datagram.remote!=Destination::Ip(endpoint) || datagram.payload.len()>scratch.len(){continue;}
                let result=tunn.decapsulate(Some(endpoint.ip()),&datagram.payload,scratch);
                handle(result,config,endpoint,transport,cancel,deadline,sink,registry).await?;
                loop {
                    let result=tunn.decapsulate(None,&[],scratch);
                    if matches!(result,TunnResult::Done){break;}
                    handle(result,config,endpoint,transport,cancel,deadline,sink,registry).await?;
                }
                None
            },
            packet=packets.recv(),if established=> {
                let packet=packet.ok_or(DispatchError::ConnectionRefused)?;
                Some(tunn.encapsulate(packet.data(),scratch))
            },
            _=timer.tick()=>Some(tunn.update_timers(scratch)),
        };
        if let Some(result) = result {
            handle(
                result, config, endpoint, transport, cancel, deadline, sink, registry,
            )
            .await?;
        }
        if !established && tunn.time_since_last_handshake().is_some() {
            established = true;
            ready.send_replace(Ready::Established);
            tracing::debug!("WireGuard handshake ready");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    result: TunnResult<'_>,
    config: &WireGuardOutboundConfig,
    endpoint: SocketAddr,
    transport: &mut dyn DatagramTransport,
    cancel: &CancellationToken,
    deadline: Instant,
    sink: &PacketSink,
    registry: &Registry,
) -> Result<(), DispatchError> {
    match result {
        TunnResult::Done => Ok(()),
        TunnResult::Err(WireGuardError::ConnectionExpired) => Err(DispatchError::ConnectionRefused),
        TunnResult::Err(_) => Ok(()),
        TunnResult::WriteToNetwork(packet) => {
            let datagram = Datagram {
                remote: Destination::Ip(endpoint),
                payload: Bytes::copy_from_slice(packet),
                sniffed_domain: None,
            };
            tokio::select! {biased;()=cancel.cancelled()=>Err(DispatchError::ConnectionRefused),result=tokio::time::timeout_at(deadline,transport.send(datagram))=>result.map_err(|_|DispatchError::TimedOut)?}
        }
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            let Some((source, destination)) = addresses(packet) else {
                return Ok(());
            };
            if !local_destination(config, destination) || source.is_ipv4() != destination.is_ipv4()
            {
                return Ok(());
            }
            // Single-peer Mihomo advertises the entire configured local family;
            // top-level allowed-ips is intentionally ignored in this mode.
            if let Some(udp) = parse_udp_packet_view(packet) {
                registry.deliver(udp.source, udp.destination, udp.payload);
            } else {
                let _ = sink.try_send(Packet::new(Bytes::copy_from_slice(packet)));
            }
            Ok(())
        }
    }
}
fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some((
            IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
            IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?),
        )),
        6 if packet.len() >= 40 => Some((
            IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
            IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
        )),
        _ => None,
    }
}
