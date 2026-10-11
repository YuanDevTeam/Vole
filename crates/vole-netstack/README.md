# vole-netstack

`vole-netstack` is Vole's bounded userspace raw-IP netstack. It accepts
IPv4/IPv6 packets from a TUN device, exposes intercepted TCP streams and UDP
datagrams to async Rust code, and returns generated raw-IP packets.

The default local buffers are intentionally small for an iOS TUN runtime;
Vole does not assume the host process role:

- 32 KiB total buffering per TCP direction, independently configurable;
- bounded raw-packet, TCP-accept and UDP-datagram queues;
- TCP flow state reclaimed by protocol completion or idle timeout;
- no unbounded channel;
- cancellation plus a stop completion barrier.

The repository-root `LICENSE` covers this crate. Upstream projects are credited
in the repository `README.md`.

`NetStackConfig::tcp_recv_buffer` bounds each flow's receive direction from raw
IP to `TcpStream`'s `AsyncRead`, and `tcp_send_buffer` bounds its send direction
from `AsyncWrite` to raw IP. Each total is split equally between the smoltcp
socket buffer and the application-facing byte queue. Both default to 32 KiB
(16 KiB per layer), must be even, and must be at least 4 KiB independently.
Increasing one direction does not reserve additional bytes for the other.

## TCP/ICMP driver and UDP codec

`NetStack::start_tcp(config)` returns `TcpNetStackParts` directly. It creates
bounded raw ingress, raw output and TCP-accept endpoints, but no shared UDP
datagram queue. The TUN runtime can own UDP association admission and use the
pure codec without sending ordinary UDP through the TCP driver:

```rust,ignore
let vole_netstack::TcpNetStackParts {
    packet_sink,
    mut packet_stream,
    tcp_listener,
    control,
    stats,
} = vole_netstack::NetStack::start_tcp(config)?;

if let Some(view) = vole_netstack::parse_udp_packet_view(raw_ip_packet.data()) {
    // Admit the association first; copy view.payload only for async ownership.
} else {
    packet_sink.try_send(raw_ip_packet)?;
}

let mut frame = Vec::with_capacity(mtu);
vole_netstack::encode_udp_packet_into(&response_datagram, mtu, &mut frame)?;
// The platform's single writer can write this frame or a driver output packet.
let raw = packet_stream.try_recv();
control.stop().await;
```

The borrowed parser checks IPv4/IPv6 and UDP header lengths and supports direct
UDP next headers only. It preserves the existing policy: no additional checksum,
fragment or IPv6 extension-header validation. Encoding emits checksums, reuses
the caller's `Vec`, and leaves it unchanged on address-family or MTU errors.
UDP mistakenly sent into the TCP-only driver is ignored.

## Generic TCP and UDP API

```rust,ignore
let stack = vole_netstack::NetStack::start(config)?;
let vole_netstack::NetStackParts {
    packet_sink,
    packet_stream,
    tcp_listener,
    udp_socket,
    control,
    stats,
} = stack.into_parts();

packet_sink.send(raw_ip_packet).await?;
let tcp = tcp_listener.accept().await;
let udp = udp_socket.recv().await;
control.stop().await;
```

`NetStackControl::stop()` returns only after the driver has released all
smoltcp sockets and woken pending TCP operations. Dropping the sole
`PacketStream` also stops the driver and releases all endpoints.

## Active TCP client

`NetStack::start_client(config, addresses)` returns `ClientNetStackParts` with
the same raw packet endpoints, control and statistics, plus a cloneable
`TcpConnector`. `ClientAddresses` supplies optional IPv4/IPv6 source addresses;
at least one must be unicast. An omitted family fails with `AddrNotAvailable`.
The client mode does not create a passive accept or UDP datagram queue, and
discards incoming TCP packets that do not belong to a requested connection.

An optional `ClientConfig` retains up to two real `ClientPrefix` candidates,
including two addresses in one family, and selects the source for each peer.
It separates the bounded receive packet size from the TX MTU and can opt into
per-socket ICMP PMTU feedback. Mapped IPv4 and duplicate candidates normalize
before startup. IPv4-only clients permit MTU 68..65535; a real IPv6 candidate
requires at least 1280. Passive TUN validation still requires 1280.
`ClientAddresses` converts with the former receive bound and PMTU disabled.

```rust,ignore
let parts = vole_netstack::NetStack::start_client(config, addresses)?;
// The owner must concurrently pump packet_sink and packet_stream.
let stream = parts.tcp_connector.connect(peer, deadline).await?;
assert_eq!(stream.destination_addr(), peer);
parts.control.stop().await;
```

`connect` takes an IP `SocketAddr` and an absolute Tokio `Instant`; bounded
command admission and the handshake use that one deadline. It returns only
after the socket reaches Established, with `source_addr` representing the
configured local IP and allocated ephemeral port. `destination_addr` is the
remote peer. The driver alone owns socket state and allocates source ports;
there is no host socket, DNS resolver, system interface, route or NAT setup.

The command queue holds at most 32 requests, independently of active socket
count. Waiting for queue space remains cancellable and deadline-bound. Future
Drop, deadline or handshake failure aborts the pending socket and reclaims its
flow after any reset reaches the existing output queue; a full output never
blocks Stop. Successful streams retain the existing direction buffers and TCP
half-close behavior. Stop closes admission, wakes queued/in-flight connects
and releases every socket before returning. Passive `start`/`start_tcp` TUN
behavior and their configured bounds remain unchanged.

## Driver buffering and scheduling

Device ingress holds at most one pending packet, not another packet queue.
smoltcp TX tokens reserve capacity in the existing bounded raw output queue
before consuming ingress or allocating an output packet. Consuming a token
sends directly into that queue; dropping an unused token returns its permit.
There is no intermediate device TX backlog. TCP protocol state retains pending
output, including resets, until a token is available. Low-priority ICMP echo
replies are dropped when output is full, without waiting or retaining a reply.

`PacketStream::recv`, `recv_batch` and `try_recv` wake the driver when they
restore output capacity. An immediate protocol timer is deferred while output
is full, avoiding a zero-delay retry loop; the wakeup resumes it promptly.
Bounded periodic polling still performs lifecycle maintenance.

The driver consumes at most eight already-ready ingress packets before full
socket maintenance. TCP ingress still advances packet by packet; cancellation
or a full output queue leaves the unconsumed suffix in the existing ingress
queue. One TCP packet may remain in the device pending output capacity.
It neither waits to fill a batch nor introduces another packet queue.
Cooperative scheduling is charged per consumed packet, including the ready
suffix. TCP egress can be deferred to batch maintenance; relative ordering with
an immediate ICMP reply is not guaranteed.
