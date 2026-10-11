//! Bounded userspace raw-IP netstack used by `Vole`.
//!
//! The crate intentionally has no TUN file-descriptor dependency. Platform
//! code feeds raw IP packets through [`PacketSink`] and drains generated raw IP
//! packets from [`PacketStream`]. TCP and UDP are exposed separately to the
//! outbound dispatcher.

mod client;
mod config;
mod device;
mod icmp;
mod packet;
mod pmtu;
mod stack;
mod tcp;
mod udp;

pub use client::{ClientConfig, ClientPrefix, MAX_RECEIVE_PACKET_SIZE};
pub use config::{ClientAddresses, ConfigError, NetStackConfig};
pub use packet::Packet;
pub use pmtu::{PathMtuHint, build_packet_too_big, parse_path_mtu_hint};
pub use stack::{
    ClientNetStackParts, NetStack, NetStackControl, NetStackError, NetStackParts, NetStackStats,
    PacketSink, PacketStream, ResourceSnapshot, TcpNetStackParts,
};
pub use tcp::{TcpConnector, TcpListener, TcpStream};
pub use udp::{
    UdpDatagram, UdpError, UdpPacketView, UdpSender, UdpSocket, encode_udp_packet_into,
    parse_udp_packet_view,
};
