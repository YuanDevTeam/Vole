//! Outbound wire transports.
#[cfg(feature = "outbound-shadowsocks")]
pub(crate) mod kcptun;
#[cfg(any(feature = "sing-mux", feature = "outbound-shadowsocks"))]
pub(crate) mod smux;
#[cfg(feature = "outbound-shadowsocks")]
pub(crate) mod ss_framed;

#[cfg(feature = "outbound-vmess")]
pub(crate) mod mkcp;

#[cfg(feature = "quinn-h3-transport")]
pub(crate) mod quinn_h3;

#[cfg(feature = "quiche-h3-transport")]
pub(crate) mod quiche_h3;

#[cfg(any(feature = "outbound-trusttunnel", feature = "outbound-masque"))]
pub(crate) mod h3_connect;
#[cfg(feature = "outbound-masque")]
pub(crate) mod masque_codec;
#[cfg(feature = "sing-mux")]
pub(crate) mod sing_mux;
#[cfg(feature = "outbound-vless")]
pub mod xhttp;

pub const STREAM_CHUNK_BYTES: usize = 16 * 1024;
pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;

#[cfg(feature = "stream-transport")]
mod ws;
#[cfg(feature = "stream-transport")]
pub use ws::{
    MAX_EARLY_DATA_BYTES, WebSocketEarlyData, WebSocketOptions, connect_websocket, http_upgrade,
    websocket,
};

#[cfg(feature = "stream-transport")]
mod http_head;
#[cfg(feature = "stream-transport")]
pub use http_head::{HTTP_HEAD_BYTES, HTTP_HEADER_COUNT};

#[cfg(feature = "stream-transport")]
mod grpc;
#[cfg(feature = "stream-transport")]
mod grpc_pool;
#[cfg(feature = "stream-transport")]
mod h2_empty;
#[cfg(feature = "stream-transport")]
mod h2_write;
#[cfg(feature = "stream-transport")]
pub use grpc::{Driver as StreamDriver, grpc, grpc_duplex, legacy_h2};
#[cfg(feature = "stream-transport")]
pub use grpc_pool::GrpcPool;

#[cfg(feature = "stream-transport")]
mod http_obfs;
#[cfg(feature = "stream-transport")]
pub use http_obfs::{HttpObfsOptions, http_obfs};
#[cfg(feature = "quic-transport")]
pub mod quic;
