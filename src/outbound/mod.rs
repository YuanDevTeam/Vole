//! Composable proxy connectors and the built-in DIRECT dispatcher.

pub mod address;
#[cfg(feature = "outbound-http")]
pub mod http;
#[cfg(feature = "outbound-trojan")]
pub mod trojan;
#[cfg(feature = "outbound-vmess")]
pub mod vmess;

#[cfg(feature = "outbound-anytls")]
mod anytls;
mod connector;
#[cfg(feature = "sing-mux")]
mod sing_mux;
#[cfg(feature = "sing-mux")]
pub use sing_mux::SingMuxConnector;
#[cfg(feature = "outbound-shadowsocks")]
mod shadowsocks;
#[cfg(any(feature = "outbound-anytls", feature = "outbound-shadowsocks"))]
mod uot;
#[cfg(feature = "outbound-shadowsocks")]
pub use shadowsocks::ShadowsocksOutbound;
mod direct;
#[cfg(feature = "outbound-socks5")]
mod socks5;
#[cfg(feature = "outbound-vless")]
mod vless;

#[cfg(feature = "outbound-anytls")]
pub use anytls::{AnyTlsLifecycle, AnyTlsOutbound, AnyTlsStream, AnyTlsTlsConnector};
#[cfg(any(feature = "invoke", test))]
pub(crate) use connector::SelectUpstreamMember;
pub use connector::{
    ConnectedStream, ConnectorDispatcher, DEFAULT_ESTABLISH_TIMEOUT, DatagramRequest,
    EstablishContext, OutboundConnector, SelectUpstream, UpstreamPath, server_destination,
};
pub(crate) use connector::{
    IpVersionConnector, MAX_OUTBOUND_DIAGNOSTIC_MESSAGE_BYTES, OutboundDiagnostic,
    capture_outbound_diagnostic,
};
pub use direct::DirectOutbound;
#[cfg(feature = "outbound-socks5")]
pub use socks5::{Socks5Auth, Socks5Outbound};
#[cfg(feature = "outbound-vless")]
pub(crate) use vless::VlessResourceLimits;
#[cfg(all(feature = "outbound-vless", feature = "interop-test"))]
#[doc(hidden)]
pub use vless::encryption::Client as VlessEncryptionClient;
#[cfg(feature = "outbound-vless")]
pub(crate) use vless::encryption::validate_config as validate_vless_encryption;
#[cfg(feature = "outbound-vless")]
pub use vless::{
    VlessCommand, VlessOutbound, VlessStream, encode_request_header, read_response_header,
};

#[cfg(feature = "outbound-hysteria2")]
pub mod hysteria2;
#[cfg(any(
    feature = "outbound-trojan",
    feature = "outbound-vmess",
    feature = "outbound-vless",
    feature = "outbound-hysteria2",
    feature = "outbound-tuic"
))]
mod owned_stream;
#[cfg(feature = "outbound-tuic")]
pub mod tuic;
