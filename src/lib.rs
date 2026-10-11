//! Vole's platform-neutral Rust core.
//!
//! The `invoke` feature exposes the common JSON API and its runtime lifecycle.
//! Native ABI/JNI wrappers (`ffi`) and the command-line entry (`cli`) call the
//! same dispatcher. Windows backends are selected explicitly at compile time.

#[cfg(all(windows, feature = "windows-wintun", feature = "windows-uwp"))]
compile_error!("windows-wintun and windows-uwp are mutually exclusive Windows backends");

pub mod config;
#[cfg(any(feature = "inbound-http", feature = "inbound-socks5"))]
mod controller;
pub mod data_dir;
pub mod dialer;
pub mod dispatch;
pub mod dns;
pub mod error;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod geodata;
pub mod inbound;
#[cfg(feature = "invoke")]
pub mod invoke;
pub mod lifecycle;
pub mod limits;
#[cfg(any(feature = "invoke", test))]
mod logging;
pub mod outbound;
pub mod packet;
pub mod platform;
#[cfg(any(feature = "tun", test))]
mod quic_sniffer;
pub(crate) mod resource;
pub mod resources;
pub mod routing;
#[cfg(all(
    any(
        feature = "outbound-http",
        feature = "outbound-anytls",
        feature = "outbound-socks5",
        feature = "outbound-shadowsocks",
        feature = "outbound-vless",
        feature = "outbound-trojan",
        feature = "outbound-trusttunnel",
        feature = "outbound-vmess",
        feature = "outbound-hysteria2",
        feature = "outbound-tuic",
        feature = "outbound-wireguard"
    ),
    any(feature = "invoke", test)
))]
mod runtime;
pub mod security;
pub mod session;
#[doc(hidden)]
pub mod sniffing;
#[cfg(any(
    feature = "inbound-socks5",
    feature = "outbound-mieru",
    feature = "outbound-http",
    feature = "outbound-anytls",
    feature = "outbound-shadowsocks",
    feature = "outbound-socks5",
    feature = "outbound-trojan",
    feature = "outbound-vless"
))]
mod socks5;
mod tcp_sniffer;
#[cfg(any(
    feature = "inbound-http",
    feature = "inbound-socks5",
    feature = "tun",
    test
))]
pub(crate) mod traffic;
#[cfg(any(
    feature = "outbound-vless",
    feature = "stream-transport",
    feature = "quic-transport"
))]
pub mod transport;
#[cfg(all(
    feature = "tun",
    any(
        unix,
        all(windows, any(feature = "windows-wintun", feature = "windows-uwp"))
    )
))]
mod tun_runtime;
#[cfg(all(windows, feature = "windows-uwp"))]
#[doc(hidden)]
pub mod windows;
#[cfg(any(feature = "outbound-vless", feature = "outbound-vmess"))]
pub mod xudp;

pub use error::{Result, VoleError};
pub use lifecycle::{Lifecycle, LifecycleState};
pub use limits::ResourceLimits;
pub use packet::{IpVersion, TunFraming};

/// Stable implementation identifier returned by the version Invoke method.
pub const ENGINE: &str = "rust";

/// Implementation identity embedded in every native artifact.
pub const BUILD_IDENTITY: &str =
    concat!("Vole;engine=rust;coreVersion=", env!("CARGO_PKG_VERSION"));

mod connections;
mod memory;
