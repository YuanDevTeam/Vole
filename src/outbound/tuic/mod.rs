//! TUIC v5 over the existing controlled QUIC seam. No socket or DNS factory.
mod activity;
mod datagram;
mod outbound;
mod stream;
mod wire;
pub use outbound::TuicOutbound;

#[cfg(all(test, feature = "inbound-http"))]
mod http_reuse_memory_tests;

fn failure<E>(_: E) -> std::io::Error {
    // Peer close reasons and TLS errors may carry identities or destinations.
    std::io::Error::other("TUIC exchange failed")
}
