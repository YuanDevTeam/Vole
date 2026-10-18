#[cfg(feature = "inbound-http")]
pub(crate) mod framing;
pub(crate) mod parser;
#[cfg(feature = "inbound-http")]
pub(crate) mod server;

#[cfg(all(test, feature = "inbound-http"))]
mod tests;

pub(crate) use parser::{RequestHead, read_request_head};
#[cfg(all(feature = "inbound-http", feature = "inbound-socks5"))]
pub(crate) use server::handle_connection_with_deadline;
#[cfg(feature = "inbound-http")]
pub use server::{HttpBasicAuth, HttpServer, HttpServerConfig};
