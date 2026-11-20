//! Preserve the sing-mux v1 framing contract through the shared raw driver.
pub(super) use crate::transport::smux::{Client, new_with_queued_flush_coalescing};
