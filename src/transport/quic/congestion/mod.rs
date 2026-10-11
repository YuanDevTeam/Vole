//! Google QUIC congestion algorithms with explicit Meta consumer parameters.
//! Source revisions and BSD attribution are recorded in README.md.

mod bbr;
mod filter;
mod loss;
mod sampler;

pub use bbr::{BbrConfigFactory, BbrVersion};
pub use loss::LossConfigFactory;
