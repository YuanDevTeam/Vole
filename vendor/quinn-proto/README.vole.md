# Quinn protocol source

This directory vendors the complete official `quinn-proto` 0.11.19 crate from
[crates.io](https://crates.io/crates/quinn-proto/0.11.19), retrieved through the official
[download API](https://crates.io/api/v1/crates/quinn-proto/0.11.19/download).
The non-yanked latest stable version was verified against the official API on 2026-10-10.

- Crate SHA-256: `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.
- Upstream VCS: `8192ed399a26a6e8f0aba43d10ec8badaa5b905e`, `quinn-proto` directory
  ([upstream repository](https://github.com/quinn-rs/quinn/tree/8192ed399a26a6e8f0aba43d10ec8badaa5b905e/quinn-proto)).
- Original `LICENSE-APACHE`, `LICENSE-MIT`, manifests, lockfile and VCS metadata are retained.
  Upstream source remains MIT OR Apache-2.0; independently written Vole additions are MIT.

The root Cargo manifest patches only `quinn-proto`; the registry Quinn 0.11.12 wrapper and
rustls/ring TLS provider are unchanged. The vendor crate is excluded from the root workspace,
so its explicitly filtered native memory fixtures use the original standalone upstream lockfile.
This does not select its default TLS provider/features for production.

Local changes are limited to `src/config/transport.rs`, `src/transport_parameters.rs`, `src/congestion.rs`,
`src/connection/{mod.rs,datagrams.rs,paths.rs,stats.rs}`, `src/connection/streams/{mod.rs,state.rs,recv.rs}`,
`src/connection/{pacing.rs,packet_builder.rs,spaces.rs}`, `src/packet.rs`, `src/frame.rs`,
and native test fixtures. They add optional initial/max
receive-credit policies, application-consumption and smoothed-RTT driven growth, real credit frames,
and an independent complete DATAGRAM frame limit. Existing fixed-window methods preserve their
behavior. Permitted remote stream IDs are stored as compact ranges until first
frame/application access; implicitly opened gaps are materialized one stream at
a time when accepted. Both halves of a bidirectional stream are created together,
so late frames cannot reopen a discarded half. Initial permission and credit
growth do not preallocate per-stream map entries, and parameter updates visit
only materialized send halves. Stream credit never exceeds the QUIC lifetime
representation of 2^60 streams. Actual active streams and sparse permission gaps
still require memory; this does not impose a new user configuration cap.
Tests marked `vole_` are deterministic native state/wire fixtures, not host network tests.
Optional congestion hooks expose connection-wide packet sample IDs, real ACK/loss feedback,
and explicit discard notifications for key retirement, Retry, 0-RTT rejection and path changes.
Feedback batches complete after RTT, loss and ECN processing. Controllers cloning their model
for another path must clear cloned outstanding samples; old-path feedback never samples the new path.
The tracked-packet memory bound increases by one 64-bit sample ID, from 128 to 136 bytes.
An optional byte-rate/burst/minimum-delay pacing policy consumes real packet wire bytes,
including ACK-only packets. `None` retains the original Quinn pacer, and controllers leaving
packet feedback disabled retain the original callbacks. `RttEstimator::latest()` exposes the
existing raw RTT measurement without changing recovery. These hooks do not select or replace
existing Vole HY2/TUIC congestion controllers.
No Mihomo or quic-go function implementation is copied or translated into this source.

Protocol/consumer behavior was independently checked against RFC 9000/RFC 9221 and the fixed
Mihomo v1.19.32 consumer (commit `88dcbf7f1614a67c3b36b848ee3592dfa92ada36`), which uses the
MetaCubeX quic-go flow-controller policy. This behavioral reference is distinct from the licensed
Quinn source provenance. Updating this directory requires verifying the official source/checksum,
retaining licenses, reviewing the small local patch and re-running the explicit native fixtures.

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --no-default-features --features rustls-ring --lib vole_
```
