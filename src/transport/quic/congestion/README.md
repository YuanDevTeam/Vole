# Native congestion controllers

The algorithm code in this directory is adapted from Google's QUIC implementation under BSD-3-Clause. The source copyright notices and the unmodified upstream license are retained in the Rust files and [LICENSE.chromium](LICENSE.chromium). Vole's MIT license does not replace that license.

| Rust implementation | Google source revision and files | Original copyright |
| --- | --- | --- |
| `bbr.rs`, v1 sampler and filter | [66dea072431f94095dfc3dd2743cb94ef365f7ef](https://github.com/google/quiche/tree/66dea072431f94095dfc3dd2743cb94ef365f7ef/quic/core/congestion_control): `bbr_sender.{cc,h}`, `bandwidth_sampler.{cc,h}`, `windowed_filter.h` | 2016 The Chromium Authors |
| `bbr.rs`, v2 sampler and filter | [e7872fc9e12bb1d46a118949c3d4da36de58aa44](https://github.com/google/quiche/tree/e7872fc9e12bb1d46a118949c3d4da36de58aa44/quiche/quic/core/congestion_control): `bbr_sender.{cc,h}`, `bandwidth_sampler.{cc,h}`, `windowed_filter.h` | 2016 The Chromium Authors |
| `loss.rs`, Cubic curve | The latter revision: `cubic_bytes.{cc,h}` | 2015 The Chromium Authors |
| `loss.rs`, hybrid slow start | The latter revision: `hybrid_slow_start.{cc,h}` | 2012 The Chromium Authors |

The public Meta v1/v2 algorithm names identify the consumers used by the frozen Mihomo configuration contract, rather than Quinn's stock BBR or the standard BBR2 algorithm. In particular, Meta v2 uses the later classic `BbrSender` with STARTUP, DRAIN, PROBE_BW and PROBE_RTT, an eight-phase gain cycle, and the newer ACK aggregation sampler. Source optional experiments that the reference consumer does not enable are not exposed as configuration.

Vole independently adapts the public consumer parameters: v1 uses the fixed 1280-byte initial MSS, ignores the profile, retains its double-MTU minimum-window calculation and minimum-then-maximum clamp order, and uses its window/RTT estimator for pacing. Its signed byte-count and historical duration/bandwidth arithmetic are kept separate from the Google algorithm's normal units. v2 uses the standard, conservative and aggressive parameter sets, scales packet-sized windows on MTU changes, and applies the 64 KiB/s pacing floor. Both consumers use a 1 ms minimum pacing delay. No GPL Go implementation was translated into these Rust files.

The Quinn adapter supplies losses before ordered ACKs and completes each event after RTT and in-flight accounting. Unique connection-wide sample identifiers include zero and span packet spaces. ACK-only packets are excluded from bandwidth sampling. Discarding a packet releases its snapshot without recording delivery or loss, and ordinary loss is not reported twice through the legacy callback.

The sampler owns only actual outstanding packet snapshots. An ordered map avoids allocation proportional to numerical packet gaps. The three-estimate filters use constant storage; ACK-point candidates are retained only while a current send-time snapshot or a future send can use them. These ownership adaptations replace Google's least-unacked cleanup interface without retaining retired packet history.
