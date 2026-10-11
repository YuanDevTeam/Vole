# smoltcp source

This directory preserves the complete official smoltcp 0.14.0 crate, checked
against the official non-yanked stable registry release on 2026-10-11.
The downloaded archive was verified before extraction:
`b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`.

Upstream revision: `cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3`, from
[smoltcp-rs/smoltcp](https://github.com/smoltcp-rs/smoltcp/tree/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3).
The original 0BSD license, manifest and VCS metadata are retained. The root
manifest patches this crate; platform adapters remain in Vole.

The TCP patch is opt-in after active `connect`. `configure_path_mtu` enables a
per-socket MTU and the IPv6 default peer MSS of 1220. Checked ICMP quotes can
reduce that socket's MTU through `apply_icmp_path_mtu`. The existing RTT
estimator supplies its optional actual-sent high-water mark, preserved across
RTO rewinds; queued-but-unsent or acknowledged sequences cannot authorize a
change. Resegmentation does not signal congestion loss. Other sockets retain
upstream behavior, including the peer MSS floor of 48.

Development dependencies use current stable releases. The random assembler
fixture uses the current rand API; this does not change production code.
Updates must preserve attribution and review this scoped patch. Network
examples must run only in isolated benchmark containers; pure TCP socket
fixtures can run in memory.
