# ClientHello 独立参考

保留官方 Mihomo/uTLS 原始 ClientHello golden，作为独立来源的测试输入。

## 验证分层

独立官方基线、Vole 内存 TLS 报文及真实协议互通分别验证，结果不能互相代替。
当前容器互通和压力测试由 container-benchmark 运行；入口和范围见
[测试](../README.md)。golden 中的 `case_id` 是用例标签；原始 TLS 字节、解析结果、
来源版本及原报告 hash 保持独立采集时的值，不表示重新抓包。

## Independent wire baseline

`mihomo-selected-v1.json` retains eight small synthetic, raw TLS observations:
four templates, ordinary TCP TLS and classic REALITY. The official latest Mihomo
binary was downloaded, not compiled from the reference source. Binary identity,
uTLS build dependency, raw record layout, handshake bytes and parsed fields are
retained as source provenance.
These are public ephemeral key shares and synthetic names, not private keys,
proxy credentials, application traffic or user destinations.

The committed golden is a source fixture, not generated run data. A verified
reference does not establish Vole support, REALITY authentication or proxy
interoperability.

Chrome120 observations remain historical reference evidence. Vole's current
supported templates are defined in the [TLS contract](../../docs/tls-client-fingerprint.md).

## Comparison rules

The bounded parser preserves ordered cipher/signature/group/share vectors,
extension payloads, ALPN/ALPS, versions, compression, ECH outer shape, padding,
session IDs' widths, ticket lengths and PSK identity/binder widths. Crypto bytes
and time-dependent ages remain in raw evidence but are not compared for equality.
GREASE values are normalized while position, width and group/share association
remain checked. Chrome shuffles only eligible slots; fixed GREASE/padding/PSK
positions are not sorted away. Firefox/Safari use fixed extension order.

The reference checker additionally validates source-defined variants before
normalizing them: exact SNI and caller-context ALPN; Chrome's ECH payload sizes
144/176/208/240; Firefox's 239-byte payload and AES128-GCM/ChaCha20 choice; and
Chrome120/Safari's conditional padding to 512 bytes. Chrome133 has no padding.
Changes outside those allowances fail comparison. Goldens are not regenerated
from the implementation under test to silence mismatches.

Sources: [Mihomo TLS connection path](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/component/tls/utls.go),
[pinned uTLS templates](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_parrots.go),
[ECH GREASE](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_ech.go),
[padding](https://github.com/MetaCubeX/utls/blob/f7d52c22f3a8d2f510ad1470f75cb6c3fe26aa37/u_tls_extensions.go).

## Intentional Vole differences

Vole retains a TLS1.2 floor, transport-owned ALPN, standard HTTP/2 SETTINGS
without TLS ALPS advertisement, a guard for unexpected nonempty ALPS,
and its bounded ordinary-TLS session cache. Safari's
TLS1.0/1.1 declarations are trimmed; Mihomo's WS Chrome still advertises h2 ALPS
when ALPN is only HTTP/1.1, which Vole deliberately does not do. Warm/resumed
hellos have separate expectations; PSK is not ignored by the comparator. These
policies do not authorize dropping unrelated cipher suites, shares or extensions.

当前身份、后端和恢复边界见 [TLS 契约](../../docs/tls-client-fingerprint.md)；实际运行结果按 [验收边界](../../docs/acceptance.md)记录。
