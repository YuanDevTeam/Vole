# ClientHello 独立参考

保留官方 Mihomo/uTLS 原始 ClientHello golden；开发阶段计划不再作为测试输入。

## 验证分层

| 历史报告标签 | 历史脚本入口 | 证明范围 |
| --- | --- | --- |
| FINGERPRINT-REFERENCE | protocol_fingerprint_reference | 官方客户端的独立基线，不是 Vole 互通 |
| FINGERPRINT-WIRE | protocol_fingerprint_shape | 公开配置的内存 TLS 报文、恢复与过期 |
| FINGERPRINT-INTEROP | protocol_fingerprint | 命名指纹在真实容器协议链路中的行为 |

上述专用运行器可从 Git 历史查阅，未随当前精简 Mihomo 互通入口恢复；不得把它们
当作现存命令。当前容器互通和压力测试由 container-benchmark 运行；入口和
范围见 [构建与验证](../../scripts/README.md)。golden 中的 `case_id` 是用例标签；原始 TLS
字节、解析结果、来源版本及原报告 hash 保持独立采集时的值，不表示重新抓包。
历史运行报告不改写，按其记录的 Git revision 复核；各层结果不能互相代替。

## Independent wire baseline

`mihomo-selected-v1.json` retains eight small synthetic, raw TLS observations:
four templates, ordinary TCP TLS and classic REALITY. The official latest Mihomo
binary was downloaded, not compiled from the reference source. Binary identity,
uTLS build dependency, raw record layout, handshake bytes and parsed fields are
retained. The historical collector's `validate_capture` re-parsed raw bytes and
detected altered derived data; that collector is not a current script entry.
These are public ephemeral key shares and synthetic names, not private keys,
proxy credentials, application traffic or user destinations.

The historical independent baseline used 116 cases: six enabled names
across TCP/WS/gRPC/REALITY, two SNI lengths and two successive connections; four
`none` controls; four actual templates with TLS1.2/1.3 handshakes on a native
OpenSSL observer. All server roles and the official client run in owned isolated
containers. Generated run data is deleted after each test; the committed golden
remains a source fixture. Success means **reference captured / baseline verified**, not Vole
support, REALITY authentication or proxy interoperability. A capture-only observer
intentionally aborts; OpenSSL handshake cases do not implement VLESS or HTTP.

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

Vole retains a TLS1.2 floor, transport-owned ALPN, h2-only ALPS advertisement,
nonempty ALPS rejection and its bounded ordinary-TLS session cache. Safari's
TLS1.0/1.1 declarations are trimmed; Mihomo's WS Chrome still advertises h2 ALPS
when ALPN is only HTTP/1.1, which Vole deliberately does not do. Warm/resumed
hellos have separate expectations; PSK is not ignored by the comparator. These
policies do not authorize dropping unrelated cipher suites, shares or extensions.

当前身份、后端和恢复边界见 [TLS 契约](../../docs/tls-client-fingerprint.md)；实际运行结果按 [验收边界](../../docs/acceptance.md)记录。
