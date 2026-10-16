# Mihomo 兼容原则与范围

## 兼容原则

Vole Core 以**内存优化和吞吐达标为第一目标**。与 Mihomo 的兼容要求是：在 Vole 支持的协议和模式范围内，与 **Mihomo listener 和官方协议 server 端互通**，不寻求配置字段行为完全一致。

实现策略、默认值、窗口、缓冲区、定时器和资源生命周期可按 Vole 的性能目标取舍；差异必须在对应契约中明确说明，并保持协议数据正确性、认证和安全边界。字段名称继续参考 Mihomo，当前接受的配置仍以 Vole 文档为准。

兼容验收以真实对端的握手、认证、数据传输和关闭验证为依据；内存与吞吐通过相同输入和目标负载的压力测试验证。逐字段对照用于确认支持范围和说明差异，不以字段行为相等作为验收门槛。验证范围见 [验收边界](acceptance.md)。

## 当前支持范围

配置名称以 [Mihomo v1.19.32](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36) 为参考。
Vole 接受的字段与限制以 [config.yaml](config.yaml) 为准；兼容配置子集不等于完整替代 Mihomo。
未知字段和不支持的组合明确拒绝，不静默修改输入。已废弃的 dns.fallback-filter.geosite 不接受，使用 nameserver-policy 的 geosite 选择器。

| 范围 | 当前支持 |
| --- | --- |
| 配置与选路 | YAML anchor/merge；rule/global/direct；内置 DIRECT/REJECT；域名、地址、端口、网络、GeoData、RULE-SET 和 AND/OR/NOT |
| 资源 | HTTP/file/inline proxy/rule providers；动态成员、筛选、覆盖、健康检查；Provider dialer-proxy 与 HTTP 订阅信息；YAML/Text 与 domain/ipcidr MRS；有界离线规则bundle；失败保留旧代 |
| 策略组 | select/url-test/fallback/load-balance；默认和持久选择；延迟容差、恢复、三种负载均衡策略；旧连接保持原路径 |
| DNS | hosts（含启动 LAN 地址快照）、bootstrap/节点/直连解析角色、policy、respect-rules；UDP/TCP/DoH/DoT/DoQ、DoH/H3；fallback；redir-host/fake-IP 与映射持久化 |
| mixed-port | HTTP/SOCKS5 TCP 与 SOCKS5 UDP；LAN 地址限制、多用户认证、认证跳过网段；allow-lan 不强制认证 |
| 出站 | HTTP(S) CONNECT、SOCKS5、AnyTLS、Trojan、VMess AEAD、VLESS、Hysteria2、TUIC v5、Shadowsocks 2022、标准 WireGuard 单/多 peer、TrustTunnel H2/H3、Mieru TCP/UDP 载体、MASQUE H2/H3 IP 与 H3 L4；依赖启用的 Cargo feature |
| QUIC 配置 | HY2 独立 initial/max 接收窗口、秒 handshake-timeout；TUIC v5 入口ip、毫秒heartbeat、反向命名的stream/connection窗口、所有者池阈值、frame/fragment限制、PMTUD与UoT v1/v2 |
| 客户端 TLS | tls.custom-certifactes 证书内容；启动时合并可读系统根、WebPKI 与显式根并跨组件共享；TUIC v5 与其它 TLS 节点复用 cert/private-key 身份加载 |
| 嗅探 | TUN/mixed TCP 的 HTTP/TLS；TUN UDP 的 QUIC；域名/地址排除、强制条件和目标覆盖 |
| Linux 自建设备 | auto-detect-interface、auto-route、systemd-resolved DNS 接管；失败和停止时恢复本次修改 |
| 运行状态 | 连接快照、流量计数和关闭；组与资源状态；规则命中、有效配置、受限 DNS 诊断 |

## 必须保留的边界

- 业务入口只有 mixed-port 与 TUN；不支持 port、socks-port、listeners、redir/tproxy 或服务端协议配置。
- tls 同时接受客户端信任根及 Controller 服务端 TLS 配置；无效显式客户端信任根拒绝配置，Mihomo 会跳过无效项。iOS/tvOS、Android 不保证取得完整系统信任库；
  所有后端仍使用 WebPKI 校验，未复制 Go 的原生系统验证器。详细范围见 [TLS 契约](tls-client-fingerprint.md)。
  独立测量 YAML 只接受 proxies 与同名客户端 tls 子集，不接受 TLS 服务端配置。
- Shadowsocks 只支持三个 2022 cipher；插件仅 strict ShadowTLS v3，UoT 仅 v2。
- DNS 不提供独立 listen。DoQ、DoH/H3、prefer-h3、ECS、上游类型过滤、TLS 验证参数、
  DoT 独立禁用复用、LRU/ARC 与显式 system/DHCP 上游已支持，
  来源发现和物理绑定的可用平台及参考差异以 DNS 契约为准。
  DoH 使用 GET、URL Basic 与实际 H3/H2/H1；详细解析角色、缓存、预算与过滤行为见 [DNS 契约](tun-icmp-dns.md)。
- Provider/group 名称筛选和改名支持 lookahead、定长 lookbehind、数字/命名 backreference；
  普通表达式保留 Rust regex 快速路径。复杂表达式和改名有内部预算，超限使候选失败。
  不支持递归/条件式或完整 .NET 方言；DOMAIN-REGEX 与 GeoSite regex 不扩展。
- gRPC 三协议共用选项和节点连接池。负 ping-interval 明确拒绝，不复制固定参考
  HTTP/2 客户端的立即重复 PING；超出本机可表示期限的正秒数也明确拒绝，不复制 Duration 溢出。
- 订阅元信息只在成功候选或合法 304 后发布，失败响应或坏候选保留旧值；
  与 Mihomo 在读取响应头时更新的时点不同。数值仅接受有限且可表示的十进制数，
  不保留非有限/溢出浮点转换的参考行为。
- WireGuard 使用标准用户态单/多 peer、最长前缀选择、reserved（数组或 Base64）、节点远端 DNS 与按需端点更新；
  每个本地地址族最多一个地址，MTU 至少1280。无 peers 时顶层 allowed-ips 与参考一致地忽略。
  peer 仅在实际使用时解析/建链；Mihomo 在节点初始化时解析所有 peer。
- 节点 UDP 能力按 [出站契约](outbounds.md) 声明；rule 模式跳过不支持 UDP 的目标，继续匹配后续规则。
  global 模式和显式 DNS 出口不执行此跳过。负载均衡组按其声明能力参与规则匹配，实际选中成员仍须支持 UDP。
- 未启用 mixed-port 或 TUN 时仍可运行 Controller 和资源任务。Controller 接受通配 IP、localhost 和空 host；secret 可选，见 [Controller API](controller-api.md)。
  CORS 按 origins/预检/私网字段处理；HTTP 与 HTTPS H2/H1 共用 handler 与 Bearer，支持服务端证书文件更新和五种客户端认证模式。
  /dns/query 查询真实上游；连接表按 UDP 目标流管理，memory 返回当前进程 resident bytes，平台口径不同。
- fake-IP TTL 最小一秒；映射生命周期独立于 TTL。本地选择和映射存储不保证与 Mihomo 数据库互读。
- DNS、fake-IP 与嗅探的 classical selector 使用对应的域名或目标 IP 条件，支持纯对应条件组成的 AND/OR/NOT。
  混合端口、来源、网络等叶子的整个逻辑项不参与匹配；Mihomo 使用零值元数据执行全部 classical 条件，因此这些组合仍有语义边界。
- Apple、Android、Windows UWP 的网络设置、权限和 App 生命周期仍归宿主；Windows Wintun 使用外置 DLL。
  借用 Unix fd 只复制并保留原描述符。Linux 扩展路由、旁路由、防火墙/NAT、进程/UID 规则不在当前范围。

平台编译、内存回归、CLI 对照诊断、协议互通和压力测试是不同的验证层次，见
[验收边界](acceptance.md)。任一层通过都不代表所有字段取值、组合、平台或真机行为已验证。

QUIC 使用官方 Quinn 固定 Middle 接收窗口：每流为 max(initial, min(maximum, 4 MiB))，
连接为 initial，不复现 Mihomo 的自适应窗口。initial>max 保留初值，max 大于 VarInt clamp，
无法编码的 initial 明确拒绝；credit 通告沿 Quinn 原生实现。
HY2 默认连接 initial 为 2 MiB，显式配置不按此默认值钳位。
HY2 正 handshake-timeout 与 Core 原期限合并；参考正值后台 offer 的生命周期可能超出
单次调用期限，该差异保留。TUIC max-open-streams=1 接受但实际不能取得业务所有权；
frame 无法容纳 TUIC 头时可解析，业务 UDP 发送失败，不额外拒绝TCP配置。支持模式的互通与窗口增大后的 RSS/吞吐/UDP loss 不由
这些内存 fixture 证明，由最终 CLI/container 对照分别记录。

Provider override 表达式的 upcase/downcase 使用 Rust 标准 Unicode 全映射，可能产生多个字符；
输出、取消和计算预算保持。它不固定到 Go 的 Unicode 15 单字符映射，也不改变 IDNA 域名处理。
