# Mihomo 配置兼容范围

配置名称以 [Mihomo v1.19.32](https://github.com/MetaCubeX/mihomo/tree/88dcbf7f1614a67c3b36b848ee3592dfa92ada36) 为参考。
Vole 接受的字段与限制以 [config.yaml](config.yaml) 为准；兼容配置子集不等于完整替代 Mihomo。
未知字段和不支持的组合明确拒绝，不静默修改输入。

| 范围 | 当前支持 |
| --- | --- |
| 配置与选路 | YAML anchor/merge；rule/global/direct；内置 DIRECT/REJECT；域名、地址、端口、网络、GeoData、RULE-SET 和 AND/OR/NOT |
| 资源 | HTTP/file/inline proxy/rule providers；动态成员、筛选、覆盖、健康检查；Provider dialer-proxy 与 HTTP 订阅信息；YAML/Text 与 domain/ipcidr MRS；失败保留旧代 |
| 策略组 | select/url-test/fallback/load-balance；默认和持久选择；延迟容差、恢复、三种负载均衡策略；旧连接保持原路径 |
| DNS | hosts、bootstrap/节点/直连解析角色、policy、respect-rules；UDP/TCP/DoH/DoT；fallback；redir-host/fake-IP 与映射持久化 |
| mixed-port | HTTP/SOCKS5 TCP 与 SOCKS5 UDP；LAN 地址限制、多用户认证、认证跳过网段；allow-lan 不强制认证 |
| 出站 | HTTP(S) CONNECT、SOCKS5、AnyTLS、Trojan、VMess AEAD、VLESS、Hysteria2、TUIC v5、Shadowsocks 2022；依赖启用的 Cargo feature |
| 嗅探 | TUN/mixed TCP 的 HTTP/TLS；TUN UDP 的 QUIC；域名/地址排除、强制条件和目标覆盖 |
| Linux 自建设备 | auto-detect-interface、auto-route、systemd-resolved DNS 接管；失败和停止时恢复本次修改 |
| 运行状态 | 连接快照、流量计数和关闭；组与资源状态；规则命中、有效配置、受限 DNS 诊断 |

## 必须保留的边界

- 业务入口只有 mixed-port 与 TUN；不支持 port、socks-port、listeners、redir/tproxy 或服务端协议配置。
- Shadowsocks 只支持三个 2022 cipher；插件仅 strict ShadowTLS v3，UoT 仅 v2。
- DNS 不提供独立 listen、DoQ、DoH/H3、ECS、system/DHCP nameserver 或可配置 ARC 缓存。
  DoH 使用 H1 POST；详细解析角色、缓存与过滤行为见 [DNS 契约](tun-icmp-dns.md)。
- 正则使用 Rust regex 子集，明确拒绝 lookaround/backreference。规则与 provider 的协议覆盖仅限已实现字段。
- gRPC 三协议共用选项和节点连接池。负 ping-interval 明确拒绝，不复制固定参考
  HTTP/2 客户端的立即重复 PING；超出本机可表示期限的正秒数也明确拒绝，不复制 Duration 溢出。
- 订阅元信息只在成功候选或合法 304 后发布，失败响应或坏候选保留旧值；
  与 Mihomo 在读取响应头时更新的时点不同。数值仅接受有限且可表示的十进制数，
  不保留非有限/溢出浮点转换的参考行为。
- 节点 UDP 能力按 [出站契约](outbounds.md) 声明；rule 模式跳过不支持 UDP 的目标，继续匹配后续规则。
  global 模式和显式 DNS 出口不执行此跳过。负载均衡组按其声明能力参与规则匹配，实际选中成员仍须支持 UDP。
- 未配置入站的配置不能启动。Controller 沿用回环地址、secret 及运行配置准入，见 [Controller API](controller-api.md)。
  /dns/query 查询真实上游；连接表按 UDP 目标流管理，memory 不代表进程 RSS。
- fake-IP TTL 最小一秒；映射生命周期独立于 TTL。本地选择和映射存储不保证与 Mihomo 数据库互读。
- Apple、Android、Windows UWP 的网络设置、权限和 App 生命周期仍归宿主；Windows Wintun 使用外置 DLL。
  借用 Unix fd 只复制并保留原描述符。Linux 扩展路由、旁路由、防火墙/NAT、进程/UID 规则不在当前范围。

平台编译、内存回归、双 CLI 行为比较、官方协议互通和压力测试是不同的验证层次，见
[验收边界](acceptance.md)。任一层通过都不代表所有字段取值、组合、平台或真机行为已验证。
