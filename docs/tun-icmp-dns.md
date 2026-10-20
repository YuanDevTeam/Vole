# TUN ICMP 与 DNS

Vole 在公共 TUN 入口处理 ICMP Echo：Linux 可经受控物理接口实际发送，接口内地址、fake-IP 与禁用转发的请求保留本地合成回应；其他平台保持 netstack 本地回应。启用运行时 DNS 后，匹配 `tun.dns-hijack` 的 TUN TCP/UDP、选路惰性解析和内部查询共享同一套有界 DNS 实现。

顶层 `ipv6: false` 时，IPv6 原始包会在进入 netstack 前被丢弃，因此不会触发 ICMPv6 回应或 IPv6 上的 DNS/业务流量；运行时 DNS 的有效 IPv6 能力同时要求顶层 `ipv6` 和 `dns.ipv6` 为 `true`。

## ICMP Echo

| 地址族 | 请求 | 响应 |
| --- | --- | --- |
| IPv4 | type 8, code 0 | type 0, code 0 |
| IPv6 | type 128, code 0 | type 129, code 0 |

Linux 的 `tun.disable-icmp-forwarding` 缺省 false。合法 Echo Request 按以下方式处理：

- 目标属于启动时读取的真实 TUN 接口地址前缀，或属于启用的 fake-IP 地址池时，由 netstack 本地合成回应；借用 TUN 的前缀从其所属网络 namespace 读取，不以配置的设备名或任意物理 LAN 网段代替。
- `disable-icmp-forwarding: true` 时，所有合法 Echo 保留本地回应，不打开物理 ping socket；合成耗时不代表目标的真实 RTT。
- 其余请求经共享 Dialer 的 DIRECT 物理出口发送，不执行 DNS、普通 TCP/UDP 规则、代理节点或组，也不声称普通代理协议可以承载 ICMP。

`tun.icmp-timeout` 单位为整数秒，缺省或 0 使用 10 秒，控制请求准入至物理答复匹配的期限。
负值、超出有符号 64 位的整数及本机单调时钟无法表示的期限均拒绝，不复制 Duration 溢出。
这两个字段仅 Linux 接受；其他平台将其视为未知字段，保持原本地合成行为。
运行中改变归一化后的值须显式重连，沿用现有配置应用门禁，不增加独立控制 API。

真实请求先经过 IP 长度、单播地址、IPv4 头及 ICMP 校验和验证；IPv6 校验包含实际地址的伪头。
IPv4 可携带合法 options，但不重组分片；IPv6 base Next Header 必须直接为 ICMPv6，不处理扩展首部链。
已识别的非法 Echo、非零 code、截断、分片或不支持的形状直接丢弃，不回退到自动合成。
非 Echo 与既有可验证 PMTU 仍交给原 netstack 路径，不将物理错误解释为成功。

真实 TUN 前缀快照读取失败时启动失败；显式禁用转发时不读取该快照。
Linux 使用 `SOCK_DGRAM` ping socket；安装器或宿主须预先在相应出口 network namespace 中，
通过 `net.ipv4.ping_group_range` 授权运行组。Core 不写 sysctl、不请求提权，也不回退 IP raw socket。
创建、源地址、protect、物理接口与 mark 均复用共享 Dialer 的初始化和停止所有者。
权限不足、出口错误、不可达、超时或容量不足只丢弃相应真实请求，不伪造本地成功。

每会话最多两个物理 ping socket（每地址族一个），由一个驱动收发；不按目标创建任务或长期 socket。
真实请求总共最多持有 64 个许可，入站与响应队列各 8 项，单个完整 IP 包最多 `min(tun.mtu, 2048)` 字节。
发送后 pending 只保留地址、原始与 wire identifier/sequence、长度、SHA-256 摘要、期限和许可，不保留 payload。
物理答复须携带有效接收接口与本地地址元数据，并匹配实际对端、校验和、wire 标识、长度、摘要及未过期记录；重复或不匹配答复丢弃。
到期、发送失败、队列满或取消均释放对应所有权；不增加重传、无界目标表或待发送积压。
这些是局部资源边界，不是进程 RSS 上限。

真实答复和本地合成答复均恢复原 TUN 请求的 identifier、sequence、地址方向与 payload，
重建最小 IP 头、TTL/Hop Limit 64 及校验和。本地合成继续使用 netstack 的原有 MTU 和有界 raw 出站队列，
不受真实转发的 2048 字节上限限制。真实答复进入独立有界通道，与 TCP/raw、UDP、DNS 共用唯一 TUN writer；
许可保留到写入完成、最终丢弃或取消。Stop 取消并等待驱动、reader 与 writer，释放 pending、队列和物理 socket；
返回后不再向 TUN 回包。上述物理路径仅限 Linux，不扩展其他平台的权限或网络设置职责。

TUN 的被动 TCP 与 MASQUE 的内部主动客户端均支持 ICMP PMTU 反馈：验证外层校验和、本地地址、
被引用的活动 TCP tuple 及实际发送且尚未确认的序号，只降低对应连接的 MTU并重新分段。
IPv6 宣告 MTU 小于 1280 时忽略，IPv4 小于 68 时取 68。
分段使用官方 smoltcp 的包层适配，重传沿用其 TCP 定时器；元信息保存已发序号，
不保留报文正文，容量独立有界，关闭连接时清除。其他 ICMP error 不转发或创建新流，
不改变 TUN 的 MTU 门禁或 Echo 配置。

## TUN DNS 入口

当 `dns.enable: true`：

- 匹配 `tun.dns-hijack` 的 TUN UDP 在普通 UDP 关联建立前进入 DNS 快速路径；
- 匹配目标的 TUN TCP 保留 netstack TCP 状态和两字节 DNS 长度帧；
- 两者与惰性解析和内部查询共享缓存、singleflight 和上游连接。

`tun.dns-hijack` 缺省为 `[0.0.0.0:53]`，显式 `[]` 关闭劫持。
每项接受 `IP:port` 或 `any:port`；与 Mihomo 相同，若包含 `://`，忽略此前的任意前缀，
仅解析后面的端点。前缀不决定传输协议，`https://` 也不表示启用 DoH。
精确端点匹配 IP 和端口。未指定 IP（`0.0.0.0` / `::` / `any`）
跨地址族匹配业务 53 端口，包括配置未指定地址项的端口写为其他值的情况。

当 `dns.enable: false`、列表为空或目标不匹配时，不做劫持或地址改写，而是保留原目标并作为普通业务流量执行规则。非 TUN 入站不使用这份劫持列表。

UDP 读取器只做有界 wire 分类和任务提交，不同步等待上游。合法 DNS 数据报不创建或刷新普通 UDP 关联。

| 查询 | 处理 |
| --- | --- |
| IN/A | 类型化解析和缓存，可生成 TUN 域名提示 |
| IN/AAAA | 类型化解析和缓存；有效 IPv6 能力关闭时本地返回 NODATA |
| 其他合法 IN qtype | 原始 wire 转发和缓存，不生成域名提示 |

SVCB、HTTPS、TXT、PTR、MX、SRV、NS、SOA、DNSSEC 和未知 16 位 qtype 都可按原始查询转发。A/AAAA 响应中的可达 CNAME 链继续执行严格地址和 TTL 校验。

redir-host 域名提示在 DNS 开启且规则需要域名或已启用嗅探时创建，供业务入口共用。DNS 提示本身不改写目标；嗅探是否覆盖目标由 override-destination 控制。

## 嗅探

HTTP/TLS 用于 TUN 与 mixed TCP；QUIC v1/v2 多包识别由 TUN 和已授权的 SOCKS5 UDP 共用。
`parse-pure-ip` 控制无域名目标，`force-dns-mapping` 控制 redir-host 提示，均默认 true。
fake-IP 恢复后的域名与显式域名只在 `force-domain` 匹配时强制嗅探。
`skip-src-address` / `skip-dst-address` 在读取前排除地址；`skip-domain` 排除识别结果。
域名项支持通配、GeoSite 和 domain/classical 规则集合；地址项支持 CIDR、GeoIP 与
ipcidr/classical 集合。classical 对完整 AND/OR/NOT 求值；只提供对应域名或目标 IP，
其余元数据沿参考零值 TCP/HTTP、端口0、空入口名和未知身份，不发起地址解析或进程扫描。

全局 `override-destination` 默认 true，协议级值优先。false 只将识别域名提供给规则，
保留实际目标；true 替换为识别域名，DIRECT 或必须 IP 的传输再解析。
UDP 覆盖保留原始目标供回包使用，活动流不随后续查询变更。

HTTP/TLS 端口可重叠。每连接共享最多 64 KiB 预读，首字节最多一秒，随后解析最多一秒；
优先识别 TLS，再识别 HTTP。失败、超时或跳过均保留已读数据供业务转发。
HTTP 识别 HTTP/1.x Host、absolute-form 与 CONNECT 目标，以及 HTTP/2 首个请求的 authority/Host。
HTTP/2 接收完整 HEADERS/CONTINUATION 后解码 HPACK，动态表上限 4 KiB，最多 128 帧/字段，
编码与解码字节受相同 64 KiB 预算限制；歧义字段或非法帧不产生域名提示。
TLS/QUIC 识别 ClientHello，检测到 ECH 时不使用外层 SNI。
不嗅探劫持的 DNS。没有列出任何协议时不读取业务数据。

## Fake-IP

`enhanced-mode: fake-ip` 在 TUN DNS 回答 A/AAAA 时分配合成地址；hosts 优先。
TCP 和 UDP 的 TUN / mixed 入口恢复域名后选路，节点、DIRECT 与必须 IP 的出站通过内部解析器取得真实地址。
SVCB/HTTPS 在选择 fake-IP 时返回空回答；过滤到真实地址的查询仍转发。

IPv4 池默认 `198.18.0.1/16`，IPv6 池默认关闭。每个池从网络地址 +4 开始分配，
排除广播地址并循环复用；没有配置相应地址池时返回 NODATA。
`fake-ip-ttl` 最小为一秒，只控制 DNS 回答 TTL。内存模式每个地址族最多保留 1,000 项，
按使用情况淘汰。未知或已淘汰的合成地址不能作为真实目标拨号。

`fake-ip-filter-mode` 支持 blacklist、whitelist 和 rule。前两种使用域名通配、GeoSite 或
域名规则集合；rule 按声明顺序匹配域名规则并使用 `real-ip` / `fake-ip` 动作，未匹配时分配。
默认 blacklist 只包含三个 Microsoft 连通性探测域名，详见配置示例。

`profile.store-fake-ip: true` 将双向映射和分配位置写入 `dataDir/fake-ip.redb`，
写入完成后才返回地址。磁盘存储的缓存有界，映射不受内存模式的 1,000 项限制。
相同地址池在重启后保留系统 DNS 缓存中的旧地址；修改池范围时清除对应地址族映射。
资源更新共享当前地址池，过滤器可独立更新。关闭持久化后重启不保证旧映射有效。
活动 UDP 流保留首包选择和真实目标，并使用独立传输区分解析到相同真实端点的不同名称；
回复恢复原合成地址，空闲和停止时释放。

## Nameserver 与出口

```yaml
dns:
  enable: true
  ipv6: true
  nameserver:
    - "tcp://1.1.1.1:53#main-select"
  nameserver-policy:
    "+.example.com": "223.5.5.5"
    "geosite:private,cn":
      - "tcp://223.5.5.5:53#DIRECT"
```

### Endpoint

- `dns.enable`、`dns.ipv6` 默认 false。主 nameserver 默认使用 DoH/DoT，可显式替换为非空列表。
- 接受裸 IPv4/IPv6、`udp://`、`tcp://`、`tls://`、`https://`、`http://` 和 `quic://`。加密连接复用会话的内置、可读系统与 `tls.custom-certifactes` 信任根；各解析角色及 WireGuard/MASQUE 私有 DNS 同样适用，平台边界见 [TLS 契约](tls-client-fingerprint.md)。HTTPS 根据实际 ALPN 使用 HTTP/2 或 HTTP/1.1；没有 ALPN 时使用 HTTP/1.1。明文 HTTP 仅支持 HTTP/1.1，不启用 h2c。
- `rcode://success`、`rcode://format_error`、`rcode://server_failure`、`rcode://name_error`、`rcode://not_implemented`、`rcode://refused` 分别返回本地 RCODE 0–5；可用于 nameserver、policy、fallback、节点和直连 resolver，不能用于 default-nameserver。
- 同一个上游列表中存在本地 RCODE 时使用第一项本地响应，不建立网络连接，也不把 SERVFAIL/REFUSED 当作上游故障重试。响应保留原查询的 flags 和 additional，仅设置 QR 与 RCODE；不额外开启 RA，不写入结果缓存。
- `dns.ipv6: false` 不限制 IPv6 nameserver；顶层 `ipv6: false` 会阻止通过 DIRECT（含 `RULES` 选中 DIRECT）的 IPv6 nameserver 在本机物理建链，并继续当前组的故障转移。
- 上游域名由 `default-nameserver` 引导解析，后者允许 IP 上游和显式 system。未启用 DNS 时，内部解析使用系统 resolver；启用后不因查询失败回退系统解析。
- `system`、`system://`、`dhcp://system` 使用物理系统 DNS；`dhcp://<精确接口名>` 仅使用该接口的 DHCP DNS，不匹配其他接口。各 nameserver 角色、policy 和 fallback 均支持；DHCP 接口不能用于 default-nameserver。来源始终直连物理接口，fragment 与 respect-rules 不改其出口。
- 无 fragment 时默认 DIRECT；`respect-rules: true` 改为 RULES，要求非空 `proxy-server-nameserver`。
- Fragment 使用 `#出口或接口&参数=值`；出口接受 `DIRECT`、`COMPATIBLE`、`REJECT`、`REJECT-DROP`、`RULES`、实际代理节点名或支持的代理组名。
  仅提供参数时沿用默认出口；整个 fragment 先百分号解码，再按 `&` 和首个 `=` 拆分，
  同名参数和出口 token 以后项为准。节点/组名称优先，没有同名目标时作为物理接口名。
  指定接口直接连接该 DNS 上游，覆盖全局接口、沿用全局 mark；接口失效时失败，不回退。
  DoT/DoH/DoQ 的连接池身份包含接口，不能跨接口复用。未知键值参数拒绝。
  system/DHCP 来源始终使用物理出口，忽略出口 token；节点私有 DNS 也忽略出口 token。
- `#RULES` 只按 nameserver endpoint 和传输执行业务规则，不把 DNS question 当作选路域名。
- 规则模式下，UDP 跳过不支持 UDP 的节点或组，继续匹配后续规则；显式出口和 global 模式不做此跳过。
- `RULES` 与业务 TCP/UDP 使用同一子规则求值器：`SUB-RULE`、`PASS`、`PASS-RULE` 的作用域一致，`rematch` 与 `REMATCH-NAME` 保留同一决策上下文；规则控制和组控制先于 UDP 能力检查。
- `COMPATIBLE` 使用直连语义；`REJECT` 结束当前尝试，`REJECT-DROP` 的 TCP 等待仍受当前 DNS 查询期限和 Stop 限制，UDP 立即结束。失败后继续当前上游组下一项。

代理组成员可以是具体节点、嵌套组、`DIRECT`、`COMPATIBLE`、`REJECT`、`REJECT-DROP`、`PASS` 或 `PASS-RULE`。PASS、PASS-RULE 和具名 rematch 仅在 rule 模式的 `RULES` 中参与规则流程；global 模式、显式命名组/节点或 dialer-proxy 选中控制目标时拒绝连接。DNS exchange 需要新建物理 transport 时解析当时的当前叶节点；选中成员失败不会使代理组自动改选，但 nameserver 列表仍按本节已有故障转移语义继续下一项。

### 上游参数

UDP/TCP/DoT/DoQ URL 只消费主机与端口；userinfo、路径和 query 与 Mihomo 一样忽略，
不形成认证或请求路径。fragment 的上游参数仍按下述规则消费。

`ecs` 接受 IPv4/IPv6 IP 或 CIDR，裸 IP 使用完整位数。已有 EDNS ECS 默认原样保留；
`ecs-override=true` 只替换首个 ECS，保留其 scope、OPT flags 和其他 option，编码时掩去前缀外的位。
缺少 OPT 时添加 UDP size 为零的新 OPT。包装作用于所有解析角色和 system、DHCP、RCODE，
DHCP 接口名只取 URL endpoint，fragment 不参与接口查找。

`disable-ipv4=true`、`disable-ipv6=true` 和 `disable-qtype-<编号>=true` 抑制对应 question，
直接返回 NOERROR 空响应并设置 AA、RA，不读取来源或建链；编号限固定 Mihomo 参考已有 RR constructor。
其他请求先验证上游响应，再过滤 Answer、Authority、Additional 中对应 RR。
全报文通过官方 `domain` codec 重编码，保持所有存留名称引用有效；RFC 3597 未知 RDATA 保持原始字节。
报文大小、记录数和名称压缩跳数仍受本节预算约束，不能通过过滤移除错误记录来绕过验证。
类型参数和 `ecs-override` 仅在字面 `true` 时启用，与顶层及 DNS 的 IPv6 门禁独立。

DoT/DoH/DoQ 的 `skip-cert-verify=true` 和 `name-cert-verify` 接共享 TLS 安全层，显式名称验证
先于跳过验证且不改变 SNI。`disable-reuse=true` 仅使指定 DoT 上游每次新建并关闭连接，
不改变 HTTPS 或其他上游的复用。不同参数的上游保持池身份隔离。

### DoH 请求

URL 只保留协议、带默认端口的主机、路径和 userinfo；丢弃原 query/fragment。
路径按解码后的值重新编码，userinfo 百分号解码后生成 `Basic base64(用户名:密码)`，
省略密码视为空串。认证值不出现在 Host、请求路径或 Debug/日志中，也不会跨池身份复用。
请求使用 GET、`Accept: application/dns-message`，没有 body 和默认 User-Agent；
`dns=` 为完整 DNS wire 的无 padding Base64URL。传输前 ID 改为 0，响应 ID 必须为 0，
之后恢复原 ID 并执行原有 question、完整报文及缓存校验。

H1/H2/H3 的请求及响应头各限 16 KiB，DNS body 仍限 4,096 字节。
仅接受 HTTP 200 与 `application/dns-message`，响应长度声明、分帧及完整 DNS 校验必须通过。

`dns.prefer-h3` 默认 false。true 时 HTTPS 的冷初始化同时建立已认证的 TCP TLS 与实际 H3，
第一条成功连接用于查询；某条先失败时继续等待另一条。TCP 获胜时取消 QUIC 初始化并等待其 driver / adapter 收尾；
H3 获胜时丢弃本次 TCP checkout，底层已开始的初始化由 Dialer / connector 的 Stop barrier 回收。
这不是 DNS 响应竞速；已选 H3 的查询失败不自动重放到 TCP。复用已选连接，H1/H2 的版本选择最多保留 4 项、空闲 30 秒，失败后重新选择；不为每次查询重新探测。
`https://…#h3=true` 仅建立 H3，失败不能降级；明文 HTTP 的 h3/prefer-h3 不改变 H1 行为。
bootstrap、主、节点和直连 DNS 角色均应用全局 prefer-h3；WireGuard/MASQUE 私有 DNS 与固定参考一致，
不继承全局偏好，但支持 URL `h3=true`。H3 共用 GET/Basic/ID 与包装，不启用 0-RTT 或恢复，
使用官方 Quinn、h3 与 h3-quinn，通过共享 TLS 1.3 / rustls 证书政策建立严格 `h3` ALPN；DoQ 同样使用 Quinn。
普通 H3 请求 FIN 不等待逐请求 QUIC ACK。取消丢弃当前请求所有者，未完成发送 reset，接收半关闭使用原生 STOP(0)，
不关闭仍可用的兄弟请求；响应错误仍使该连接不再接受新查询。GOAWAY 停止新请求准入，已存在的查询可完成。

### DoQ

`quic://host[:port]` 默认 853，使用受控 UDP、TLS 1.3 与实际 `doq` ALPN。
每条查询使用独立双向 stream：两字节网络序长度、完整 DNS wire，ID 设为 0，并结束写方向。
响应必须是一份 12..=4,096 字节的完整 DNS message，ID 为 0，读至 FIN 后恢复原 ID 并校验；
空长度、超限、截断或额外消息均拒绝。并发查询共享连接，取消只停止当前 stream。
DoQ/H3 都沿用原 DNS 路由、bootstrap、证书政策与查询包装，不新增 socket 工厂或系统解析回退。
独立 `dns-quic` feature 提供两种能力，默认构建和 Invoke 生产入口启用；显式关闭该 feature 的
精简 Core 构建拒绝 `quic://`、`prefer-h3: true` 和 HTTPS `h3=true`，不会接受后忽略。

### Policy

`nameserver-policy` 是有序映射：

- 项数与 GeoSite 唯一引用数不设独立上限，仍受整个 YAML 输入大小约束；
- 接受普通域名和 Clash 通配域名，也可以用逗号连接多个模式；域名不区分大小写。
  `*.example.com` 匹配一层子域，`.example.com` 匹配所有子域，`+.example.com` 包含本域和所有子域；
- 连续域名项合为一个区块，按字面标签、`*`、前导 `.` 的优先级匹配；同一区块内重复的归一模式以后项为准；
- `geosite:<selector>[,<selector>...]` 同一项内为 OR，前缀不区分大小写；每个 selector 可为
  `code`、`code@attr@attr` 或前置 `!` 的反选，属性为 key 存在性 AND。与业务规则共享分类和记录，
  `@!cn` 是字面属性 key，不是属性排除；
- GeoSite 项隔开域名区块，区块与 GeoSite 项按声明顺序匹配；重复 GeoSite selector 也按此顺序处理；
- value 接受单个 nameserver 字符串或非空数组；`rule-set:` 引用 domain/classical 集合。
  classical 以域名和其余零值元数据执行完整逻辑；不继承触发查询的业务端口、来源或入口身份；
- 命中后只在所选列表内并发查询，列表耗尽不查询其他 policy 或主组；
- GeoSite 资产或分类不可用时该 policy 不命中，不能因反选变成全匹配；
- 存在分类但属性筛选为空时仍可用，正选不命中、反选匹配合法非空名称。

hosts 和 fake-IP 分配先于 policy；命中 fake-IP 过滤器、需要真实响应时才应用 policy 中的 RCODE。
policy 的本地响应不进入 fallback；主 nameserver 的本地响应没有地址，已配置 fallback 时沿用
本节的 fallback 选择规则。未配置 fallback 时直接返回本地响应。

Policy 只决定当前 DNS exchange，不改写后续业务动作。分类、属性归一和语义边界见
[GeoData 规则](geodata.md#规则)；所有平台均不按 GeoData 条数截断记录。
每次同步 policy 选择捕获一份不可变 GeoData 快照，所有 selector 与 policy 项共用，
不在一次求值中混用旧代、空快照和新代。捕获空快照时跳过 GeoSite 项，继续其余 policy；
均未命中时使用主组。普通域名 policy 不依赖 GeoData。
快照在选择函数返回时释放，不复制规则，也不跨后续上游 I/O 的 `await` 持有。
Regex selector 记录与业务规则共用 `regex::bytes::Regex`；其搜索缓存由正则库管理，
可能分配 scratch 或发生缓存竞争，不承诺 DNS policy 正则搜索零分配。

业务规则中的 DOMAIN-REGEX 与 classical rule-set 使用有界的独立复杂正则入口；GeoSite
保留大小写敏感的线性入口。DNS 请求的 fake-IP filter、nameserver-policy、fallback domain
及 respect-rules 出口共用执行预算，并跨 A/AAAA、别名、引导和并发上游候选保留。规则
执行错误不选择默认上游、fallback、系统 DNS 或 synthetic IP，不写入缓存/域名提示；
wire 查询返回 SERVFAIL，内部解析返回脱敏规则错误。嗅探计划的地址/force/skip 选择同样
共享预算，错误关闭当前会话/数据报，不忽略该失败继续连接。

### 显式系统与 DHCP 来源

App 通过运行时级 [`updateDnsNetwork`](invoke-api.md#updatednsnetwork) 提供完整网络快照，地址必须是字面 IP，接口必须精确。快照优先于 OS 发现，空数组明确撤销来源。替换时原子推进 DNS epoch 并清理全部角色的类型化/wire 缓存及 redir-host 提示；保留 fake-IP 映射和活跃流。旧查询可返回原调用者，但不能回填新网络缓存，新查询不加入旧 singleflight。DNS TCP 连接池按来源代次、接口和地址区分复用。

Linux CLI 无宿主快照时仅调用已有 `/usr/bin/busctl`，读取 systemd-resolved 的物理 link DNS 或 NetworkManager 已激活接口的 DHCP4 `domain_name_servers`；原生 DHCP 还需现有 resolved link 的加密策略，无法确认策略时不可用。不启动服务、不读 VPN stub、不发送 DHCP DISCOVER，也不读取其他接口的租约。发现仅在后续 DNS miss 按需刷新，元数据缓存 20 秒；到期本身不主动清结果缓存。重新发现的 endpoint、加密要求或绑定变化时，原子推进共享 epoch/source generation 并清 cache/hints，连接池不能复用旧来源 key。整体发现期限 3 秒，stdout/stderr 各限 64 KiB；取消会关闭并等待子进程。缺服务、无可靠租约或加密要求无法满足时来源不可用。被接管的 TUN 接口、回环/stub 地址和自身网关被排除。与 Mihomo 主动 DISCOVER/DHCPOFFER 的 DHCP 来源机制不同。

Apple 使用宿主快照和 `IP_BOUND_IF`/`IPV6_BOUND_IF`；App 负责取得真实物理 DNS 数据。Android 和 Wintun 当前没有可证明的精确物理接口绑定，显式 system/DHCP 来源不可用，不改变现有 protect 与宿主网络隔离合约。UWP 仅在实际 Session Host 的既有物理 GUID 绑定内发现系统 DNS；前台 Invoke registry 不是 IPC，不能通过它更新另一个进程的 VPN 会话。DHCP 租约 metadata 不可靠时保持不可用。来源要求加密但当前 UDP/TCP 路径无法满足时失败关闭，不降级为明文，也不补充公共 DNS。


## Fallback

`fallback` 只作用于主 resolver 的 A/AAAA。先应用 nameserver-policy；命中的 policy
独立查询自己的上游，不再进入 fallback。否则，`fallback-filter.domain` 的 Clash 通配
命中时直接查询 fallback，不启动主组。GeoSite 分流使用 `nameserver-policy` 配置。

其余查询先取主组结果。主组失败、没有地址，或任一地址命中 `ipcidr` / GeoIP 条件时
使用 fallback 的结果。`geoip` 默认 true、`geoip-code` 默认 CN：非本地且不属于该分类的
地址触发 fallback；私有、回环、链路本地、多播和未指定地址不触发 GeoIP 条件，
但仍可被显式 `ipcidr` 匹配。GeoData 与业务规则共用快照；缺失分类不当作反选全匹配。

`fallback-lazy-query` 默认 false，两组并发查询，主组结果可接受时立即返回并取消剩余尝试；
true 只在确定需要时发起 fallback。fallback 返回后不再次套用过滤条件。
选定的最终结果进入主 resolver 缓存，fake-IP 回答和 hosts 不触发上游查询。
bootstrap、单独配置的节点/直连 resolver，以及非地址 qtype 不使用这组 fallback。

## Wire 校验

- DNS message 最大 4,096 字节。
- 只接受 opcode QUERY、恰好一个 IN question；query 不能含 answer 或 authority。
- 允许结构合法且受总大小限制的 EDNS additional record。
- 保留原始 16 位 qtype。
- Response 必须匹配 peer、QR、opcode、transaction ID 和完整 question。
- Name compression 最多跳转 16 次，response 最多扫描 64 条记录。
- 类型化缓存和提示最多保留 16 个唯一地址。
- 非法长度、压缩循环、尾随字节或错误帧格式都会失败关闭。
- TCP frame 长度必须为 1..=4,096，非法 frame 关闭当前 DNS 流。

## 缓存与 singleflight

### 结果缓存

`dns.cache-max-size` 控制每个 DNS 角色的结果总条目数，缺省或零值为 4,096。
A/AAAA 的类型化结果和其他 qtype 的原始响应共享这份容量与替换策略。
客户端携带 EDNS 或额外语义 flags 的 A/AAAA 使用同一有界原始响应缓存，以完整查询摘要区分
ECS、DO、CD 等上下文并保留响应 additional/flags；普通 A/AAAA 仍使用小型地址缓存。
`dns.cache-algorithm` 精确为 `arc` 时使用 ARC，缺省和其他字符串使用 LRU。
LRU 命中和替换将条目移到最近使用端；满容量时淘汰最久未使用的结果，命中不延长 TTL。
哈希索引和安全槽位链表按需分配，查询时只检查命中条目的寿命。运行时过期正结果按下节返回旧答复并刷新；其他过期结果重新查询。
类型化结果仍最多保留 16 个地址，负缓存仍保留 30 秒。
TUN 域名提示独立保留最多 256 项并按 TTL 失效；fake-IP 映射不计入这份结果缓存。

ARC 分别保留近期与常用结果，命中提升到常用组，使用两组淘汰历史自适应调整比例。
历史项只保留 key 和过期时间，不持有地址或原始响应；有效结果最多为配置容量，
历史项最多为同样容量，所有索引和槽位最多为两倍容量。
旧正结果仍占 resident 容量，旧答复只更新原列表内的最近使用顺序，不提升到常用组；超过旧答复保留期或历史项到期时直接删除，不新增淘汰历史。清空和解析器释放会回收结果、历史项及其存储。

### 原始响应缓存

- 在结果总容量内额外限制为最多 64 项、总保留内存 256 KiB，单响应最大 4,096 字节。
  原始响应的 key、TTL 偏移及条目索引/链表元数据计入字节预算，ARC 的原始响应历史项也计入。
  此预算满时先删除原始响应历史项，再淘汰最久未使用的原始响应，不改变 ARC 的自适应比例。
- Key 包含规范化 question、qclass、qtype 和移除 transaction ID 后的完整查询语义 SHA-256。
- 命中时恢复调用方 transaction ID 和 RD，并按剩余寿命更新所有可缓存 TTL。
- 正缓存寿命取可缓存记录的最小 TTL，并限制在 30–3,600 秒。
- NXDOMAIN 固定负缓存 30 秒；NOERROR 空 answer 只有在 authority 含 IN/SOA 时才缓存为 NODATA。
- Referral、TTL 0、无可缓存记录和扩展错误码不缓存。
- 非地址 qtype 的原始响应不生成 TUN 域名提示；A/AAAA 仍按既有地址校验生成提示。

### 过期答复与刷新

运行时的完整正结果到期后，以 TTL=1 立即回答，并在后台刷新。旧结果最多保留到原到期时间后一小时，命中不延长寿命；它与新结果共用原有容量及原始响应字节预算，不另设旧记录池。原 TTL 为零、负答复、错误和不完整结果不延续为旧答复；hosts 与 fake-IP 仍在结果缓存之前处理。

原始响应带 DO、AD、CD 或 DNSSEC 记录时仅按原有效期缓存，不返回过期安全声明。普通类型化 A/AAAA 缓存只保存地址并重新合成无 AD/CD 的响应；非地址 qtype 不产生域名提示。过期 A/AAAA 沿当前 epoch 和资源退役门禁补充有界域名提示，提示仍使用原容量和 TTL 规则。

每个会话的 DNS 树及节点私有解析器共享最多四个后台刷新许可，无待执行队列；每个 key 复用原 singleflight，失败完成后五秒内不重试。单次刷新沿原五秒总查询期限。许可不足或已有刷新时仍立即返回旧答复。各资源树与私有解析器分别拥有取消和任务等待屏障，停止一个节点不停止主解析器；资源退役禁止新增刷新并取消旧刷新。Stop 等待全部刷新结束，不留下无所有者任务。没有运行时所有者的独立解析器保持原有过期 miss 行为。

### Singleflight

未命中缓存时，以规范化 question、wire 语义摘要和缓存 epoch 作为 key：

- 前台 miss 的 Leader 在发起方任务内运行；过期命中不等待，刷新 Leader 由上述运行时所有者持有；
- Leader 被取消或释放时，RAII 通知 follower 重新选举；
- 每个调用方恢复自己的 transaction ID 和 endpoint，并独立应用失败策略；
- 不同 key 可以并行。

### 清理

Controller `POST /cache/dns/flush` 清理主 resolver、bootstrap、节点和直连角色的类型化与
原始响应缓存、ARC 历史项和 redir-host hints。所有角色共享一次 epoch 边界；清理完成后
的新查询不能加入旧 singleflight，旧在途查询仍可向原调用方返回结果，但不能回填缓存或 hints。
资源替换保留这份 epoch，旧资源 generation 也不能回填共享 hints。
fake-IP 映射、活动业务会话、在途查询和上游连接池继续保留。

## Hosts 与解析职责

`hosts` 支持 IP、IP 数组和域名别名，匹配规则沿用 Clash 域名通配；默认包含 localhost，别名循环在配置阶段拒绝。`use-hosts`、`use-system-hosts` 独立控制配置与系统 hosts，默认均为 true；系统 hosts 在运行时创建时读取。TCP、UDP 节点的 TLS SNI 和逻辑目的名称不因解析为 IP 而改变。

值恰好为 `lan` 或 `[lan]` 时，启动准备捕获全部接口 IP，排除回环和 link-local，
包含可用的公网与 TUN 接口地址，不仅限私有网段。校验只保留内部标记，不读取网卡。
无可用地址或枚举失败使启动失败；运行期间及 Provider 更新均保留启动快照。

`default-nameserver` 仅引导上游域名。`proxy-server-nameserver` 与其 policy 用于节点解析；`direct-nameserver` 用于直连，`direct-nameserver-follow-policy` 决定是否使用业务 policy。各角色拥有独立 cache/singleflight，未配置节点或直连 resolver 时复用主 resolver。有限并发、取消与连接池适用于各角色，依赖循环不会等待自身的 singleflight。

启用有效 IPv6 时，内部地址解析并发请求 A/AAAA，结果按 IPv4、IPv6 排列。
`dns.ipv6-timeout` 单位为毫秒，缺省或 0 使用 100；从 A 完成后开始等待 AAAA，
不改变整个解析的五秒期限。任一地址族失败不丢弃另一族的有效地址；等待到期或调用方
取消时释放未完成查询。IPv6 关闭时只查询 A。TUN 客户端直接 A/AAAA 查询仍保留原有
wire/RCODE 语义，不使用这段地址合并等待。

## 查询、故障转移与连接复用

- 查询总期限 5 秒；单 nameserver 尝试最多 3 秒，并受剩余时间限制。
- UDP 尝试只打开一个传输；首次发送后 1 秒无合法响应时，在同一传输和 ID 上最多重发一次。
- 前两次 peer/ID/question 不匹配只丢当前响应，第三次使当前尝试失败。
- 同一上游策略最多同时发起 4 个实际 endpoint 尝试，字面上游和显式来源展开的 endpoint 共用许可；bootstrap/fallback 是独立子查询，不是全链或全局 socket 额度。优先返回有效响应并取消其余尝试。超时、I/O、格式错误、SERVFAIL、REFUSED 或 REJECT 不作为成功结果。
- 未启用 fallback 或命中 nameserver-policy 时，NXDOMAIN 和 NODATA 是终态。
- 验证来源、ID 和 question 后，UDP TC 在原期限内改用同一 endpoint 的 TCP。TCP TC 仍是失败响应。
- 全部上游失败时生成 SERVFAIL；非法 UDP 查询只丢当前数据报。

TCP、DoT 和 DoH 使用解析器所属的连接池：

- Key 包含上游地址、TLS 验证策略、查询包装、传输、HTTP 路径与 Basic 身份、endpoint、最终 route target、
  来源 generation 和物理接口绑定；
- TCP、DoT、HTTP/1.1 一条连接只处理一个查询，不做 pipeline；这部分空闲连接总数最多 4、同 key 最多 2、超时 30 秒；
- HTTP/2 同 key 首次建连串行发布，之后共享 sender；每连接最多 32 个并发 stream，超出时在查询原期限内等待。流接收窗口 4 KiB、连接接收窗口 128 KiB，禁用 server push；H2 空闲连接另限 4、超时 30 秒；
- DoQ/H3 同 key 串行初始化后复用，每连接最多 32 条查询；QUIC stream 固定接收窗口 4,098 字节、connection 接收窗口 128 KiB，发送额度 128 KiB，不接收服务器双向 stream 或 QUIC DATAGRAM。DoQ 不接收单向 stream；H3 最多接收 8 条单向 stream，控制流与业务流均从 4,098 字节信用开始，消费后由 Quinn 通告后续信用。该信用不是完整 HEADERS parser 内存上限。空闲 QUIC 连接另限 4、超时 30 秒；
- 活动物理连接不设固定业务数量上限；完整响应校验后才能归还 H1 连接或继续复用 H2；
- TCP/DoT/H1 复用连接遇到 EOF、I/O、reset 或响应不匹配时，在原尝试期限内最多新建一次连接；
- 非法、截断或超限响应不重试、不归还连接。

HTTP/2 单流取消发送 RST，其他流可继续使用原连接；响应错误使该连接不再接受新查询。
解析器拥有连接 driver 与有界空闲回收任务，Session Stop 和资源代际退役关闭全部解析角色并等待 driver 结束；WireGuard/MASQUE 私有 DNS 同样由节点 Stop 关闭且不保留空闲连接。MASQUE IP 查询经过节点内部栈，L4 仅可使用 TCP DNS 传输；system/DHCP 始终沿物理来源策略，不因节点模式改变出口。
DoQ/H3 的连接取消和退役最多等待一秒 QUIC close exchange，随后停止并等待
Quinn 原生任务与受控 datagram driver；未发布初始化、握手取消和移交前的准备失败同样属于此 Stop 所有权。
初始发送 MTU 为 1200 字节，H3 的 PMTUD 上限受当前发送路径预算约束；接收广告独立使用实际接收预算，
不把 fixture 中的 4096 字节接收值作为所有路径的统一上限。任一方向不足 1200 的 QUIC 路径拒绝。
H3 在非 DATA 帧声明长度完整时提前检查：HEADERS 编码长度最多 24 KiB，SETTINGS 最多 256 字节，
CANCEL_PUSH / GOAWAY / MAX_PUSH 长度为 1..8 字节，PUSH_PROMISE 最多 24 KiB 加 8 字节且非空。
未知 H3 帧也限 24 KiB，超限立即拒绝，不先累计完整 payload；这比 quiche 对未知帧最多 16 MiB 的跳过范围更严格。
DATA 仍按应用读取流式处理，DNS body 保持 4096 字节限制；QPACK 与未知单向 stream 的分类沿官方 h3 实现。

Controller 切换代理组后，只在后续需要创建新 DNS transport 时使用新选择。类型化/原始响应 cache、singleflight 状态和已经位于 TCP pool 中的 transport 不清空、不迁移；因此命中 cache 或复用既有 TCP transport 时，不会为切换单独建链。停止 session 才统一释放这些状态。

## 队列与生命周期

| 队列 | 容量 |
| --- | ---: |
| 每普通 UDP 关联入站 | 64 |
| DNS 响应 | 128 |
| 普通 UDP 响应 | 256 |

reader 在进入 TCP netstack 前分流 UDP，拥有按源地址建立的关联表，没有共享 UDP 入站接收器或独立 DNS 请求准入数。每普通 UDP 关联有独立请求队列；DNS 查询继续提交受跟踪的任务，不等待上游。入站或 DNS 响应队列满时只丢当前数据报，不阻塞 reader。普通响应队列满时，每源关联最多暂持一个已接收响应并暂停继续接收，等待容量期间仍可发送请求或取消，不增加任务；取消或错误时丢弃未提交响应。TCP accept 仍为 128 项。TUN UDP 响应按有效 MTU 减去 48 字节保守限制；默认 9000 MTU 时为 8,952 字节；显式 1500 为 1,452 字节，Windows UWP 使用 1400 时为 1,352 字节。

唯一受跟踪的 TUN writer 公平读取普通 UDP、DNS 和 TCP/ICMP raw 通道，Linux 的真实 Echo 使用第四个有界通道；任一通道关闭不丢弃其他通道的待写响应。UDP 构包后直接写平台，不再转发到共享 raw output。DNS 查询观测 permit 保留至该包被平台接受、最终丢弃或取消，写回阻塞和 ENOBUFS 重试不提前释放；WinRT Adapter 成功处理不等于框架最终交付。MTU/地址族错误只丢当前响应。

运行时停止会取消 open、send、receive、retry 和 response-send，释放全部传输并等待已跟踪任务结束。停止返回后不得再向 TUN 回包。

普通非 DNS UDP 关联不设固定总数，采用代次感知所有权和 `tun.udp-timeout` 空闲超时，缺省或零值为 300 秒；清理周期为该期限与 10 秒的较小值。只有成功入队的请求或响应刷新活动时间。

普通 TUN UDP 的 IP 目标在源关联内按目的 IP/端口固定规则 action，即五元组独立
选路，不把整个源的所有目标固定到同一个动作。首包完成嗅探/选路后，活动流不随
DNS 提示或 GeoData 更新改路；新流使用当前数据。每目标按同一个 `tun.udp-timeout` 独立空闲失效，
10 秒间隔借既有关联收发回收；无逐流任务/队列/socket。新认证 QUIC 连接的首包
重新选路，同连接 Initial 重传不重选。具体边界见 [GeoData 生命周期](geodata.md#生命周期)。
匹配配置的 DNS 劫持仍先于普通关联，每个查询独立执行 nameserver-policy，不受五元组固定影响。

## IP-only协议与独立测速接点

`experimental.dialer-ip4p-convert` 只在已声明的物理 connected TCP 和指定 UDP 节点端点生效。
物理端点解析后先解码、再按实际 IPv4/IPv6 应用地址族及 source/interface 绑定；
解析角色、逻辑 host/port、认证和代理链不改变。DNS 的查询族与缓存仍遵循原配置，
不自动开启 AAAA、不改写对外 DNS 记录或通用 IP-only 业务解析结果。

公共`ResolutionContext`仅在协议必须取得IP地址的边界解析业务目标或逻辑上游；原始`Destination`保持不变，HTTP Host、TLS SNI和路由仍使用逻辑名称。代理服务器在实际建链时通过节点 resolver 解析，准备阶段不解析备用节点。静态 ECH 不查询 DNS；动态 ECH 通过同一解析上下文消费节点角色的原始 HTTPS 记录。查询名可独立覆盖，不改业务/服务器逻辑名称；沿原建链期限、取消和 weak runtime 所有权，不增加 Invoke DNS 入参。DNS 关闭和独立测速使用物理 system source，不可用时失败。

Running Session上下文仅弱引用本 session 的 RuntimeDns；业务 IP-only 解析使用 nameserver/policy，代理服务器使用 proxy-server-nameserver/policy，DIRECT 目标使用 direct-nameserver。未绑定、上游不可达或 session 已停止时失败；只有配置关闭 DNS 时才使用系统解析。IP字面量仍执行端口/地址族政策。解析共享同一次建链期限，Stop取消当前及后续查询；在进入可能等待自身的singleflight之前拒绝同名递归依赖，嵌套依赖深度最多32层。不会因为DNS经代理出口就无条件禁止整个图。

独立`measureDelay`使用测量生命周期的受控bootstrap resolver，仅在IP-only边界解析域名；不创建Running Session、RuntimeDns或DNS监听服务，也不改变现有endpoint准备流程。通用 IP-only connector 覆盖最终节点和 `dialer-proxy` 上游的受控解析、期限与取消。该公共接点继续供 packetaddr 等必须 IP 的消费者使用；通用机制测试不替代各协议的实际数据闭环。

## 不支持

- Linux Echo 以外的真实 ICMP 转发、PMTU 以外的 ICMP error、Traceroute、ICMP 选路规则或 ICMP 测速；
- 运行中随接口变化自动刷新 hosts: lan；
- 用户可配置的查询总超时、重试或并发度；
- 使用 DNS question 执行业务规则，或用 DNS 出口改写后续业务动作。

自动化和物理 TUN 覆盖范围见 [验收矩阵](acceptance.md)。

## 入站规则元数据

TUN TCP 的 `IN-TYPE` 为 TUN，`IN-PORT` 为虚拟连接的原始目标端口；TUN UDP
没有本地监听端口，`IN-PORT` 为 0。两者没有认证用户，来源规则读取原始来源 IP/端口。
这与 Mihomo 默认 MIPS 栈一致；其他栈的内部 TCP listener 端口可能不同。

业务规则中的 `IN-NAME` 为区分大小写的固定入口名：TUN 为 DEFAULT-TUN；
mixed 的 HTTP/SOCKS5 为 DEFAULT-MIXED。内部请求的名称为空，不新增可命名 listeners。
Core 的 DNS、GeoData 下载及测速入口均映射为 INNER，端口为 0、用户为空。
DNS `respect-rules` 使用同一个规则求值器，但不继承触发解析的业务用户。
classical selector 的空元数据是单独参考视图（TCP/HTTP、端口0、无入口名和身份），
并不把内部 DNS 路由伪装成业务 HTTP 连接。
