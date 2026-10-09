# TUN ICMP 与 DNS

Vole 在 TUN netstack 内回答受支持的 ICMP Echo Request。启用运行时 DNS 后，匹配 `tun.dns-hijack` 的 TUN TCP/UDP、选路惰性解析和内部查询共享同一套有界 DNS 实现。

顶层 `ipv6: false` 时，IPv6 原始包会在进入 netstack 前被丢弃，因此不会触发 ICMPv6 回应或 IPv6 上的 DNS/业务流量；运行时 DNS 的有效 IPv6 能力同时要求顶层 `ipv6` 和 `dns.ipv6` 为 `true`。

## ICMP Echo

| 地址族 | 请求 | 响应 |
| --- | --- | --- |
| IPv4 | type 8, code 0 | type 0, code 0 |
| IPv6 | type 128, code 0 | type 129, code 0 |

响应会交换源地址和目标地址，保留 identifier、sequence 和 payload，重建最小 IP 头，将 TTL/Hop Limit 设为 64，并重新计算所有校验和。该路径完全位于 netstack 内，不调用 DNS、规则、出站、protect 或物理接口。

输入要求：

- 校验 IP 版本、头长度、声明长度、地址和校验和；
- IPv4 可以携带合法 options，但响应不复制 options；
- 不重组 IPv4 分片或 IPv6 Fragment Header；
- IPv6 base Next Header 必须直接是 ICMPv6；
- 非 Echo、非零 code、截断和非单播地址一律丢弃；
- 单包失败不停止 netstack，也不生成 ICMP error。

smoltcp 负责生成 Echo Reply，Vole 负责更严格的输入分类和运行时门禁。响应直接尝试进入现有原始包出站队列；队列满时只丢当前低优先级响应并更新统计，不创建等待任务或积压队列。

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

HTTP/TLS 用于 TUN 与 mixed TCP；QUIC v1/v2 多包识别用于 TUN UDP。
`parse-pure-ip` 控制无域名目标，`force-dns-mapping` 控制 redir-host 提示，均默认 true。
fake-IP 恢复后的域名与显式域名只在 `force-domain` 匹配时强制嗅探。
`skip-src-address` / `skip-dst-address` 在读取前排除地址；`skip-domain` 排除识别结果。
域名项支持通配、GeoSite 和 domain/classical 规则集合；地址项支持 CIDR、GeoIP 与
ipcidr/classical 集合，classical 只使用对应的域名或目标 IP 条件。

全局 `override-destination` 默认 true，协议级值优先。false 只将识别域名提供给规则，
保留实际目标；true 替换为识别域名，DIRECT 或必须 IP 的传输再解析。
UDP 覆盖保留原始目标供回包使用，活动流不随后续查询变更。

HTTP/TLS 端口可重叠。每连接共享最多 64 KiB 预读，首字节最多一秒，随后解析最多一秒；
优先识别 TLS，再识别 HTTP。失败、超时或跳过均保留已读数据供业务转发。
HTTP 识别 HTTP/1.x Host；TLS/QUIC 识别 ClientHello，检测到 ECH 时不使用外层 SNI。
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
- 接受裸 IPv4/IPv6、`udp://`、`tcp://`、`tls://`、`https://` 和 `http://`。加密连接复用共享 TLS 证书验证。DoH 采用 HTTP/1.1 POST。
- `dns.ipv6: false` 不限制 IPv6 nameserver；顶层 `ipv6: false` 会阻止通过 DIRECT（含 `RULES` 选中 DIRECT）的 IPv6 nameserver 在本机物理建链，并继续当前组的故障转移。
- 上游域名由 `default-nameserver` 引导解析，后者只允许 IP 上游。未启用 DNS 时，内部解析使用系统 resolver；启用后不因查询失败回退系统解析。显式 system/DHCP nameserver 尚未实现。
- 无 fragment 时默认 DIRECT；`respect-rules: true` 改为 RULES，要求非空 `proxy-server-nameserver`。
- Fragment 只接受 `DIRECT`、`RULES`、实际代理节点名或支持的代理组名。
- `#RULES` 只按 nameserver endpoint 和传输执行业务规则，不把 DNS question 当作选路域名。
- 规则结果为 `REJECT` 时，当前尝试失败并继续当前组下一项。

代理组成员可以是具体节点、嵌套组、`DIRECT` 或 `REJECT`。DNS exchange 需要新建物理 transport 时解析当时的当前叶节点；选中成员失败不会使代理组自动改选，但 nameserver 列表仍按本节已有故障转移语义继续下一项。

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
- value 接受单个 nameserver 字符串或非空数组；`rule-set:` 引用 domain/classical 集合，classical 仅使用域名条件；
- 命中后只在所选列表内并发查询，列表耗尽不查询其他 policy 或主组；
- GeoSite 资产或分类不可用时该 policy 不命中，不能因反选变成全匹配；
- 存在分类但属性筛选为空时仍可用，正选不命中、反选匹配合法非空名称。

Policy 只决定当前 DNS exchange，不改写后续业务动作。分类、属性归一和语义边界见
[GeoData 规则](geodata.md#规则)；所有平台均不按 GeoData 条数截断记录。
每次同步 policy 选择捕获一份不可变 GeoData 快照，所有 selector 与 policy 项共用，
不在一次求值中混用旧代、空快照和新代。捕获空快照时跳过 GeoSite 项，继续其余 policy；
均未命中时使用主组。普通域名 policy 不依赖 GeoData。
快照在选择函数返回时释放，不复制规则，也不跨后续上游 I/O 的 `await` 持有。
Regex selector 记录与业务规则共用 `regex::bytes::Regex`；其搜索缓存由正则库管理，
可能分配 scratch 或发生缓存竞争，不承诺 DNS policy 正则搜索零分配。

## Fallback

`fallback` 只作用于主 resolver 的 A/AAAA。先应用 nameserver-policy；命中的 policy
独立查询自己的上游，不再进入 fallback。否则，`fallback-filter.domain` 的 Clash 通配或
`geosite` 命中时直接查询 fallback，不启动主组。

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

### 类型化缓存

A/AAAA 缓存最多 256 项，从空容量按需增长。TUN 域名提示存储启用时同样最多 256 项，并按 TTL 失效。

### 原始响应缓存

- 最多 64 项，总保留内存 256 KiB，单响应最大 4,096 字节。
- Key 包含规范化 question、qclass、qtype 和移除 transaction ID 后的完整查询语义 SHA-256。
- 命中时恢复调用方 transaction ID 和 RD，并按剩余寿命更新所有可缓存 TTL。
- 正缓存寿命取可缓存记录的最小 TTL，并限制在 30–3,600 秒。
- NXDOMAIN 固定负缓存 30 秒；NOERROR 空 answer 只有在 authority 含 IN/SOA 时才缓存为 NODATA。
- Referral、TTL 0、无可缓存记录和扩展错误码不缓存。
- 原始响应缓存不生成 TUN 域名提示。

### Singleflight

未命中缓存时，以规范化 question 和 wire 语义摘要作为 key：

- Leader 在发起方任务内运行；
- Leader 被取消或释放时，RAII 通知 follower 重新选举；
- 每个调用方恢复自己的 transaction ID 和 endpoint，并独立应用失败策略；
- 不同 key 可以并行。

## Hosts 与解析职责

`hosts` 支持 IP、IP 数组和域名别名，匹配规则沿用 Clash 域名通配；默认包含 localhost，别名循环在配置阶段拒绝。`use-hosts`、`use-system-hosts` 独立控制配置与系统 hosts，默认均为 true；系统 hosts 在运行时创建时读取。TCP、UDP 节点的 TLS SNI 和逻辑目的名称不因解析为 IP 而改变。

`default-nameserver` 仅引导上游域名。`proxy-server-nameserver` 与其 policy 用于节点解析；`direct-nameserver` 用于直连，`direct-nameserver-follow-policy` 决定是否使用业务 policy。各角色拥有独立 cache/singleflight，未配置节点或直连 resolver 时复用主 resolver。有限并发、取消与连接池适用于各角色，依赖循环不会等待自身的 singleflight。

## 查询、故障转移与连接复用

- 查询总期限 5 秒；单 nameserver 尝试最多 3 秒，并受剩余时间限制。
- UDP 尝试只打开一个传输；首次发送后 1 秒无合法响应时，在同一传输和 ID 上最多重发一次。
- 前两次 peer/ID/question 不匹配只丢当前响应，第三次使当前尝试失败。
- 当前策略最多同时发起 4 个上游尝试；优先返回有效响应并取消其余尝试。超时、I/O、格式错误、SERVFAIL、REFUSED 或 REJECT 不作为成功结果。
- 未启用 fallback 或命中 nameserver-policy 时，NXDOMAIN 和 NODATA 是终态。
- 验证来源、ID 和 question 后，UDP TC 在原期限内改用同一 endpoint 的 TCP。TCP TC 仍是失败响应。
- 全部上游失败时生成 SERVFAIL；非法 UDP 查询只丢当前数据报。

TCP、DoT 和 DoH 使用解析器所属的连接池：

- Key 包含上游地址、认证名称、传输、HTTP 路径、endpoint 与最终 route target；
- 一条连接同时只处理一个查询，不做 pipeline；
- 活动连接不设固定业务数量上限；空闲连接总数最多 4、同 key 最多 2、超时 30 秒；
- 完成帧和响应校验后才能归还连接；
- 复用连接遇到 EOF、I/O、reset 或响应不匹配时，在原尝试期限内最多新建一次连接；
- 非法、截断或超限响应不重试、不归还连接。

Controller 切换代理组后，只在后续需要创建新 DNS transport 时使用新选择。类型化/原始响应 cache、singleflight 状态和已经位于 TCP pool 中的 transport 不清空、不迁移；因此命中 cache 或复用既有 TCP transport 时，不会为切换单独建链。停止 session 才统一释放这些状态。

## 队列与生命周期

| 队列 | 容量 |
| --- | ---: |
| 每普通 UDP 关联入站 | 64 |
| DNS 响应 | 128 |
| 普通 UDP 响应 | 4,096 |

reader 在进入 TCP netstack 前分流 UDP，拥有按源地址建立的关联表，没有共享 UDP 入站接收器或独立 DNS 请求准入数。每普通 UDP 关联有独立请求队列；DNS 查询继续提交受跟踪的任务，不等待上游。队列满时只丢当前请求或响应，不阻塞 reader；TCP accept 仍为 128 项。TUN UDP 响应按有效 MTU 减去 48 字节保守限制；默认 9000 MTU 时为 8,952 字节；显式 1500 为 1,452 字节，Windows UWP 使用 1400 时为 1,352 字节。

唯一受跟踪的 TUN writer 公平读取普通 UDP、DNS 和 TCP/ICMP raw 三个通道，任一通道关闭不丢弃其他通道的待写响应。UDP 构包后直接写平台，不再转发到共享 raw output。DNS 查询观测 permit 保留至该包被平台接受、最终丢弃或取消，写回阻塞和 ENOBUFS 重试不提前释放；WinRT Adapter 成功处理不等于框架最终交付。MTU/地址族错误只丢当前响应。

运行时停止会取消 open、send、receive、retry 和 response-send，释放全部传输并等待已跟踪任务结束。停止返回后不得再向 TUN 回包。

普通非 DNS UDP 关联不设固定总数，采用代次感知所有权和 `tun.udp-timeout` 空闲超时，缺省或零值为 300 秒；清理周期为该期限与 10 秒的较小值。只有成功入队的请求或响应刷新活动时间。

普通 TUN UDP 的 IP 目标在源关联内按目的 IP/端口固定规则 action，即五元组独立
选路，不把整个源的所有目标固定到同一个动作。首包完成嗅探/选路后，活动流不随
DNS 提示或 GeoData 更新改路；新流使用当前数据。每目标按同一个 `tun.udp-timeout` 独立空闲失效，
10 秒间隔借既有关联收发回收；无逐流任务/队列/socket。新认证 QUIC 连接的首包
重新选路，同连接 Initial 重传不重选。具体边界见 [GeoData 生命周期](geodata.md#生命周期)。
匹配配置的 DNS 劫持仍先于普通关联，每个查询独立执行 nameserver-policy，不受五元组固定影响。

## IP-only协议与独立测速接点

公共`ResolutionContext`仅在协议必须取得IP地址的边界解析业务目标或逻辑上游；原始`Destination`保持不变，HTTP Host、TLS SNI和路由仍使用逻辑名称。代理服务器在实际建链时通过节点 resolver 解析，准备阶段不解析备用节点。当前静态ECH不查询DNS；动态ECH及其可选宿主bootstrap入口尚未实现，不属于当前Invoke接口。

Running Session上下文仅弱引用本 session 的 RuntimeDns；业务 IP-only 解析使用 nameserver/policy，代理服务器使用 proxy-server-nameserver/policy，DIRECT 目标使用 direct-nameserver。未绑定、上游不可达或 session 已停止时失败；只有配置关闭 DNS 时才使用系统解析。IP字面量仍执行端口/地址族政策。解析共享同一次建链期限，Stop取消当前及后续查询；在进入可能等待自身的singleflight之前拒绝同名递归依赖，嵌套依赖深度最多32层。不会因为DNS经代理出口就无条件禁止整个图。

独立`measureDelay`使用测量生命周期的受控bootstrap resolver，仅在IP-only边界解析域名；不创建Running Session、RuntimeDns或DNS监听服务，也不改变现有endpoint准备流程。通用 IP-only connector 覆盖最终节点和 `dialer-proxy` 上游的受控解析、期限与取消。该公共接点继续供 packetaddr 等必须 IP 的消费者使用；通用机制测试不替代各协议的实际数据闭环。

## 不支持

- 真实 ICMP 转发、ICMP error、Traceroute、ICMP 选路规则或 ICMP 测速；
- DoQ、DoH HTTP/2/3、显式 system/DHCP nameserver；
- 动态 hosts: lan；
- 用户可配置的缓存容量、超时、重试或并发度；
- 使用 DNS question 执行业务规则，或用 DNS 出口改写后续业务动作。

自动化和物理 TUN 覆盖范围见 [验收矩阵](acceptance.md)。
