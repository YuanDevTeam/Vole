# 客户端出站

字段、类型与示例由 [config.yaml](config.yaml) 维护；这里只定义行为。
VLESS/Vision/Encryption/JLS/ECH 见 [VLESS](vless.md)，XHTTP/sing-mux 见[专用契约](xhttp.md)。

## 公共规则

- 物理 TCP/UDP 只能由共享 Dialer 创建，保留 Android protect、Windows 物理绑定和受控解析。
  传输包装器只消费 IO，不另建 socket 或系统 resolver。
- `dialer-proxy` 可引用节点或策略组；与业务路由共享选择，完整 DAG 在配置期验证。
  一次建链使用组快照和同一绝对期限；已有连接不随切组迁移，无自动 failover 或 DIRECT 回落。
- 节点 `ip-version` 为 `dual`（默认）、`ipv4`、`ipv6`、`ipv4-prefer` 或 `ipv6-prefer`。
  限制或排序该节点的物理服务器地址与本地解析结果，仍受全局 IPv6 开关约束。
  不要求远端代理按相同地址族解析业务域名。
- gRPC/legacy H2 首次读取延迟响应头时先检查原建链期限，即使响应已就绪也不能绕过
  超时；响应头已确认后的业务读取不再受该期限限制。
- HTTP、SOCKS5、TUN、DNS 选路及 node-only `measureDelay` 使用同一连接器。
  底层业务 UDP 默认为 false；收发预算分别逐层扣封装开销，超限不截断交付。
- 所有普通节点都可启用公共 `smux` 包装，使用节点自己的正常 TCP 传输与独立 mux 池，
  业务路由、`dialer-proxy`、provider 代际与测速都使用最终包装器。
  `only-tcp: false` 提供 mux UDP，包括底层 `udp: false` 或仅支持 TCP 的节点；
  true 则原样委托底层 UDP，继承其能力。组 `disable-udp` 仍生效。
  对端必须解码 sing-mux；普通 HTTP/SOCKS5 listener 不因此自动提供解码。
  字段、半关闭及池边界见 [通用 sing-mux](xhttp.md#通用-sing-mux)。
- TLS 使用共享 WebPKI、叶证书 pin/非叶信任锚与 skip 策略。pin 不匹配不能被 skip 绕过，
  TLS 握手签名始终验证。节点策略与恢复缓存不可变、互相隔离，标准 TLS 总票据预算为 4。
  字段及模板详见 [TLS 证书与指纹](tls-client-fingerprint.md)。
- 未知字段、null、错型、非法枚举或不适用的传输选项在网络 IO 前拒绝。
  凭据、UUID、业务目标和完整请求不进入 Debug/错误；资源与 Stop 见[公共策略](runtime-resource-policy.md)。

## HTTP / HTTPS CONNECT

`type: http` 提供 TCP CONNECT；`tls: true` 在代理链路使用共享 TLS 与证书策略。
支持 `username/password`、`headers`、`sni`、`skip-cert-verify`、`name-cert-verify`、
`fingerprint` 及成对的内联 `certificate/private-key`。用户名和密码均非空时发送 Basic 认证。
HTTP CONNECT 本身不提供 UDP，也不接受 `udp` 字段。公共 smux 可承载 UDP。
握手沿用原期限，失败关闭，
成功后保留响应头后的业务字节。启用此协议需要 `outbound-http` feature。

## SOCKS5

仅 SOCKS5 CONNECT / UDP ASSOCIATE；用户名密码成对配置，不支持 SOCKS4。
TCP 保留域名交由上游解析；UDP 由控制连接拥有，校验 relay 来源并保留实际回包目标。
上游为 select 组时，控制连接和后续 UDP 数据报使用同次建链快照。
`tls: true` 使用共享 TLS、`skip-cert-verify`、`name-cert-verify`、`fingerprint` 和
成对的内联 `certificate/private-key`。TLS 名称固定使用 server；不接受 sni、alpn
或 ClientHello 模板。TLS 保护 CONNECT / UDP ASSOCIATE 控制连接，普通 UDP relay
数据不经过 TLS；预算独立于 TUN MTU。TLS 关闭时不能配置证书字段。

## AnyTLS

支持 v2、兼容 v1 的会话、内置填充与 UoT v2。password 为 1–1024 UTF-8 字节；
SNI 默认 server；ALPN 省略/空列表不发送，非空保持顺序，不强制选中某协议。
支持独立的 `name-cert-verify` 和成对内联 PEM `certificate/private-key` 客户端身份；
不开放 TLS 版本、ECH、REALITY、填充和会话参数。命名指纹沿用共享 TLS。

连接先发送 SHA-256 密码摘要、认证填充和首个会话批次。Settings 固定声明 v=2 和
填充方案 MD5，不附产品/版本标识；合法 ServerSettings v>=2 启用 v2，否则兼容 v1。
首个流与认证批次一起发送。复用空闲会话时，v2 写 SYN 和目标后即返回流，再监视
最长 3 秒 SYNACK；v1 不等待。非空 SYNACK、超时、协议/读写器错误销毁整个会话，
已返回流在后续 IO 报错。仅 open 返回前发现空闲会话失效时可新建一次；不重放业务。

未知流、控制 ID/方向错误、越界负载或非法设置是会话级错误；Alert/非空 SYNACK
仅返回固定诊断，不向日志或调用方回显远端内容。
一个物理会话同时仅一个活动流，完整结束后入空闲列表；优先复用序号最大者。
检查/空闲超时均 30 秒，不预热；首次使用才启动清理 worker。ID/序号耗尽关闭会话。

写命令队列 2 项，流接收容量按运行时预算推导且至少 1；活动会话不设全局数量上限。
UoT v2 使用 `sp.v2.udp-over-tcp.arpa:0` 数据报模式，首包含请求，之后每包携带
IP/域名目标，协议负载最多 65,535 字节并取调用方预算交集；响应队列 1 项。
关闭/取消/丢弃 UoT 同时结束读取任务和底层流。

填充为内置方案；新物理会话持有不可变快照，合法 UpdatePaddingScheme 仅影响后续
会话，非法更新只产生有界警告。文本、条目、逻辑填充量和帧负载都有界。
begin_shutdown 同步禁止新流、清空空闲并取消所有会话；shutdown 等待清理 worker、
读写器和 UoT 任务。准备回滚、运行时 Stop 和测速返回前均完成此屏障，不跨运行时共享。

## Trojan

固定 TLS，network 为 tcp/ws/grpc，默认 tcp。ws 可选标准 WebSocket 或 HTTPUpgrade。
密码为非空原始 UTF-8，不 trim，
认证为 SHA-224 小写十六进制。无认证 ACK：本地建链成功不代表密码通过，负例须检查
原站零业务字节。

SNI 默认 server；WS Host 只覆盖 HTTP authority，不作为 SNI 回退。ALPN 默认 TCP 空、
WS http/1.1、gRPC h2，显式列表及实际协商均须满足传输，不能静默降级。
`name-cert-verify` 只覆盖证书验证名；成对的内联 PEM `certificate/private-key`
用于客户端 mTLS 身份，共用标准 TLS 的验证、指纹与恢复策略。

WS path 默认 /，可带 query；头字段不得覆盖握手保留头或大小写重复。early-data
0–2048 字节，启用时默认 Sec-WebSocket-Protocol，可自定义；空头名表示路径后缀，
此时禁止 query。禁用时不能附 ED 头名。首请求头与剩余数据只按序发送一次。
`ws-opts.v2ray-http-upgrade:true` 使用原始 HTTPUpgrade 流，不发送 WebSocket 帧。
普通模式在有效 101 后发送剩余认证前缀；`v2ray-http-upgrade-fast-open:true` 提前
发送该前缀，但仍须在原建链期限内收到有效 101 才返回成功。握手每次从等待恢复时
先复核原期限，即使响应或写入已就绪也不能绕过；建立后的读写不再受该期限限制。
fast-open 需要 upgrade。
Upgrade 的 ED 仅允许默认 Sec-WebSocket-Protocol 头（大小写不敏感），不支持
自定义头或路径 ED。101/头限额/截断失败不重放前缀，响应头后的字节保留给协议。
这些选项同样适用于 VMess 的明文和标准 TLS；不改变各协议认证、UDP 编码或关闭责任。
gRPC 选项与 VMess/VLESS 共用：省略或空 service-name 默认 GunService，普通名映射 /name/Tun，以 / 开头使用完整路径；省略或空 user-agent 默认 grpc-go/1.36.0。
ping-interval 为秒，0 不主动 PING，负值明确拒绝；max-connections/min-streams/max-streams 接受带符号整数，负阈值禁用相应分支。三项字面全零归一 max-connections=1；正 max-connections 优先于 max-streams。
每个节点独立拥有连接池，空闲连接总是复用；复用保留原上游选择、TLS 身份和认证策略，每条逻辑流仍单独发送 Trojan 认证头。

TCP 保留半关闭；gRPC duplex 发送 END_STREAM，不用 RST_STREAM 提前结束读侧。
UDP 使用同一已认证流上的地址/长度/CRLF 帧，无额外 socket/读取泵/池。
payload 最多 8192 字节，待解析最多 8455 字节，并与调用方收发预算分别取交集。
非法/截断帧关闭，合法超接收预算整包丢弃；取消读取保留进度，部分发送取消使关联失效。
运行时先取消并 join 入站所有者，再等待节点 gRPC 驱动。
Mihomo 的 Trojan listener 仅支持 IP 形式的 UDP 目标；域名互通另用原生 Xray。
Mihomo IP 路径可传空包；Xray 不转发空包，且域名回复的 8192 字节总帧预算需扣除
地址和帧头。这些是对端限制，不降低 Vole 的独立帧解析上限。

## VMess AEAD

标准 UUID，alterId 仅省略/0，请求和响应头均 AEAD，无旧认证回退。cipher 为 auto、
aes-128-gcm、chacha20-poly1305、none；zero 归一 none。auto 按实际 AES 硬件能力选择。
none 只关闭 body 加密，仍验证响应身份；不能启用 global-padding/authenticated-length，
两开关默认 false。

network 默认 tcp，另支持 ws/grpc/http/h2；均可明文或标准 TLS。tls 默认 false，
关闭时禁止 TLS 字段，即便空串、空列表或 false。认证名依次为 servername、WS Host
去端口、server；HTTP 伪装 Host/H2 authority 不替代认证名。WS 需 http/1.1，gRPC/H2 需 h2。
TLS 支持独立的 `name-cert-verify` 和成对内联 PEM `certificate/private-key` 客户端身份。

- WS ED/路径/头及 HTTPUpgrade 普通/fast-open 约束同 Trojan。
- gRPC 选项、默认值和节点连接池与 Trojan/VLESS 共用，每条逻辑流独立生成 VMess AEAD 认证；关闭逻辑流不关闭物理连接或兄弟流。
- http 是 TCP 首包伪装：method 默认 GET，path 列表省略/空为 /，按 URL.Path 转义；
  头为字符串列表，每次握手独立选择路径/头值，Host 默认物理 server authority。
  仅首包封装一次，之后恢复原流；禁止 Content-Length/Transfer-Encoding。
- h2 需要非空 authority 列表，path 默认 /，每流选一个 authority，通过 HTTP/2 PUT body
  双向传输；明文 prior knowledge、TLS h2，无 gRPC 帧。

关闭对齐 Mihomo：TCP/WS 可保留上传 EOF 后的读取；gRPC/HTTP/H2 关闭整条逻辑流，
完整响应应在关闭前读取，不统一要求半关闭尾包。

UDP packet-encoding 默认空串（raw），外层仍 TCP：

| 编码 | 目标与预算 |
| --- | --- |
| raw | 首目标写入认证头；同关联换目标失败，等待首包不重置组快照/建链期限 |
| xudp | 每帧携带目标，零 global ID 不发可选扩展；内部 mux 标记不解析 DNS |
| packetaddr | 每包仅 IP+端口，业务域名用运行时受控 DNS；没有 resolver 时不回退系统 DNS |

UDP body 最多 15,000 字节；packetaddr 另扣 IPv4 7 / IPv6 19 字节，未解析域名按 19
预检；超限一字节即写前失败，不拆业务包。对端可能更小，V2Ray 部分返回路径总缓冲
仅 2048 字节，不能当作 Vole 上限。body wire 解析最多 16 KiB，响应头/XUDP 元数据有界。
三种 UDP 编码均不接受零长度业务包；HTTPUpgrade 不改变这个边界。
TCP 写块最多 4 KiB 以适配 Mihomo 拷贝边界；UDP 不按此切块。16 位帧计数耗尽前关闭，
不重复 nonce。半帧发送取消关闭，接收取消保留进度；认证/地址/标签错误使关联失效。
gRPC 池与 legacy H2 driver 由节点拥有并同步退出，无全局会话额度或历史表。

## Hysteria2

始终 QUIC/TLS 1.3，使用官方 rustls；不接受 tls/network/client-fingerprint/REALITY。
port 为 1–65535，仅提供 ports 时可省略；显式非法 port 仍拒绝。password 默认空、
保留原值，须为最长 8192 字节的合法 HTTP 头值。SNI 默认 server；ALPN 省略/空为 h3。
支持共享证书 pin/skip、独立 `name-cert-verify` 和成对内联 PEM mTLS；
验证名不改变 SNI。udp 只控制业务 UDP，不关闭 QUIC 载体。

- up/down 独立非负整数或十进制整数字符串，裸值 Mbit/s；单位 [KMGT]?[bB]ps 使用
  十进制倍率，bit 向下取整为 byte/s。省略/归一零为自动；拒绝小数、符号、溢出。
- udp-mtu 缺省/0 为 1197，其他值 64–65535，限制编码后单分片并取实际 DATAGRAM
  预算交集，不是 TUN MTU。
- obfs 只允许 salamander，须配非空独立 obfs-password。
- ports 是归一去重的非空端口/闭区间集合，优先于合法 port。hop-interval 仅随 ports：
  整数秒 N、字符串 N 或 N-M，默认 30，5 ≤ N ≤ M ≤ u32::MAX；过短严格拒绝。

每节点一个当前认证 QUIC 会话，逻辑流/关联复用且互不取消。HTTP/3 POST hysteria/auth
在业务前要求 233；TCP 类型 0x401，响应可延迟到首次读取，允许先写业务。
认证/上游/请求共用绝对 10 秒预算。旧会话失败后新流可新建会话，已有业务不重放。
写 EOF 关闭当前逻辑 TCP 双向通道，与 Mihomo 一致，不影响兄弟流。

每流接收窗口 256 KiB、连接收发各 1 MiB、DATAGRAM 收发各 256 KiB；最多 8 条单向
控制流，拒绝主动双向流。PMTUD 关闭，最大 QUIC payload 1400 并取上游预算交集；
空闲 30 秒/保活 10 秒。认证头 16 KiB，TCP 响应消息 2048/padding 4096 字节。
业务 UDP 原生 DATAGRAM，payload 最多 4096，最多 255 分片；未知关联不创建状态。
重组按关联/包/地址隔离，最多 64 个待完成包/256 KiB、TTL 5 秒，关联交付队列 32 包。
重复未完成分片忽略；完成后立即释放 16 位 Packet ID，允许后续重用，**不做业务去重**。

down 写入 Hysteria-CC-RX。up=0 或服务端 auto 使用 BBR，否则取 up 与服务端正上限
较小值（服务端 0 无限），使用固定带宽控制与实际 wire-byte pacer。Mihomo down=0
可能返回 RxAuto，优先自动模式。丢包补偿五秒窗口、最小采样量、ACK 比例下限 0.8。
Salamander 采用公开 salt + XOR/BLAKE2b-256，每包加 8 字节，先扣 QUIC 预算但计入
pacer；这是混淆不是认证，错误密钥由 QUIC 拒绝，短包有界丢弃。

端口集合须映射同一服务端 QUIC 状态；初始/后续随机选端口。跳跃创建新受控 socket，
保持认证时组快照，独立期限不延长初始认证、不重认证。发送只走新路径；一秒内公平
接收新旧路径，最多两条，之后回收旧路径。Stop 同步 join 路径/重组/HTTP3/QUIC，
关闭交换最多一秒。

官方 Hysteria 已验证版本的 4096 字节回包缓冲包含头，更大回包可能在分片前丢弃。
原生测试记录实际版本和限制，Vole 完整 4096 字节另对 Mihomo 验证，不修改第三方。

## TUIC v5

固定 QUIC/TLS 1.3，复用官方 Quinn、rustls/ring 与共享受控数据报适配器。
仅 v5；必填标准 UUID 与原样 UTF-8 password，后者可空、最长 65,535 字节。
SNI 缺省 server，ALPN 缺省 h3；显式空列表拒绝，非空有序列表必须实际协商命中。
使用共享 pin/skip/独立验证名；无命名 TCP 指纹、mTLS、ECH、0-RTT 或跨节点恢复。
拥塞使用官方 Quinn cubic（默认）、new_reno 或 bbr，不承诺与其他实现的吞吐相同。
`log-level: debug` 在物理会话建立后记录实际 controller 的固定算法标签；
标签不包含节点、凭据或业务目标，配置验证和复用同一会话不重复记录。

认证使用当前真实 TLS 会话 exporter，UUID 为 label，原样 password 为 context。
Authenticate 与 Connect 没有成功 ACK；本地 open 成功不是密码通过证明，错误身份
必须由最终拒绝和原站零业务验证。Connect 为双向 QUIC 流，不引入 HTTP/3 请求。
流关闭结束该逻辑双向通道，与 Mihomo 对齐，不影响兄弟流。

业务 udp 默认 false，但外层 QUIC 始终需要有效双向至少 1200 字节的数据报路径。
未开放 DATAGRAM、预算不足、protect 失败或只支持 TCP 的上游均失败，不回退 TCP
或 DIRECT。`udp` 业务路由开关不替代上游实际数据报能力和预算检查。
SS UoT、AnyTLS 与支持 UDP ASSOCIATE 的 SOCKS5 可作为上游；组快照绑定物理会话。

`udp-relay-mode` 为 native（默认）或 quic。native 使用 DATAGRAM，按实际容量拆为
最多 255 片；quic 每包使用一条单向流，不受单 DATAGRAM MTU 限制，也不是 UoT。
两者逐包携带 IPv4/IPv6/域名，业务负载取 u16 和调用方双向预算交集，超限不截断。
未知关联不分配状态；每关联最多 64 个未完成包、256 KiB 分片负载、TTL 5 秒和
32 项完成包交付队列。重复相同片忽略、冲突片丢弃；完成后释放 Packet ID，可回绕，
不做业务去重。发送过的关联关闭时发送有界 Dissociate，未发包关闭不创建对端状态。

每节点按需共享物理会话，流 credit 等待沿用调用方原期限。关联 ID 在同一物理会话
不重用；65,536 个 ID 用尽后新业务新建会话，旧流继续，最后一个旧所有者退出即回收。
TCP shutdown 立即完成逻辑关闭，发送所有权保留到 FIN/数据确认或最多 5 秒，防止
退役池提前丢弃已接受的末尾上传；该等待归节点所有，Stop 直接取消并 join。
切组不迁移已有池；故障后只有新业务可创建新池，已发送业务不自动重放。

每流接收窗口 256 KiB，连接收发各 1 MiB，DATAGRAM 收发各 256 KiB；最多 32 条
入站单向控制流，半条控制流最长 5 秒；拒绝服务端主动双向流。QUIC payload 最大
1400 并取路径预算交集，PMTUD 关闭。保活/Heartbeat 每 10 秒，空闲 30 秒；两种
UDP 模式的 Heartbeat 均用 DATAGRAM。Stop 等待认证、收发、重组、心跳及上游释放，
关闭交换最多一秒；这些都是局部结构限制，不是全局业务会话额度。

## Shadowsocks 2022

原样复用官方 shadowsocks-rust，仅三算法：

| cipher | 密钥 |
| --- | --- |
| 2022-blake3-aes-128-gcm | 16 字节 Base64 PSK，或有序 iPSK1:…:iPSKn:uPSK |
| 2022-blake3-aes-256-gcm | 32 字节，同上 |
| 2022-blake3-chacha20-poly1305 | 单一 32 字节 Base64 PSK |

标准 Base64 可省末尾 padding；空段/非法编码/长度错误拒绝，凭据不 trim。
官方库只包装已有 TCP 流，UDP codec 单包有界交接，不调用其 socket 工厂。

### ShadowTLS v3

SS 三算法的 TCP 可配置 `plugin: shadow-tls` 与完整 `plugin-opts`，不是新的代理类型。
仅整数 version 3，始终 strict/TLS 1.3；不提供 v1/v2、弱认证或版本回退。
host 为独立 cover DNS 名/IP，不参与拨号或业务解析；password 保留原始 UTF-8。
ALPN 缺省 `[h2, http/1.1]`、空列表不发送；共享 pin/skip/name-cert-verify 与
节点 client-fingerprint 只影响 cover，不能替代 ShadowTLS 密码。

顺序为受控上游流 → 原生完整 TLS 握手与 relay 认证 → v3 记录流 → 官方 SS2022。
借用原建链期限、取消和组快照，握手失败不发送 SS 目标或业务；pin/skip 不绕过
CertificateVerify 或 Finished。独立 TLS 策略，不恢复 cover 会话。
记录增量认证、未认证内容不交付；每次写最多 16 KiB，背压最多保留一条记录。
flush 排空，关闭最多五秒，不在已切换的 SS 通道中发送 TLS close_notify。

原生 SS UDP 仍走独立受控 UDP 路径，**不经过 ShadowTLS**；TCP-only v3 服务端不会
自动得到 UDP 或 UoT。裸 SS 拒绝 client-fingerprint。默认与 TUN 构建启用
shadow-tls-v3，精简构建可单独移除；无 feature 的插件配置在 IO 前拒绝。
v3 的额外四字节记录特征仍存在，完整认证和互通不等于不可识别。

### UDP over TCP v2

`udp-over-tcp` 默认 false；true 要求 `udp: true`，三算法均可用于裸 SS 或
ShadowTLS v3。开启时 `udp-over-tcp-version` 省略或整数 2 均固定使用 v2；
关闭时不得提供版本，不支持 v1、协商或原生 UDP 降级。无 SS feature 在 IO 前拒绝。

每个关联独占一条既有 SS TCP 路径，支持 TCP-only SOCKS5 上游与 select 组。
目标固定为 `sp.v2.udp-over-tcp.arpa:0`；v2 non-connect 请求只发送一次，之后每包
携带地址和 u16 长度。业务域名先经过受控 `ResolutionContext` 转为 IP，magic 不参与
DNS 或路由。AnyTLS 复用同一有界 codec，但保留自己的域名与会话/FIN 所有权。

SS 首包写入并 flush 成功前阻止后台读取；零长度 UDP 仍有非空 UoT 帧。
延迟首包沿用原建链 deadline，成功建立后的业务不再使用旧期限。未发包关闭直接释放
底层 IO，不触发官方空 SS 握手；半帧写取消使关联失效，不重发。每关联最多一个读取
任务、一个排队响应及一个正在解析/等待入队的响应；接收取消不丢 parser 状态，超接收
预算完整排空该包再读下一包。Stop 取消并等待读任务，释放流；不跨关联池化。

编码负载上限为 65,535 字节，发送/接收各自受调用方预算约束。当前官方 Mihomo
UoT 对端使用 16 KiB 接收缓冲；容器数据验收覆盖该实际边界与多一字节负例，不将
内存中的 u16 上限宣称为端到端 UDP 能力。原样 ssserver 不支持 UoT，仅作拒绝负例。

### 共享 SS 流与数据报行为

- TCP 每次最多交付 16 KiB；读或关闭先于首次写时，完成并刷新官方空首写，
  但受下述空首包限制影响，不承诺可靠 server-first。Pending 继续同次握手，已有首写不重复目标头。
- 背压适配最多暂存一个 16 KiB 原文块并立即报告接受；后续保持同缓冲完成写入，
  避免官方重试长度误计。flush/关闭排空，读取也推进待写但不被写背压阻塞。
- 原生 UDP 取消前预留 packet ID，底层实际发送后才成功；Pending 不重编码，无后台发送队列。
  接收验证来源、认证、关联与完整负载，外层 wire 最大 65,507。
- 每关联随机 client session ID、递增 packet ID，最多两个 server session 的 8128 包
  重放窗口；旧 session 一分钟仍有有效包时不替换，ID 将溢出时换 client ID 并清空窗口。
  close 清空并关闭底层，不新增后台任务。

依赖仅 crates.io 版本，不使用 Git/path/源码补丁。AWS-LC 仅允许沿 shadowsocks →
shadowsocks-crypto 链使用，TLS/REALITY 不消费它，详见[TLS 依赖](tls-dependencies.md)。
启用 SS 时通过 log 的 max_level_off/release_max_level_off 关闭整个依赖图该 facade，
防止上游日志泄密；Vole tracing 不受影响。上游 Debug 不暴露。
重放窗口派生代码的来源/完整许可保留在源码头，发布仍审计实际链接图。

**已知风险：**原样上游空 TCP 首写/空 UDP padding 路径扩展长度而未显式初始化，
存在把残留缓冲传给可解密对端的风险；普通 echo 或自有背压修复不代表此风险已解决。
官方空 TCP 首写还可能随机生成零 padding，被其严格服务端拒绝；Vole 不修改或重试
该上游行为。裸 SS、EIH 和外包 ShadowTLS v3 的 TCP 均受影响；入站转发先轮询读取时，
即使业务计划随后发送请求，也可能触发空首写。TCP 数据验收使用已提交非空首段的
client-first 路径，server-first/空首包列为已知限制，不计成功；其他协议的 server-first
要求不变。内存回归分别验证适配器刷新与确定性的零 padding 拒绝，不将 codec
级回复算作 server-first 互通通过。SS UoT 的非空请求帧与专用读取门控独立验证。
首次固定头不够单次读取时，上游按探测防护拒绝，不改成 read_exact。
Mihomo 仅提供单 PSK；原样 ssserver 验证 AES 单层 EIH 多用户 TCP/UDP 终结及错误身份。
MTU1500 大包夹具显式启用官方双向 IP 分片。自有 1/2 层身份中继不是原生任意多层证明。
所有结果与平台/发布签收分开，见[验收边界](acceptance.md)。


## WireGuard

`type: wireguard` 使用官方 boringtun 的标准 Noise 协议和用户态 IP 栈。
`outbound-wireguard` 可独立启用，不依赖 TUN；不创建系统接口、路由或 NAT。
private-key 必填，ip/ipv6 至少提供一个本地地址；地址接受 IP 或 CIDR，保留主机地址，
每族最多一个。密钥必须是解码后 32 字节的标准 Base64，保存时清零回收，Debug/错误不暴露密钥。

未配置 peers 时，server/port/public-key 必填，pre-shared-key 可选；顶层 allowed-ips
与 Mihomo 一致地忽略，每个本地地址族使用全地址路由。有 peers 时，顶层端点与公钥
不参与选择，每个 peer 必须提供 server/port/public-key 与非空 allowed-ips CIDR 列表。
发送目的地址与解密包的来源地址使用同一不可变最长前缀表；相同前缀最后声明的 peer
优先。同一公钥的重复声明更新端点，保留未覆盖的 PSK，并追加允许前缀。

reserved 缺省为空（全零），否则必须为三个字节。peer 缺省继承顶层值；发送时写入
WireGuard 消息头的保留字节，接收时清零后验证 Noise。MTU 省略/0 为 1408，范围
1280–65503；外层实际双向 UDP 预算必须至少为 MTU+32，不足时关闭上游，不静默缩小。
udp 缺省 false，只控制业务 UDP；外层始终需要双向数据报。persistent-keepalive 为
uint16 秒，0 关闭定期保活。当前不接受 Amnezia、workers、ip-stack 或系统接口模式字段。

每节点、资源代际按需拥有一套 TCP 栈；每个实际使用的 peer 独立拥有 Noise、外层会话
和驱动，未使用的 peer 不启动网络任务。内层 UDP 使用真实临时端口。外层经过共享
Dialer/UpstreamPath，节点端点由 Core 代理 DNS 角色解析；旧会话保留建链组快照与已认证
入站身份。真实握手完成才交付业务流，握手重试与保活使用官方定时器；一个 peer
失败不会关闭其他 peer 或整个共享栈，后续新业务可重建失败会话，不重放旧业务。

remote-dns-resolve 默认 false；只有 true 且 dns 非空时，业务域名使用节点私有 DNS，
查询经过该 WireGuard 节点的内层 TCP/UDP。dns 支持 Core 的 UDP/TCP/DoT/DoH/RCODE
上游；`#route` 不改变这个固定出口。DNS 上游域名仍由 Core 的代理 DNS 角色 bootstrap，
不通过节点私有解析器解析自身端点。私有缓存有界，查询由调用方持有，不保留空闲 TCP
连接或独立后台清理任务。关闭该开关或 dns 为空时使用受控本地 DNS；两种路径都遵循
节点 ip-version、全局 IPv6 开关、本地地址族与原建链期限，失败不回落 DIRECT。

refresh-server-ip-interval 默认 0，关闭更新；非零值以秒计，新业务在间隔到期后触发
所有已建立 peer 的端点重新解析，负值每次检查均到期。不创建额外周期任务。IP 不变时保留物理会话；
变化时保留共享栈、TCP 状态和 UDP 端口，替换外层会话并重新握手。解析或新上游配置失败
保留原端点，下次业务重试。

节点 raw 包队列和各 peer 发送队列各 32 项；每 UDP 关联响应队列 64 项。UDP 负载上限
为 MTU 减本地 IP/UDP 头，再与调用方收发预算分别取交集；双栈保守扣 48 字节，IPv4
扣 28 字节。满队列丢当前包，TCP 依赖重传。解密后校验本地目的地址、来源地址族、
最长前缀所属 peer 和关联端口；这些是局部结构边界，不是业务连接总数限制。

握手、收发、更新与重试均可取消；驱动由节点持有，调用方 future 丢弃不会丢失任务
所有权。Stop 关闭新准入，取消并等待所有 peer 与退役驱动，关闭各上游（分别最多一秒），
随后等待用户态栈退出；私有 DNS 使用弱节点引用，不延长节点生命周期。
