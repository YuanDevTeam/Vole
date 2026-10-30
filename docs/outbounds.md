# 客户端出站

字段、类型与示例由 [config.yaml](config.yaml) 维护；这里只定义行为。
VLESS/Vision/Encryption/JLS/ECH 见 [VLESS](vless.md)，XHTTP/sing-mux 见[专用契约](xhttp.md)。

## 公共规则

- 物理 TCP/UDP 只能由共享 Dialer 创建，保留 Android protect、Windows 物理绑定和受控解析。
  传输包装器只消费 IO，不另建 socket 或系统 resolver。
- 全局与节点 `interface-name/routing-mark` 使用同一物理出口策略：节点非空接口/非零 mark
  分别覆盖全局，空/0 继承；未指定接口时保留平台默认或 Linux TUN 自动识别。
  接口支持 Linux、Apple 和 Windows；名称在建 socket 时核验，失效不回退。
  回环物理目标保留本机路径，不套用公开接口或 mark；UWP 原有字面量回环门禁不变。
  Android 显式接口尚不可用，protect 仍强制执行；非零 mark 仅 Linux 可用。
  UWP 显式接口只能匹配 Provider 当前物理适配器，不能替换源地址/索引。
  Linux 自建 TUN auto-route 的捕获规则只匹配零 mark；物理首跳保留非零公开 mark，
  只有未配置 mark 才注入私有防环值。动态 Provider 候选沿用相同策略，失败仍保留旧代。
- 代理链只由实际物理首跳消费出口策略；当前节点不覆盖其上游节点的策略。
  上游组选择 DIRECT 时使用当前节点策略。XHTTP 两腿、多端点刷新、跳端口和新 QUIC
  socket 沿用其所属路径的策略与选择快照；已建立连接不迁移。DNS、Provider、GeoData
  和健康检查继续使用当前运行图的受控出口，不建立额外裸 socket。
- `dialer-proxy` 省略/空串使用物理 Dialer，也可指定 DIRECT、COMPATIBLE 或引用节点、策略组；与业务路由共享选择，完整 DAG 在配置期验证。
  一次建链使用组快照和同一绝对期限；已有连接不随切组迁移，无自动 failover 或 DIRECT 回落。
- 节点 `tfo` 缺省 false，具名 direct 同样可用。Linux 在只剩一个允许的物理 TCP 地址时
  使用 TCP Fast Open；多地址保留普通串行/并发建链，其他系统使用普通受控 TCP。
  代理链由实际物理首跳消费自己的 `tfo`，组选择 DIRECT 时使用当前节点值；不影响原生 UDP。
  TFO 不把尚未连接的 socket 当成地址竞速赢家；实际地址来自同一出口校验/转换，
  首读、空写、flush 和零上传半关闭也推进握手，并保留同一建链期限与同步 Stop。
  不缓存、重新拨号或重放已接受的业务字节。Provider 同名覆盖保留显式 false。
- 节点 `mptcp` 缺省 false，具名 direct 同样可用，Provider 同名覆盖保留显式 false；
  均只接受非 null 布尔值。Linux 的无约束物理 TCP 首跳可尝试 MPTCP，保留既有
  routing-mark 与防环策略；路径管理器、额外路径与系统路由由宿主管理，Core 不配置子流。
  有 socket protector、显式或自动接口绑定、专用 DNS binding、源 IP 约束时使用普通
  受控 TCP，避免内核额外子流越过初始 socket 的保护范围。Linux 自建 TUN 的
  `auto-detect-interface` 同样属于接口约束；启用 MPTCP 的宿主须自行确保物理路径与防环。
  其他系统或本机/对端没有 MPTCP 能力时允许普通 TCP 回退，但保护、绑定及实际 IO 错误
  不触发绕过策略的重拨。代理链仅实际物理首跳消费自身值，组落到 DIRECT 时使用
  当前节点值；原生 UDP/QUIC 不受影响。多路径协商不代表已建立多条子流。
- 普通协议节点和具名 direct 的 `ip-version` 为 `dual`（默认）、`ipv4`、`ipv6`、`ipv4-prefer` 或 `ipv6-prefer`。
  限制或排序该节点的物理服务器地址与本地解析结果，仍受全局 IPv6 开关约束。
  不要求远端代理按相同地址族解析业务域名。
- `experimental.dialer-ip4p-convert` 缺省 false；开启后，物理 TCP 与 SS2022、SOCKS5、WireGuard
  的原生 UDP 节点端点识别 `2001:0000::/32`，按编码的 IPv4/端口建立实际首跳。
  转换先于实际地址族、源地址和接口绑定；逻辑 server、TLS SNI、认证、代理链目标保持原值，
  收包校验使用实际端点。经代理的逻辑端点不在本地强制转换，实际物理首跳按其自身策略处理。
  不转换 DIRECT 无连接业务 UDP、DNS 答复或其他原生 QUIC 节点入口，不增加缓存或连接池。
  域名的编码地址不能通过转换取得新的回环例外；UWP 物理绑定下同样拒绝编码地址转为回环。
  显式普通回环节点保留原行为；解析查询仍遵循 DNS 的既有 IPv6 开关，不为 IP4P 自动增加 AAAA 查询。
- gRPC/legacy H2 首次读取延迟响应头时先检查原建链期限，即使响应已就绪也不能绕过
  超时；响应头已确认后的业务读取不再受该期限限制。VMess／Trojan gRPC 由外层在原期限内
  等待对端 H2 SETTINGS、提交并 flush 完整认证请求，此后允许 client-first 业务等待响应，
  不再沿用该期限；未完成 H2 握手或请求提交时仍受原期限限制。
- HTTP、SOCKS5、TUN、DNS 选路及 node-only `measureDelay` 使用同一连接器。
  除 Hysteria2/TUIC 的业务 UDP 始终可用外，普通协议节点的业务 UDP 默认为 false；
  组 `disable-udp` 仍可禁用业务 UDP。收发预算分别逐层扣封装开销，超限不截断交付。
  Hysteria2/TUIC 的固有能力声明不替代对端、上游和实际数据报预算的检查。
- UDP 关联复用由共享路由层管理。DIRECT、Mieru、TrustTunnel、WireGuard 内层 UDP、
  MASQUE/IP 内层 UDP 和 VMess packetaddr 均提供逐包目标与实际回包来源，可复用多目标关联。
  开启逐目标连接追踪时，仅同一来源、同一具体出站实例和同一资源代际的未改写 IP 目标共享；
  逐目标路由、统计、关闭、关联退役和旧回复隔离见[资源策略](runtime-resource-policy.md#udp)。
  域名、fake-IP 和需要地址还原的目标保持独立。VMess raw 的首目标约束不变；
  Gecko 等固定对端的底层适配也不因此获得多目标能力，外层业务关联按自身能力处理。
  每层明确声明共享能力，透明包装传递底层声明，不根据外层协议或字段推断其内部载体可共享。
- 所有普通节点都可启用公共 `smux` 包装，使用节点自己的正常 TCP 传输与独立 mux 池，
  业务路由、`dialer-proxy`、provider 代际与测速都使用最终包装器。
  `only-tcp: false` 提供 mux UDP，包括底层 `udp: false` 或仅支持 TCP 的节点；
  true 则原样委托底层 UDP，继承其能力。组 `disable-udp` 仍生效。
  对端必须解码 sing-mux；普通 HTTP/SOCKS5 listener 不因此自动提供解码。
  字段、半关闭及池边界见 [通用 sing-mux](xhttp.md#通用-sing-mux)。
- `smux.brutal-opts` 在新 mux 会话接纳业务前完成一次远端 TCP Brutal 带宽协商，
  不限定客户端平台；对端必须支持并启用它。本地上行仅在 Linux 可证明独占的直连
  物理 TCP 上尝试，保护与绑定保持。代理 hop、共享/多腿传输及 `mptcp: true` 不设置
  本地算法，即使 MPTCP 已回退普通 TCP；完整协议范围见上述 sing-mux 契约。
  Core 不安装或加载模块，本地不可用不否定有效远端协商；参数设置失败恢复旧算法，
  恢复失败终止物理 socket。Brutal 使用单会话池，退役等待旧业务释放，沿原期限与 Stop。
- TLS 使用共享 WebPKI、叶证书 pin/非叶信任锚与 skip 策略。pin 不匹配不能被 skip 绕过，
  TLS 握手签名始终验证。节点策略固定，恢复缓存按节点和身份代隔离，标准 TLS 总票据预算为 4。
  字段及模板详见 [TLS 证书与指纹](tls-client-fingerprint.md)。
  SNI/servername 空串使用协议默认名称；pin/name-cert-verify 空串关闭对应覆盖。
  certificate/private-key 均省略或为空时不启用客户端身份；非空身份仍须成对且有效。
- 未知字段、错型、非法枚举或不适用的传输选项在网络 IO 前拒绝；显式 null 通常也拒绝，
  HTTP 出站已有的可选 TLS 字段保留 null 等同省略的行为。
  凭据、UUID、业务目标和完整请求不进入 Debug/错误；资源与 Stop 见[公共策略](runtime-resource-policy.md)。

`experimental.quic-go-disable-gso` 缺省 false，`quic-go-disable-ecn` 缺省 true。
这两个会话配置只由 Linux 上 TUIC、XHTTP H3、DoQ/DoH H3 的 DIRECT 物理首跳消费，
使用共享 Dialer 已保护、已绑定的同一 socket；不修改宿主进程环境。
GSO 分段批次依实际路径与预算每次最多 10 段、整批最多 65,507 字节，每段保留原 UDP 预算。
未分段的数据报沿用原方向预算，IPv6 可达 65,527 字节；关闭 GSO 后只发独立数据报。
DoQ/DoH H3 的当前 DIRECT 发送预算为 IPv4 65,507、IPv6 65,527 字节，接收预算为 4 KiB，分段能力为 1；
这些 DNS 路径使用同 socket 的原生收发与 ECN 元数据，不据此声称实际 GSO 批量发送。
ECN 开启时传递实际发送标记和接收元数据；关闭时不发送/交付 ECN 标记。
系统无法开启 ECN 接收元数据时，保留同一受保护 socket，沿用原单包、无元数据路径。
GRO 保持关闭，接收仍使用一个有界完整包，不放大 QUIC 接收区或 socket 缓冲。
代理 hop、HY2 的 pacer/混淆/Realm、quiche 后端以及非 Linux 平台当前保持单包且不保留 ECN；
这些路径不声称消费新元数据能力。停止时撤销物理 socket 的共同租约；保留已关闭的 QUIC
连接或写就绪 poller 不会延长物理 fd 的生命周期。GSO 的明确能力错误只关闭后续批量发送，失败批次
作为 UDP 丢失交给 Quinn 的正常 ACK/重传；不会立即重发该批次，不掩盖地址、策略或 ECN 错误。H3 的正常传输、认证、PMTUD、取消及同步 Stop 仍沿原所有者。

VMess + TLS、Trojan、AnyTLS、TrustTunnel、VLESS 和 Hysteria2 支持 `ech-opts.enable/config/query-server-name`，
静态优先和动态节点 DNS 来源、后端算法及失败边界见 [ECH](vless.md#ech)。
TUIC 的固定参考未消费 ECH，因此不接受该字段。

## 流式安全身份

VMess/VLESS 在 `tls: true` 时接受 `shadow-tls-opts` 或 `jls-opts`；Trojan/AnyTLS
沿其固定 TLS 路径接受这两种身份，不增加 `tls` 开关。ShadowTLS 必须显式
`version: 3` 和非空 `password`，SNI 使用节点现有 `servername/sni`；SS2022 插件
仍使用自己的 `plugin-opts.host`。普通 TLS、ShadowTLS、JLS、REALITY 是同一腿的互斥模式，
不叠第二次 TLS，也不在认证失败后降级。ShadowTLS/JLS 只用于对应节点已有的 TCP 承载传输；
XHTTP 仅 H1/H2，主腿和下载腿独立持有身份。两者不能与 Vision 或 ECH 混用。

ShadowTLS cover 接受共享 pin/skip/name-cert-verify 与成对 `certificate/private-key`，
它们只影响 cover 握手；JLS 以用户名/密码认证，不能混用证书策略或 mTLS。
ShadowTLS/JLS 均使用原生完整 TLS 1.3 认证且关闭会话恢复；指纹不能替代密码认证。
受控上游、建立期限、取消和 Stop 仍由原连接器所有者管理。

VMess 的 TCP/HTTP/H2/gRPC、Trojan 的 TCP/gRPC 可用 `reality-opts`，须提供有效的
`client-fingerprint`；WS/HTTPUpgrade 不接受 REALITY。REALITY 不混用证书策略、
mTLS 或 ECH，沿用 [REALITY](reality-wire-protocol.md) 的无回退身份与密钥交换边界。

## 功能出站

具名 `direct`、`dns`、`reject` 只需 `name/type`，没有代理服务器端点，均提供 UDP。
`direct` 另接受 `ip-version/interface-name/routing-mark/tfo/mptcp`，通过共享 Dialer 直连业务目标，
域名使用当前会话的 `direct-nameserver` 角色，并保留其取消和地址族策略。
`dns/reject` 不接受未被其实际消费的节点出口参数。

`type: dns` 将普通规则选中的 TCP/UDP DNS 查询交给当前会话的共享解析器；目标端口不限于 53，
不新增 DNS 监听端口或解析引擎。TCP 与 TUN DNS 接管共用有界的长度帧处理，支持连续查询及半关闭；
UDP 保留原目标作为响应源，每个关联只保留一个活动查询、一个待处理请求和一个待交付响应，
队列已满时丢弃新请求。查询及响应上限为 4096 字节，响应还受入口实际 UDP 预算限制。
丢弃会话取消其任务，停止节点关闭准入并等待所有工作退出。独立测量没有运行会话解析器时，
不能使用具名 DNS 出站。

具名 `reject` 立即结束 TCP，丢弃 UDP 并立即结束其接收路径；没有 `action` 字段。
内置 `REJECT` 保持建链拒绝及 UDP 逐包丢弃。
内置 `REJECT-DROP` 的 TCP 读写等待同一个 60 秒期限，不发往远端、不另留请求副本，
Stop 立即取消等待；UDP 逐包丢弃，沿用关联的正常空闲清理，不套用 TCP 延迟。
`COMPATIBLE` 在规则、代理组、DNS 上游选择和 `dialer-proxy` 中使用直连语义。

## 规则重匹配

`type: rematch` 是规则控制，只有 `name/type/target-rematch-name/target-sub-rule`，
没有服务器、物理连接或额外任务。两个 target 字段至少提供一个非 null 值；null 与省略一致。
省略某字段保留本次决策原值。`target-rematch-name: ''` 清除标记；非空字符串按原样设置，
`REMATCH-NAME,a/b` 将各项 trim 后逐字、区分大小写比较，不接受空项。

`target-sub-rule` 指向已定义子规则列表时，从该列表首条重新求值；存在但为空的列表耗尽后 DIRECT。
空字符串或不存在的名称回到主列表首条；省略时保留当前根列表。
它不是 `SUB-RULE` 调用，不返回原调用位置，也不要求名称在配置时存在。
主列表中的普通 `SUB-RULE` 调用和 `PASS/PASS-RULE` 保留原作用域。

业务 rule 模式及 DNS `#RULES` 共享此流程，组间接选中 rematch 时也生效，先于 UDP 能力检查。
重入保留来源、目标、已解析地址、process 结果和同一次决策的取消、期限、总执行预算与规则开关快照。
同一决策最多进入 32 个 rematch 节点，重复节点名称或超预算即失败关闭；不会建立空连接或回落 DIRECT。
已建立连接保持原路径。global 模式、显式 DNS 出口、`dialer-proxy`、健康探测和 node-only
`measureDelay` 不执行该控制；物理建链选中它时拒绝，测速配置直接拒绝 rematch 节点。

## HTTP / HTTPS CONNECT

`type: http` 提供 TCP CONNECT；`tls: true` 在代理链路使用共享 TLS 与证书策略。
支持 `username/password`、`headers`、`sni`、`skip-cert-verify`、`name-cert-verify`、
`fingerprint` 及成对的 `certificate/private-key`（PEM 或文件路径）。用户名和密码均非空时发送 Basic 认证。
HTTP CONNECT 本身不提供 UDP，也不接受 `udp` 字段。公共 smux 可承载 UDP。
握手沿用原期限，失败关闭，
成功后保留响应头后的业务字节。启用此协议需要 `outbound-http` feature。

## TrustTunnel

`type: trusttunnel` 提供 H2/H3 CONNECT TCP/UDP，使用 `outbound-trusttunnel`。
quic 缺省 false 使用 TLS + HTTP/2；true 使用 QUIC v1/TLS1.3 + HTTP/3，无 0-RTT。
username/password 默认空字符串，始终发送 Basic 认证；不增加非空限制。
SNI 缺省/空串使用 server，ALPN 缺省/空列表随模式使用 h2/h3，自定义列表必须包含该值，
H3 实际握手必须协商 h3；H2 接受协商 h2，或在对端未返回 ALPN 时使用 H2 prior knowledge，
兼容 Mihomo listener。明确协商其他协议仍拒绝，不回退 HTTP/1。两模式使用共享证书策略、mTLS 和 ECH。
client-fingerprint 仅 H2 消费；H3 接受该字符串但不校验模板名、不应用 TCP ClientHello 模板。

三项 max-connections/min-streams/max-streams 全为 0 才应用 8/5/0。
逻辑客户端池先选择活跃流最少的客户端，零活跃流始终复用。
max-connections > 0 时，达到客户端数上限或该客户端流数 < min-streams 即复用；
max-connections <= 0 时，只在 max-streams > 0 且流数 < max-streams 时复用。
各分支未满足复用条件时增加客户端。
混合配置和负阈值不额外拒绝；池参数是分配阈值，不是业务流总量上限。
每个逻辑客户端复用自己的物理连接，空闲30秒后关闭；H3 的 QUIC 空闲期限74秒，
不增加周期 QUIC keepalive。逻辑空闲回收与 QUIC 传输空闲是不同期限。

TCP 流使用原始字节，无 gRPC 帧；建立流后独立消费响应头，允许服务端等待 client-first 业务。
udp 缺省 false，开启后使用 `_udp2` CONNECT 承载多目标数据报。
health-check 缺省 false，开启后使用 `_check` CONNECT；成功 CONNECT 响应重置 7 秒计时，
单次探测期限为7秒。两模式的UDP业务都使用可靠CONNECT流，不使用QUIC DATAGRAM。
关闭只结束当前逻辑流；节点Stop取消并join池、探测、H2/H3及QUIC驱动，释放受控上游。

H3 外层无论业务 udp 是否开启，都要求受控上游提供双向至少1200字节UDP路径；
QUIC payload 最大1400并取实际双向上游预算交集，PMTUD不超过该预算，不回落TCP或DIRECT。
congestion-controller 的 cubic、new_reno 使用官方 quiche 算法；bbr、bbr_meta_v1、
bbr_meta_v2 均使用 quiche 的 Bbr2Gcongestion。省略或未知名称使用 cubic。
H2 不消费 congestion-controller。

## Mieru

`type: mieru` 使用 `outbound-mieru`，底层 transport 必填 TCP 或 UDP，
两者均承载 TCP 和 `udp: true` 的多目标 UDP Associate。用户名、密码各为1–64 UTF-8字节，
不 trim；XChaCha20-Poly1305 分段认证使用物理连接建立时的时间派生密钥。
UDP 载体发送复用既有 boring 的原位 AEAD；接收在启用低熵编码时保留 RustCrypto，
其余接收使用 boring。收发方向各独占认证上下文，后端选择不改变低熵编码或协议字节。
TCP 载体保留 RustCrypto，均使用原 ring PBKDF2 派生规则，不启用 TLS。
业务目标通过协议内 SOCKS 请求传递，不进行 SOCKS 认证方法协商。

port 与非空 port-range 互斥；范围完整匹配十进制 `起点-终点`，两端为1–65535且起点不大于终点。
每次新物理连接随机选择范围内端口，通过共享 Dialer 建链，复用连接保留原上游选择。
MULTIPLEXING_DEFAULT/LOW 对应因子1，MIDDLE/HIGH为2/3；按可复用连接数及因子随机选择
复用或新建，OFF始终新建。DEFAULT/LOW 将TCP CONNECT与UDP Associate分池。
TCP载体的TCP CONNECT仅复用没有活动会话和建流预留的空闲连接，并发TCP会话使用独立载体，
避免慢读会话阻塞兄弟流；UDP Associate保留活动连接的概率复用。
UDP载体的两类业务均保留各自池内的活动连接概率复用，分别持有发送字节预算与命令队列。
DEFAULT/LOW 的 UDP载体 UdpAssociate 独立池，在原单向流预算恰为32 KiB时，每物理载体
共享64 KiB发送信用；同载体各SID共用，待确认分片继续持有许可，首次发送不归还信用。
这是原默认资源策略的例外：低层显式传入相同32 KiB值也使用64 KiB载体发送信用；
其他非默认小/大预算、TCP业务、TCP载体及OFF/MIDDLE/HIGH仍取原值。
每SID接收预算、发送块上限、四写准入、命令FIFO2和物理TX8不随此信用扩大。
LOW的UDP载体在原复用桶内优先选择活动会话与建流预留合计较少的连接，同负载按原随机起点选择；
新建桶概率不变。该合计是建流时的非原子调度估计，不作为容量准入或会话上限。
上述分池不扩大接收预算，但分池和并发TCP仍可能增加物理连接和驱动数量。MIDDLE/HIGH保持两类业务共池，
共享TCP载体仍可能发生慢读队头阻塞。因子不是业务流上限。空闲和累计传输量使连接停止接收新流，
已有流继续工作；退休连接在空闲期限后回收。

HANDSHAKE_DEFAULT/STANDARD 发送请求并等待 SOCKS 回复；HANDSHAKE_NO_WAIT 延迟至
首个业务写入发送请求和数据，再确认回复。枚举必须使用完整前缀。
标准握手完成后直接交付逻辑字节流，不保留懒握手状态。
关闭单个流仅释放其会话；节点 Stop 取消并 join 物理读写、清理及 UDP 读取任务。
写队列、接收字节及 UDP 单包受运行时预算约束；取消不会重放加密帧。
TCP 载体的 UDP Associate 接收信用取原流容量与单包接收预算（含最大 SOCKS 首部和
四字节封装）的较小值；发送块与 TCP CONNECT 窗口不变。跨信用边界的已解密帧
按块复制，包括最后的短尾片，避免排队切片继续持有整帧；物理读取仍先完整认证一帧。
UDP 包解析后由响应持有已验证的接收缓冲，仅移除 SOCKS 首部视图，避免再次复制 payload。
UDP 载体的 UDP Associate 写入在原字节预算与命令 FIFO 准入后返回，不逐包等待首次物理发送。
同会话最多连续准入四笔逻辑写；第五笔非空写在分配新payload与许可前，等待同批最新写入的首次发送回执。
最新回执完成后才开启下一批；空写不作发送屏障，已就绪的首次发送错误仍优先返回。
显式 flush 和 shutdown 仍等待同会话最新写入的首次发送完成；准入不释放发送许可。
TCP业务的写入和flush，以及TCP载体的完成边界保持不变。
UDP 载体的标准握手 TCP CONNECT 流在显式 shutdown 时，先等原首次发送完成，再等本会话
待确认数据的累计 ACK，随后发送原 Close。flush仍只等待首次发送，不等待整个物理载体。
对端关闭或底层终止保留原结果；NoWait、UDP Associate、物理TCP、Drop和活动Stop沿原关闭边界，
不新增ACK等待期限。
UDP 底层使用可靠会话，提供累计 ACK、重传、有序交付、分片和窗口。
密钥固定于物理载体，每包使用显式 nonce；重传保留明文，重新生成 nonce 和时间戳。
收发分别取1400字节 MTU 与真实上游预算的交集。正常接收的应用未读队列与乱序缓存
分别持有接收字节预算，默认各32 KiB。TCP CONNECT在原预算至少32 KiB且可容纳单包时，
给乱序缓存额外32 KiB固定余量，默认乱序容量64 KiB；UDP Associate保持原预算。
额外余量不通告给对端，窗口仍扣除该余量与缺失首片预留，沿原预算计算。
累计 ACK 只在连续数据成功进入应用队列后前移。
乱序缓存优先保留较近的前缀，信用不足时只回收更远且尚未累计确认的数据。
小于单包的应用预算沿用一个物理 Partial 槽。远端关闭保留已接收的连续前缀供读取。
已建立 TCP 的正常 CloseRequest 若在原至少32 KiB预算下携带尚未收齐的末尾序号且无 Partial，
最多保留首次收到关闭后的100 ms来接收该序号前的在途数据；重复关闭不延长期限，
原乱序、字节及交付预算不变，新写入仍被关闭。错误关闭、UDP Associate及小预算沿原关闭路径。
Stop 结束驱动并回收驱动缓存，不等待应用读取；外部仍持有流的已递交数据由读取或释放流回收。
待确认明文仍持有发送预算。物理驱动每轮最多接收8个就绪数据报、发送8个数据报，
ACK 优先于该会话的批量数据，会话轮换服务；接收每8包让出一次执行机会。
Mieru UDP 向共享 Dialer 请求512 KiB物理接收缓冲；当前Linux接受时通常为1 MiB有效容量。
这是内部性能提示，OS可钳位或拒绝；保留原socket、protect、接口绑定及停止所有权，
不改变逻辑包预算，不新增配置字段，协议自有池仍管理自己的物理载体。
创建60秒后的 UDP 载体停止接纳新会话，已有会话继续。
`traffic-pattern` 接受标准 Base64 编码的 Mieru protobuf，保留可选字段的省略与显式零值。
支持 seed、unlockAll、TCP 控制帧分片/间隔、nonce 前缀、padding 及低熵编码；
省略或空值使用协议默认策略。模式仅控制发送，接收不要求对端使用相同模式。
低熵编码作用于数据密文，认证 tag 保持原值；按真实载体预算缩小明文分片，
不会扩大队列或接收预算。重传重新应用 nonce 与 padding，控制帧分片由物理写任务完成。

## MASQUE

`type: masque` 由 `outbound-masque` 提供。缺省、空串及非 `h2`/`h3-l4proxy`
的 network 使用 H3 `cf-connect-ip`；每个节点按需建立一条共享 IP 隧道，TCP/UDP
经同一个内部 `vole-netstack`，不创建系统 TUN。`network: h2` 使用严格 H2 TLS
与普通 CONNECT，设置 `cf-connect-proto: cf-connect-ip` 和 `pq-enabled: false`；
精确 HTTP 200 后交付隧道，DATA 内 DATAGRAM capsule 直接携带原始 IP，不添加 context ID。
H2 每 30 秒发送空闲 PING，ACK 期限为 15 秒；不因隧道暂时空闲而回收。
H3 等待实际 peer SETTINGS 中的
现代 DATAGRAM 支持，同时发送现代与旧 DATAGRAM setting；原始 IP 使用请求流关联及
context ID 0。控制 capsule 有界解析，发送 IPv4/IPv6 完整 route advertisement。
H3 IP 模式在所有受控抽象 socket 平台启用有界 QUIC PMTUD；具有 IPv6 本地地址时，
就绪前确认真实 DATAGRAM 预算可承载 1280 字节 IP 包，未满足时按建链期限失败。
`ip`/`ipv6` 最多提供两条本地 prefix，标签不强制地址族；未带前缀分别补 /32 与 /128。
mapped IPv4 归一，重复地址取较长前缀，同族两地址按目标选择源地址。
MTU 缺省/零值为 1280；只有 IPv4 时允许 68..65535，存在实际 IPv6 时至少 1280。
收包预算与发包 MTU 分离；TCP 的有效 MSS 和经过活动 tuple/已发送序号验证的 ICMP
PMTU 反馈按连接生效，通过包层软件分段恢复，重传由官方 smoltcp 的定时器触发。
初始发送 MTU 取配置与真实隧道预算的交集，避免已知预算下的持续二次分段。
内部队列、capsule 和 packet 均有界，停止等待其工作任务回收。
H3 IP 的物理 UDP 请求沿原受控 dialer 携带 512 KiB 接收缓冲提示；系统可限制或忽略该提示，不构成进程 RSS 或真机内存保证。
当底层实际报告发送预算缩小时，只反馈当前过大包，不关闭其它业务流。
稳定路径的 MTU 下降目前不会自动触发 QUIC PMTU 重新探测。

`network: h3-l4proxy` 使用 Cloudflare L4 HTTP/3 CONNECT，每个 TCP 目标独占请求流，共享受控 QUIC 连接；
等待 2xx 响应后才交付业务流，拒绝响应不取消其它流，节点 Stop 等待所有驱动退出。
基础 UDP 始终关闭，`udp: true` 也不启用它。

`remote-dns-resolve: true` 且 `dns` 非空时启用节点私有 DNS；否则忽略 dns 内容，
业务域名沿原受控本地解析。IP 模式的 DNS 查询通过同一个内部栈，L4 仅支持经节点的
TCP DNS 传输，不将 UDP 查询改为 TCP 或改走 DIRECT。节点 DNS 沿用 Core DNS 上游格式，
不继承全局 prefer-h3；解析上游域名仍使用节点外部的 bootstrap 上下文，避免自递归。
system/DHCP 来源沿共享物理来源策略处理，网络快照更新清理节点缓存；不可用时失败。
私有 resolver 不保留空闲连接，由节点 Stop 关闭并等待驱动。

IP 模式 `handshake-timeout` 为整数秒：0 使用创建调用的建立期限，创建者取消会终止
尚未就绪的创建；正值使用节点拥有的独立期限，创建者或其它等待者取消不终止共享创建。
已交付业务不继承建立期限；节点 Stop 取消创建和业务并等待全部任务。

private-key 是标准 Base64 SEC1 ECDSA 私钥，public-key 是标准 Base64 ECDSA SPKI。
客户端发送对应自签证书，服务端每张证书都必须使用固定公钥；不检查证书名称、
信任根或有效期。skip-cert-verify 只关闭公钥固定，握手签名仍验证；
name-cert-verify 是 Mihomo 保留的占位字段，不消费。每个物理连接使用独立 TLS 配置，
关闭恢复与 0-RTT；H2 使用 rustls/ring，H3 使用 quiche 与共享 Boring，
两者保留相同的公钥固定与握手签名校验。

SNI 缺省或空串在 IP 模式使用 consumer-masque.cloudflareclient.com，
L4 使用 consumer-masque-proxy.cloudflareclient.com。IP URI 缺省为
https://cloudflareaccess.com，不支持含变量的 IP flow URI template。
L4 不解析 ip/ipv6/uri，不消费 mtu 或正 handshake-timeout；负超时拒绝。
QUIC 使用 20 字节 CID、初始 payload 1242 与受控预算交集、30 秒 keepalive；
拥塞字段采用上述 TrustTunnel H3 的算法映射。
`ip-stack` 支持省略/auto 与省略/cubic，不把其它栈或算法映射为现有栈。

## SOCKS5

仅 SOCKS5 CONNECT / UDP ASSOCIATE；用户名密码成对配置，不支持 SOCKS4。
TCP 保留域名交由上游解析；UDP 由控制连接拥有，校验 relay 来源并保留实际回包目标。
Controller 跟踪的同源、同具体节点和同代际的未改写 IP 目标共享 UDP ASSOCIATE，
逐目标统计与关闭保持独立；目标退出使关联退役，新目标使用新关联，旧回复不能进入重建目标。
上游为 select 组时，控制连接和后续 UDP 数据报使用同次建链快照。
`tls: true` 使用共享 TLS、`skip-cert-verify`、`name-cert-verify`、`fingerprint` 和
成对的 `certificate/private-key`（PEM 或文件路径）。TLS 名称固定使用 server；不接受 sni、alpn
或 ClientHello 模板。TLS 保护 CONNECT / UDP ASSOCIATE 控制连接，普通 UDP relay
数据不经过 TLS；预算独立于 TUN MTU。TLS 关闭时不能配置证书字段。

## AnyTLS

支持 v2、兼容 v1 的会话、内置填充与 UoT v2。password 为 1–1024 UTF-8 字节；
SNI 默认 server；ALPN 省略/空列表不发送，非空保持顺序，不强制选中某协议。
支持独立的 `name-cert-verify` 和成对内联 PEM 或文件路径 `certificate/private-key` 客户端身份；
支持共享静态/动态 `ech-opts`，强制真实 TLS1.3 接受后才能发送认证与业务；
不开放 TLS 版本、REALITY和填充参数。命名指纹沿用共享 TLS。

连接先发送 SHA-256 密码摘要、认证填充和首个会话批次。Settings 固定声明 v=2 和
填充方案 MD5，`client-metadata` 原样写入 client 值，缺省为空，不自行填产品/版本标识；
metadata 不含换行且须适合 u16 Settings 帧。合法 ServerSettings v>=2 启用 v2，否则兼容 v1。
首个流与认证批次一起发送。复用空闲会话时，v2 写 SYN 和目标后即返回流，再监视
最长 3 秒 SYNACK；v1 不等待。非空 SYNACK、超时、协议/读写器错误销毁整个会话，
已返回流在后续 IO 报错。仅 open 返回前发现空闲会话失效时可新建一次；不重放业务。

未知流、控制 ID/方向错误、越界负载或非法设置是会话级错误；Alert/非空 SYNACK
仅返回固定诊断，不向日志或调用方回显远端内容。
一个物理会话同时仅一个活动流，完整结束后入空闲列表；优先复用序号最大者。
`idle-session-check-interval` / `idle-session-timeout` 使用整数秒，缺省或 <=5 回到30秒；
`min-idle-session` 缺省/负值为0，只保留现有空闲会话，不预热。回收从最新会话开始，
未过期项计入保留数，必要时刷新已过期项的空闲时间。首次使用才启动清理 worker。
`disable-reuse: true` 不启动回收 worker、不领取/归还空闲会话，逻辑流结束即关闭该会话。
ID/序号耗尽关闭会话。

写命令队列 2 项，流接收容量按运行时预算推导且至少 1；活动会话不设全局数量上限。
UoT v2 使用 `sp.v2.udp-over-tcp.arpa:0` 数据报模式，首包含请求，之后每包携带
IP/域名目标，协议负载最多 65,535 字节并取调用方预算交集；响应队列 1 项。
同一源关联、具体节点和资源代际内，未改写 IP 目标共享 UoT 传输；逐目标统计、
关闭和固定出口保持独立，具体退役边界见[资源策略](runtime-resource-policy.md#udp)。
单次发送 future 被取消时，最多保留一个未完成帧及写入偏移；后续发送或接收先完成该帧，
不重复首部或破坏后续边界。首帧仍沿用原建链期限；实际 IO 失败或超时使关联失效。
显式关闭、父作用域取消或丢弃 UoT 同时结束读取任务和底层流，不等待未提交帧的写入容量。

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
`name-cert-verify` 只覆盖证书验证名；成对的内联 PEM 或文件路径 `certificate/private-key`
用于客户端 mTLS 身份，共用标准 TLS 的验证、指纹与恢复策略。

WS path 默认 /，可带 query；头字段不得覆盖握手保留头或大小写重复。early-data
按配置最大值与当前请求16KiB头预算的较小值发送，不预留配置上限。path 的 `?ed=N`
覆盖显式ED配置并移除ed参数；启用时默认 Sec-WebSocket-Protocol，可自定义；空头名表示路径后缀，
此时禁止 query。禁用时不能附 ED 头名。首请求头与剩余数据只按序发送一次。
`ws-opts.v2ray-http-upgrade:true` 使用原始 HTTPUpgrade 流，不发送 WebSocket 帧。
普通模式在有效 101 后发送剩余认证前缀；`v2ray-http-upgrade-fast-open:true` 提前
发送该前缀，但仍须在原建链期限内收到有效 101 才返回成功。握手每次从等待恢复时
先复核原期限，即使响应或写入已就绪也不能绕过；建立后的读写不再受该期限限制。
fast-open 需要 upgrade。
Upgrade 的 ED 仅允许默认 Sec-WebSocket-Protocol 头（大小写不敏感），不支持
自定义头或路径 ED。101/头限额/截断失败不重放前缀，响应头后的字节保留给协议。
这些选项同样适用于 VMess 的明文和标准 TLS；不改变各协议认证、UDP 编码或关闭责任。
gRPC 的 HTTP authority 使用非空 SNI，否则使用 server，不包含端口；不改变物理拨号地址。
gRPC 选项与 VMess/VLESS 共用：省略或空 service-name 默认 GunService，普通名映射 /name/Tun，以 / 开头使用完整路径；省略或空 user-agent 默认 grpc-go/1.36.0。
ping-interval 为秒，0 不主动 PING，负值明确拒绝；max-connections/min-streams/max-streams 接受带符号整数，负阈值禁用相应分支。三项池阈值省略或字面全零时归一为4/0/0，Mihomo为1/0/0；显式 max-connections=1 或2保留各自策略。正 max-connections 优先于 max-streams。
每个节点独立拥有连接池，空闲连接总是复用；复用保留原上游选择、TLS 身份和认证策略，每条逻辑流仍单独发送 Trojan 认证头。

Trojan 私有 gRPC 池在原绝对期限内等待 H2 SETTINGS、提交并 flush 完整认证请求，
随后允许 client-first 上传等待迟到的 HTTP 响应，不把建链期限继续套用到业务。
迟到的 HTTP/gRPC 状态仍完整校验；未完成认证提交、TLS 或 H2 握手继续受原期限约束。

TCP 保留半关闭；gRPC duplex 发送 END_STREAM，不用 RST_STREAM 提前结束读侧。
UDP 使用同一已认证流上的地址/长度/CRLF 帧，无额外 socket/读取泵/池。
同一来源、具体节点和资源代际内，未改写 IP 目标共享该流，回复按每帧地址分流；
逐目标统计、关闭及旧回复隔离沿用[资源策略](runtime-resource-policy.md#udp)。
不同来源、域名及需要地址还原的目标保持独立；关闭一个目标不关闭仍有成员的流，
但部分发送取消仍使整条关联失效，不重放已提交的帧。
payload 最多 8192 字节，待解析最多 8455 字节，并与调用方收发预算分别取交集。
非法/截断帧关闭，合法超接收预算整包丢弃；取消读取保留进度，部分发送取消使关联失效。
运行时先取消并 join 入站所有者，再等待节点 gRPC 驱动。
Mihomo 的 Trojan listener 仅支持 IP 形式的 UDP 目标；域名互通另用原生 Xray。
Mihomo IP 路径可传空包；Xray 不转发空包，且域名回复的 8192 字节总帧预算需扣除
地址和帧头。这些是对端限制，不降低 Vole 的独立帧解析上限。

## VMess AEAD

UUID 接受标准、紧凑、花括号、URN 表示，其他字符串按 UUIDv5(nil, 原始 UTF-8) 映射，不 trim。
alterId 仅省略/0，请求和响应头均 AEAD，无旧认证回退。cipher 不区分 ASCII 大小写，为 auto、
aes-128-gcm、chacha20-poly1305、none；zero 归一 none。auto 按实际 AES 硬件能力选择。
none 只关闭 body 加密，仍验证响应身份；不能启用 global-padding/authenticated-length，
两开关默认 false。

物理出口、安全身份、传输握手及完整认证请求的写入和 flush 共用原建立绝对期限；
请求提交后，服务端可等待业务上传再发送响应头，不继承旧建立期限。响应 AEAD、身份和长度仍须
验证通过才交付下行数据；失败关闭、传输自身的握手期限、取消和 Stop 边界不变。

network 省略/空串为 tcp，另支持 ws/grpc/http/h2；均可明文或 TLS，安全身份范围见上文。tls 默认 false，
关闭时禁止 TLS 字段，即便空串、空列表或 false。认证名依次为 servername、WS Host
去端口、server；HTTP 伪装 Host/H2 authority 不替代认证名。WS 需 http/1.1，gRPC/H2 需 h2。
TLS 支持独立的 `name-cert-verify` 和成对内联 PEM 或文件路径 `certificate/private-key` 客户端身份。

- WS ED/路径/头及 HTTPUpgrade 普通/fast-open 约束同 Trojan。
- gRPC 选项、默认值和节点连接池与 Trojan/VLESS 共用，每条逻辑流独立生成 VMess AEAD 认证；关闭逻辑流不关闭物理连接或兄弟流。
  authority 使用非空 servername，否则使用 server:port；name-cert-verify 不参与 authority。
- http 是 TCP 首包伪装：method 默认 GET，path 列表省略/空为 /，按 URL.Path 转义；
  头为字符串列表，每次握手独立选择路径/头值，Host 默认物理 server authority。
  仅首包封装一次，之后恢复原流；禁止 Content-Length/Transfer-Encoding。
  完整 HTTP 首请求与认证前导写入、flush 沿用原建链期限；成功提交后，首个 HTTP
  响应可等待业务下行，不再继承旧建链期限。头解析上限、取消和整流关闭保持。
- h2 的 authority 列表省略/空时使用 www.example.com，path 省略/空时为 /，每流选一个 authority，通过 HTTP/2 PUT body
  双向传输；明文 prior knowledge、TLS h2，无 gRPC 帧。

关闭对齐 Mihomo：TCP/WS 可保留上传 EOF 后的读取；gRPC/HTTP/H2 关闭整条逻辑流，
完整响应应在关闭前读取，不统一要求半关闭尾包。

UDP packet-encoding 默认空串（raw），外层为所选可靠流：

| 编码 | 目标与预算 |
| --- | --- |
| raw | 首目标写入认证头；同关联换目标失败，等待首包不重置组快照/建链期限 |
| xudp | 每帧携带目标，零 global ID 不发可选扩展；内部 mux 标记不解析 DNS |
| packetaddr | 每包仅 IP+端口，业务域名用运行时受控 DNS；没有 resolver 时不回退系统 DNS |

UDP body 最多 15,000 字节；packetaddr 另扣 IPv4 7 / IPv6 19 字节，未解析域名按 19
预检；超限一字节即写前失败，不拆业务包。对端可能更小，V2Ray 部分返回路径总缓冲
仅 2048 字节，不能当作 Vole 上限。body wire 解析最多 16 KiB，响应头/XUDP 元数据有界。
三种 UDP 编码均不接受零长度业务包；HTTPUpgrade 不改变这个边界。
TCP 写块最多 4 KiB 以适配 Mihomo 拷贝边界；UDP 不按此切块。
AES/ChaCha body 的收发记录计数各自按 16 位回绕，与 Mihomo/sing-vmess 和 V2Ray-core
一致；跨越 65,536 条记录时不额外断开、重连、重放或更换 cipher。长度认证沿用同一记录索引。
该协议行为会在同一密钥下重复 nonce，不提供回绕后的 nonce 唯一性保证；外层 TLS 不更新
内层 body 密钥。认证标签、长度、地址及其它解析错误仍失败关闭。
raw/packetaddr 半帧发送取消关闭；XUDP 保留一个待写帧并在下次收发时完成，
遵循[VLESS 的 XUDP 取消边界](vless.md#udp)。接收取消保留进度；认证/地址/标签错误使关联失效。
gRPC 池与 legacy H2 driver 由节点拥有并同步退出，无全局会话额度或历史表。

## Hysteria2

始终 QUIC/TLS 1.3，使用官方 rustls；不接受 tls/network/client-fingerprint/REALITY。
port 为 1–65535，仅提供 ports 时可省略；显式非法 port 仍拒绝。password 默认空、
保留原值，须为最长 8192 字节的合法 HTTP 头值。SNI 默认 server；ALPN 省略/空为 h3。
支持共享证书 pin/skip、独立 `name-cert-verify` 和成对内联 PEM 或文件路径 mTLS；
验证名不改变 SNI。业务 UDP 始终可用；`udp` 可省略或填 true/false，均不禁用它，
组 `disable-udp` 仍生效。外层 QUIC 始终需要数据报路径。

- up/down 独立非负整数或十进制整数字符串，裸值 Mbit/s；单位 [KMGT]?[bB]ps 使用
  十进制倍率，bit 向下取整为 byte/s。省略/归一零为自动；拒绝小数、符号、溢出。
- udp-mtu 缺省/0 为 1400，其他值 64–65535，限制编码后单分片并取实际 DATAGRAM
  预算交集，不是 TUN MTU。
- obfs 支持 salamander 或 gecko，须配非空独立 obfs-password。Gecko 对 QUIC 长头随机分片并填充，
  短头只用 Salamander；`obfs-min-packet-size/obfs-max-packet-size` 默认512/1200，
  正值且 min≤max≤2048，只用于 Gecko。max 是填充目标，不是 QUIC MTU，实际片仍受物理预算限制。
- ports 为端口/闭区间集合，接受逗号或斜线分隔，逆序范围归一并去重；有效非空集合优先于 port，
  此时 port 可省略或为0。空集合或 `*` 使用非零 port，不启用跳跃。
  hop-interval 随 ports 使用整数秒 N、字符串 N 或 N-M，范围先排序，0 使用30秒，
  正数小于5归一为5，最终上界至少为归一后的下界；仍须可表示为 u32。

`realm-opts.enable: true` 使用 Realm 控制面/STUN/UDP 打洞，和 ports 跳端口互斥。
必填 server-url、realm-id 与非空 stun-servers；token 默认空，服务端按实际认证处理。
server-url 为无 userinfo/query/fragment 的 HTTP(S) base URL，不跟随重定向。
STUN 可用 IP/域名及可选端口，默认3478；每个域名使用一个受控解析地址，同时探测两族应列出两族端点。
HTTPS 控制面独立接受 sni/alpn、skip-cert-verify/name-cert-verify/fingerprint 与成对
certificate/private-key（内联 PEM 或相对配置目录的文件）；它们不改变业务 QUIC 身份。
实际 UDP 对端由 Realm 发现，但原节点 server/SNI 仍用于 QUIC 认证，不解析未使用的原 server。

最多2个候选UDP association、16个STUN、32个控制面peer、128个打洞候选；首部/body各16KiB，
所有网络操作使用同一节点受控出口、建立期限和取消。胜出的原 association 移交 Quinn，
失败/取消/Stop 关闭未交付候选并等待驱动。无额外 resolver、物理 socket 工厂或 DIRECT 回落。
Gecko 重组最多8个消息/每消息8片/1400字节，TTL8秒，不保留 padding backing。

每节点按需使用最多两个当前认证 QUIC 会话，自动和显式带宽模式共用此有界池，
按来源地址稳定选择，分担对端逐连接 UDP 处理。上行共用节点 wire pacer，
下行声明按连接分配且总和保持配置值；down 为一字节/秒时保留单连接。
单条流的下载上限受所在连接的分配值限制，空闲连接不转移其声明额度。
各连接内的逻辑流/关联复用且互不取消。HTTP/3 POST hysteria/auth
在业务前要求 233；TCP 类型 0x401，响应可延迟到首次读取，允许先写业务。
认证/上游/请求提交共用绝对 10 秒预算。请求已提交后的业务及延迟响应不再使用建链期限；
响应失败仍使当前逻辑流失效。旧会话失败后新流可新建会话，已有业务不重放。
写 EOF 关闭当前逻辑 TCP 双向通道，与 Mihomo 一致，不影响兄弟流。

四个 initial/max 接收窗口按字节配置；0 独立使用默认：stream 64 KiB，connection 4 MiB。
采用固定 Middle 策略：每流信用为 max(initial, min(maximum, 4 MiB))，连接信用为 initial；
不执行消费量或 RTT 驱动的自适应增长。默认窗口优先多流公平性和较小的未读数据。
较高 RTT 的单流吞吐受固定流窗口约束，可通过现有初始/最大窗口字段显式增大，同时增加接收驻留。
initial 大于 max 时保留初始值，不缩小或额外拒绝；max 限制到 QUIC VarInt，无法编码的
initial 拒绝。窗口是信用额度，不预分配整个缓冲。handshake-timeout 为整数秒，正值使共享
建链由节点持有并使用独立期限；各调用仍受自身原建立期限约束，短等待退出不取消有效 pending。
每槽位最多一个 pending，失败驱动清理后才能替换；<=0 保留创建调用的期限与取消语义。
成功后的业务/端口跳跃不重新应用此期限，Stop 取消并等待全部驱动。

节点可靠发送窗口总额 1 MiB、DATAGRAM 接收预算 2 MiB、发送预算 4 MiB，
按固定会话槽位数均分；未使用槽位的额度不转移。可靠接收信用仍按连接配置，
第二会话另有独立协议状态、队列和物理 socket，因此这些预算不代表节点总内存不变。
每连接最多 8 条单向
控制流，拒绝主动双向流。PMTUD 关闭，最大 QUIC payload 1400 并取上游预算交集；
空闲 30 秒/保活 10 秒。认证头 16 KiB，TCP 响应消息 2048/padding 4096 字节。
共享 Dialer 为每个物理 UDP socket 请求 2 MiB 接收缓冲以承接突发，实际大小由系统决定；
原 socket 的保护、绑定和所有权继续保留，逻辑包预算及 QUIC 接收信用独立。
业务 UDP 原生 DATAGRAM，payload 最多 4096，最多 255 分片；未知关联不创建状态。
重组按关联/包/地址隔离，最多 64 个待完成包/256 KiB、TTL 5 秒，关联交付队列 32 包。
每条认证连接另有 32 项原始消息发送队列；同一连接任务顺序编码分片，不增加后台任务。
满队列等待可取消的准入，准入成功才使用 Packet ID；关闭关联后未发送项丢弃，Stop 取消并释放队列。
重复未完成分片忽略；完成后立即释放 16 位 Packet ID，允许后续重用，**不做业务去重**。
缓存满时淘汰最早开始的未完成包以接纳新包，避免缺片占满缓存后使后续包停滞至 TTL；
总项数、总负载字节及单包预算保持不变。
同一来源、具体节点和资源代际内，未改写的 IP 目标共用一个 UDP session ID 和交付队列；
逐目标统计、取消与出口固定仍由路由层管理，退役及旧回复隔离沿用[资源策略](runtime-resource-policy.md#udp)。

down 写入 Hysteria-CC-RX。up=0 或服务端 auto 使用官方 Quinn CUBIC，否则取 up 与服务端正上限
较小值（服务端 0 无限），使用固定带宽控制与实际 wire-byte pacer。Mihomo down=0
可能返回 RxAuto，优先自动模式。丢包补偿五秒窗口、最小采样量、ACK 比例下限 0.8。
自动模式采用 CUBIC 的本地策略，符合 [Hysteria 拥塞控制协议](https://hysteria.network/docs/developers/Protocol/#congestion-control)，
不承诺与 Mihomo/官方客户端的 BBR 在高 RTT 或有损网络下性能相同。
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
仅 v5，native／quic 服务端互通目标为官方 Itsusinn/tuic，UoT v2 与服务端 mTLS 使用 Mihomo；
必填标准 UUID。password 为原样 UTF-8，省略/空串为空密码，最长 65,535 字节。
SNI 缺省 server，ALPN 缺省 h3；显式空列表拒绝，非空有序列表必须实际协商命中。
`disable-sni: true` 只关闭 ClientHello 的 SNI，仍验证原认证名/显式 name-cert-verify 和 pin，
不隐式关闭证书验证。
使用共享 pin/skip/独立验证名，支持配对内联 PEM 或文件路径的 certificate/private-key 客户端身份；无命名 TCP 指纹、ECH、0-RTT 或跨节点恢复。
拥塞使用官方 Quinn cubic（默认）、new_reno 或 bbr，不承诺与其他实现的吞吐相同。
`log-level: debug` 在物理会话建立后记录实际 controller 的固定算法标签；
标签不包含节点、凭据或业务目标，配置验证和复用同一会话不重复记录。

认证使用当前真实 TLS 会话 exporter，UUID 为 label，原样 password 为 context。
Authenticate 与 Connect 没有成功 ACK；本地 open 成功不是密码通过证明，错误身份
必须由最终拒绝和原站零业务验证。Connect 为双向 QUIC 流，不引入 HTTP/3 请求。
流关闭结束该逻辑双向通道，与 Mihomo 对齐，不影响兄弟流。

业务 UDP 始终可用；`udp` 可省略或填 true/false，均不禁用它，组 `disable-udp` 仍生效。
外层 QUIC 始终需要有效双向至少 1200 字节的数据报路径。
未开放 DATAGRAM、预算不足、protect 失败或只支持 TCP 的上游均失败，不回退 TCP
或 DIRECT。业务 UDP 能力声明不替代上游实际数据报能力和预算检查。
SS UoT、AnyTLS 与支持 UDP ASSOCIATE 的 SOCKS5 可作为上游；组快照绑定物理会话。

`udp-relay-mode` 为 native（默认）或 quic。native 使用 DATAGRAM，按实际容量拆为
最多 255 片；quic 每包使用一条单向流，不受单 DATAGRAM MTU 限制，也不是 UoT。
quic 收齐声明长度的报文后立即交付并释放接收流，TCP 通道的关闭与 FIN 保留规则不变。
两者逐包携带 IPv4/IPv6/域名，业务负载取 u16 和调用方双向预算交集，超限不截断。
未知关联不分配状态；每关联最多 64 个未完成包、256 KiB 分片负载、TTL 5 秒和
32 项完成包交付队列。未完成包槽满时，新分片包逐出最老的未完成包；字节预算和 TTL 保持。
重复相同片忽略、冲突片丢弃；完成后释放 Packet ID，可回绕，
不做业务去重。协议不携带跨片报文代次或完整内容校验；同一关联、相同 Packet ID 的
跨包互补分片无法一般性区分，QUIC 对单片的认证不代替完整业务内容校验。
发送过的关联关闭时发送有界 Dissociate，未发包关闭不创建对端状态。

启用逐目标连接追踪时，native 与 quic 模式允许同一 TUN UDP 来源、同一具体出站实例的
未改写 IP 目标共用一个 TUIC 关联，每包仍携带目标地址；逐目标路由、统计与取消保留。
目标改写、域名目标及不同出站实例在该追踪路径保留独立关联。
未启用追踪时沿用既有路由缓存的关联复用规则。

每节点按需复用物理会话。native 按完整来源地址（含端口）稳定分配至两个按需池，
同源 TCP/UDP 保持池亲和；UoT v2 保持原共享池。quic relay 的 TCP 与原生 UDP
各自按需使用独立池，避免逐包单向流的回包积压占用 TCP 所在连接。每池仍沿原所有者
阈值准入、退役与释放，不增加单个连接的窗口或远端单向流信用。两个当前池不是全节点
总连接上限；退役会话仍由既有所有者生命周期释放。流 credit 等待沿用调用方原期限。
native 模式（不含 UoT v2）向共享 Dialer 请求512 KiB物理 UDP 接收缓冲；
这是可钳位或拒绝的性能提示，沿用同一个受保护、已绑定的 socket，不改变 QUIC 信用、
应用队列或逻辑包预算。quic relay 与 UoT v2 不请求该提示；Linux 内核缓冲与进程 RSS 分开核算。
关联 ID 在同一物理会话
不重用；65,536 个 ID 用尽后新业务新建会话，旧流继续，最后一个旧所有者退出即回收。
TCP shutdown 立即完成逻辑关闭，发送所有权保留到 FIN/数据确认或最多 5 秒，防止
退役池提前丢弃已接受的末尾上传；该等待归节点所有，Stop 直接取消并 join。
切组不迁移已有池；故障后只有新业务可创建新池，已发送业务不自动重放。

`ip` 覆盖物理拨号地址，逻辑 server/SNI 保留。heartbeat-interval 单位毫秒，<=0 回落
10000，同时控制 QUIC keepalive 与实际 v5 HEARTBEAT，两种 UDP relay 模式均用 DATAGRAM。
recv-window-conn 实际为 stream，recv-window 实际为 connection；正值同时设 initial/max，
缺省或零值分别按 15 MiB/10、2 MiB 初值与 15 MiB、64 MiB 最大值归一化，
随后采用上述 Middle 策略，默认实际为固定 stream 4 MiB / connection 2 MiB。
窗口是信用额度，不预分配全部缓冲；显式正值不按默认窗口钳位。

max-open-streams 控制客户端 TCP/UDP 所有者池，不扩大 Quinn 内部远端 stream 表；
远端双向流信用固定为 0，单向流为 32。0 使用100；参考客户端100阈值转换90，入池计数必须严格小于阈值，所以
默认89个同时所有者，其它正N为N-1；1和负值可解析但无法开启业务。饱和新建物理
会话，退役会话继续服务已有所有者，最后所有者退出回收，不重放已发送业务。

max-datagram-frame-size 是按规范 type/length varint 编码计的完整 frame 上限，最多1400；缺省以
max-udp-relay-packet-size（0使用1252）+IPv6最坏TUIC头29计算。native relay 的业务
fragment 上限取 frame-29 与实际路径扣头容量交集；能在实际容量内发送的包不分片。
quic relay 按参考在一条单向流发送完整 u16 packet，不使用 native fragment 限额。
frame 配置限制本机发送与分片，不修改 Quinn transport parameter。接收按独立物理预算、
关联和完整包重组预算校验，允许对端采用不同分片大小；未知关联或超预算负载在解码前丢弃。
DATAGRAM 累计收发缓冲仍各256 KiB，独立于 frame 上限。disable-mtu-discovery 缺省
false，PMTUD 探测始终限制在受控双向路径预算内，QUIC payload 最多1400。

udp-over-stream 默认关闭；开启后使用 TUIC Connect 到 `sp.v2.udp-over-tcp.arpa:0` 的 UoT v2，
udp-over-stream-version 省略或整数2均使用v2，其余版本拒绝。首包含 Datagram-mode request，
后续每包携带目标与长度。仍需要 QUIC 数据报物理入口；
首包保留原绝对建链期限；取消单次发送保留一帧进度，后续收发继续完成。
实际错误或超时使关联失效。响应队列1项、任务归节点Stop同步回收。
UoT在可靠流中传输，有丢包导致的队头阻塞成本，不应用原生TUIC分片额度。

连接未确认发送缓冲1 MiB；最多32个并行入站控制解码器，半条控制流最长5秒，
拒绝服务端主动双向业务流。空闲30秒。Stop等待认证、收发、重组、心跳及上游释放，
关闭交换最多一秒；这些是局部结构限制，不是全局业务会话额度。

## Shadowsocks 2022

使用官方 shadowsocks-rust 的加密实现，仅三算法：

| cipher | 密钥 |
| --- | --- |
| 2022-blake3-aes-128-gcm | 16 字节 Base64 PSK，或有序 iPSK1:…:iPSKn:uPSK |
| 2022-blake3-aes-256-gcm | 32 字节，同上 |
| 2022-blake3-chacha20-poly1305 | 单一 32 字节 Base64 PSK |

标准 Base64 可省末尾 padding；空段/非法编码/长度错误拒绝，凭据不 trim。
TCP 使用官方 `CryptoStream` 的加解密与记录分帧，Vole 构造目标地址与 padding 前导。
原生 UDP 使用 Vole 的 SIP022 包层适配官方公共 `UdpCipher`，处理包头、EIH、padding 与地址，
只消费已有受控 IO，不调用 socket 工厂。每关联持有一个当前 TX cipher；AES 至多保留两个
已认证 server session 的 RX cipher，ChaCha 收发复用同一 PSK cipher。未知 server ID 仅使用
临时 cipher，通过认证、类型、时间、client session、地址、负载及重放校验后才保留。
接收复用既有有界缓冲；取消、重放窗口与受控 IO 的生命周期见下文，close/Stop 回收关联 cipher。

### 流式传输插件

一个 SS2022 节点最多使用一个 `plugin/plugin-opts`，包装位于官方 SS2022 codec 之前；
原生 UDP 使用独立受控路径。插件不启动子进程，也不绑定本地代理端口。

- `plugin: obfs`：`mode: http/tls`，`host` 默认 `bing.com`；TLS 模式是 simple-obfs 报文，
  与提供身份认证的 ShadowTLS 不同。HTTP 首个响应头和 TLS 记录均有大小上限，保留尾部字节。
- `plugin: v2ray-plugin` 或 `gost-plugin`：`mode: websocket`，支持 `host/path/headers/tls/mux`。
  host 缺省为 `bing.com`，空 path 使用 `/`，mux 缺省 true。TLS 模式使用 HTTP/1.1 ALPN，
  支持 `skip-cert-verify/name-cert-verify/fingerprint/certificate/private-key/ech-opts`；
  未启用 TLS 时不接受这些选项。Host 头同时确定 TLS SNI。v2ray-plugin 另外接受
  `v2ray-http-upgrade/v2ray-http-upgrade-fast-open`。两种 mux 分别是单通道 V2Ray mux 和裸 smux，
  不附加 sing-mux 的目标与响应头；它们的关闭结束整个下层会话。
- `plugin: jls`：`host/username/password/alpn`；ALPN 缺省 h2、http/1.1，显式空列表保持为空。
  节点 `client-fingerprint` 作用于 JLS 握手；不增加标准证书策略或客户端证书字段。

`client-fingerprint` 仅 ShadowTLS/JLS 插件消费，其余插件不接受该字段。
插件参数只接受对应模式的字段；队列、窗口、连接池和配置范围均有界，取消/Stop 不等待远端回包。

### ShadowTLS v3

SS 三算法的 TCP 可配置 `plugin: shadow-tls` 与完整 `plugin-opts`，不是新的代理类型。
仅整数 version 3，始终 strict/TLS 1.3；不提供 v1/v2、弱认证或版本回退。
host 为独立 cover DNS 名/IP，不参与拨号或业务解析；password 保留原始 UTF-8。
ALPN 缺省 `[h2, http/1.1]`、空列表不发送；支持共享 pin/skip/name-cert-verify、
成对内联 PEM 或文件路径的 certificate/private-key；节点 client-fingerprint 只影响 cover，不能替代 ShadowTLS 密码。

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
任一流式插件。开启时 `udp-over-tcp-version` 省略或整数 2 均固定使用 v2；
关闭时不得提供版本，不支持 v1、协商或原生 UDP 降级。无 SS feature 在 IO 前拒绝。

同一源关联、具体节点和资源代际内，未改写 IP 目标共用一条既有 SS TCP 路径；
其它关联保持独立，不跨来源池化。支持 TCP-only SOCKS5 上游与 select 组。
目标固定为 `sp.v2.udp-over-tcp.arpa:0`；v2 non-connect 请求只发送一次，之后每包
携带地址和 u16 长度。业务域名先经过受控 `ResolutionContext` 转为 IP，magic 不参与
DNS 或路由。AnyTLS 复用同一有界 codec，但保留自己的域名与会话/FIN 所有权。

SS 首包写入并 flush 成功前阻止后台读取；零长度 UDP 仍有非空 UoT 帧。
延迟首包沿用原建链 deadline，成功建立后的业务不再使用旧期限。未发包关闭直接释放
底层 IO，不触发官方空 SS 握手；半帧写取消保留一帧偏移，后续收发继续，不重发前缀。
实际错误或超时使关联失效。每关联最多一个读取
任务、一个排队响应及一个正在解析/等待入队的响应；接收取消不丢 parser 状态，超接收
预算完整排空该包再读下一包。Stop 取消并等待读任务，释放流；不跨关联池化。

编码负载上限为 65,535 字节，发送/接收各自受调用方预算约束。当前官方 Mihomo
UoT 对端使用 16 KiB 接收缓冲；容器数据验收覆盖该实际边界与多一字节负例，不将
内存中的 u16 上限宣称为端到端 UDP 能力。原样 ssserver 不支持 UoT，仅作拒绝负例。

### 共享 SS 流与数据报行为

- TCP 每次最多交付 16 KiB；首次非空写与目标前导合并。首次读、显式空写或上传半关闭
  可发送不含业务数据的前导，padding 长度为 1–900 字节，内容明确初始化为随机字节，
  并在读取响应前完成刷新，支持 server-first。Pending 继续同次握手，不重复目标头或业务。
  握手完成后的空写不发送额外记录；零容量读取和单独 flush 不启动握手。
  SS 层上传半关闭保留读侧，外层传输与对端仍遵循各自的关闭契约；
  Drop、取消与 Stop 不额外启动握手。
- 背压适配最多暂存一个 16 KiB 原文块并立即报告接受；后续保持同缓冲完成写入，
  避免官方重试长度误计。flush/关闭排空，读取也推进待写但不被写背压阻塞。
- 原生 UDP 取消前预留 packet ID，底层实际发送后才成功；Pending 不重编码，无后台发送队列。
  接收验证来源、认证、关联与完整负载，外层 wire 最大 65,507。
  每次成功发送后，在下一包编码前合作退让；不添加发送队列或限速器。
  同一来源、具体节点和资源代际内，未改写 IP 目标共享受控 socket、codec 缓冲和重放窗口；
  逐目标统计、取消及旧回复隔离沿用[资源策略](runtime-resource-policy.md#udp)。
- 每关联随机 client session ID、递增 packet ID，最多两个 server session 的 8128 包
  重放窗口；旧 session 一分钟仍有有效包时不替换，ID 将溢出时换 client ID 并清空窗口。
  close 清空并关闭底层，不新增后台任务。

依赖仅 crates.io 版本，不使用 Git/path/源码补丁。AWS-LC 仅允许沿 shadowsocks →
shadowsocks-crypto 链使用，TLS/REALITY 不消费它，详见[TLS 依赖](tls-dependencies.md)。
重放窗口派生代码的来源/完整许可保留在源码头，发布仍审计实际链接图。

TCP 前导不使用上游私有的 padding 构造器；响应在交付前校验 request-salt 与本连接
发送 salt 的绑定，类型、时间与认证仍由官方 codec 校验。裸 SS、AES EIH 与外包
ShadowTLS v3 共用此路径，不通过伪造业务字节或握手失败重拨支持 server-first。
空原生 UDP 使用调用者持有的临时编码缓冲：按 nonce、身份、地址、最大 900 字节
padding 和 tag 的完整上界初始化，SIP022 包层仅将已初始化字节交给官方 cipher。
缓冲不常驻，不为普通非空数据报增加整包初始化；session/packet ID、取消和重放保护不变。
SS UoT 仍由非空请求帧和专用读取门控完成首包，不触发独立空 SS 握手。
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

reserved 缺省为空（全零），否则接受三字节数组或解码后恰好三字节的标准 Base64 字符串。peer 缺省继承顶层值；发送时写入
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
查询经过该 WireGuard 节点的内层 TCP/UDP。dns 支持 Core 的 UDP/TCP/DoT/DoH/DoQ/RCODE
上游；fragment 中的出口 token（包括未定义的名称）不改变这个固定出口，键值参数仍按
通用 DNS 契约解码一次并消费 ECS、类型过滤、证书策略和 DoT 复用设置。私有解析器
不继承全局 prefer-h3，HTTPS 的显式 h3=true 仍强制使用 H3。DNS 上游域名仍由 Core 的代理 DNS 角色 bootstrap，
不通过节点私有解析器解析自身端点。私有缓存有界，查询由调用方持有，不保留空闲 TCP
连接或独立后台清理任务。关闭该开关或 dns 为空时使用受控本地 DNS；两种路径都遵循
节点 ip-version、全局 IPv6 开关、本地地址族与原建链期限，失败不回落 DIRECT。

refresh-server-ip-interval 默认 0，关闭更新；非零值以秒计，新业务在间隔到期后触发
所有已建立 peer 的端点重新解析，负值每次检查均到期。不创建额外周期任务。IP 不变时保留物理会话；
变化时保留共享栈、TCP 状态和 UDP 端口，替换外层会话并重新握手。解析或新上游配置失败
保留原端点，下次业务重试。

节点 raw 包队列和各 peer 发送队列各 32 项；每 UDP 关联响应队列 64 项。UDP 负载上限
为 MTU 减本地 IP/UDP 头，再与调用方收发预算分别取交集；双栈保守扣 48 字节，IPv4
扣 28 字节。TCP 栈输出交给已就绪 peer 时先尝试入队；Full 时只暂持当前包与原 peer
代际，释放 peer 槽位锁后，在同一次队列准入的轮询之间给一次协作调度机会，仍满则丢弃，
TCP 依赖重传。全局取消优先结束输出 pump，其次处理原 peer 取消，不把待交付包改投新代际。
这次退让会暂缓共享输出 pump，不承诺其他 peer 零等待或固定墙钟时限。
解密后到栈的 raw 包与 UDP 响应仍在满队列时丢当前包；业务 UDP 发送保留直接等待原 peer
发送队列的可取消路径，不经过 TCP 输出 pump。解密后校验本地目的地址、来源地址族、
最长前缀所属 peer 和关联端口；这些是局部结构边界，不是业务连接总数限制。

握手、收发、更新与重试均可取消；驱动由节点持有，调用方 future 丢弃不会丢失任务
所有权。Stop 关闭新准入，取消并等待所有 peer 与退役驱动，关闭各上游（分别最多一秒），
随后等待用户态栈退出；私有 DNS 使用弱节点引用，不延长节点生命周期。
