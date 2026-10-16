# XHTTP 与通用 sing-mux

XHTTP/sing-mux 使用严格字段与类型；未知、null、无效或被忽略的组合在 IO 前拒绝。
REALITY、JLS、ECH 的身份规则见 [VLESS](vless.md)，实际验证边界见[验收说明](acceptance.md)。

## HTTP 版本和连接模式

`network: xhttp` 使用现有 Dialer、上游图、保护接口与 SecurityClient，不另建系统解析器或裸 socket。`alpn: [http/1.1]` 选择 H1；空列表、`[h2]` 或包含 H1/H2 的列表选择 H2；只有独占 `[h3]` 选择 H3。不会静默降级 HTTP 版本。

H1/H2 可使用明文、标准 TLS 1.3、REALITY（经典默认、显式混合模式）或 JLS。H3 使用官方 h3/h3-quinn 与 Quinn，必须使用标准 TLS 1.3，不允许同腿明文、REALITY 或 JLS。QUIC 收发走受控数据报，上游任一方向有效预算小于 1200 字节即拒绝，不绕开代理、protect 或接口绑定；发送从 1200 字节起探测 MTU，探测上限受发送预算约束，接收广告独立使用实际接收预算。

`xhttp-opts.mode` 接受 `auto`（省略或空串默认）、`packet-up`、`stream-up`、`stream-one`。auto 在 REALITY 无下载配置时选择 stream-one，有下载配置时选择 stream-up，其余选择 packet-up。stream-one 是一条双工 POST，不允许 `download-settings`；其余模式以同一会话 ID 关联上传与下载。`path` 省略或空串默认 `/`，`host` 显式非空优先，否则使用该腿 servername/server；IPv6 authority 使用方括号。主腿与下载腿的 host 均禁止 userinfo（`@`）。

## 请求字段

区间字段接受字符串 `"N"` 或 `"N-M"`；`uplink-chunk-size`、`sc-max-each-post-bytes`、`sc-min-posts-interval-ms` 还接受 YAML 整数，使用相同的范围与配套校验。空串或纯空白使用字段默认，字符串中的数字及区间两端允许外围空白和正号。其他区间字段不接受数字类型；所有字段均拒绝 null、浮点数、布尔值、负数、倒置区间或溢出。每次采样保持在闭区间内。

| 字段 | 默认及约束 |
| --- | --- |
| `headers` | 字符串 map；最多 100 项 / 8 KiB。禁止 Host、定界/逐跳头、CRLF、大小写重复及与生成字段冲突。值不进入 Debug |
| `no-grpc-header` | false；true 关闭流式请求的 application/grpc，packet-up 不接受 true |
| `x-padding-bytes` | `"100-1000"`，1–4096 |
| `x-padding-obfs-mode` | false：固定 Referer 中的 `x_padding`、queryInHeader、repeat-x |
| `x-padding-placement` | 混淆开启时必填：queryInHeader/header/query/cookie |
| `x-padding-key` | 混淆 queryInHeader/query/cookie 时必填；header 不使用此字段 |
| `x-padding-header` | 混淆 header/queryInHeader 时必填合法头名；其他位置不使用 |
| `x-padding-method` | repeat-x；开启混淆后也可 tokenish，按 HPACK 编码后的长度生成 |
| `uplink-http-method` | POST，也接受 PUT/PATCH/DELETE；不将 GET 或 OPTIONS 用于上传 |
| `session-placement` / `session-key` | path（不填写 key）；header 默认 X-Session，query/cookie 默认 x_session |
| `session-table` | 空：32 字符随机 hex；uuid：标准 UUID v4；或预定义/自定义去重 ASCII 字符表 |
| `session-length` | 字符表模式默认 `"16-32"`，1–128；全部长度构成的命名空间至少 2^31。空表/uuid 不接受显式长度 |
| `seq-placement` / `seq-key` | 仅 packet-up；path，或 header 默认 X-Seq、query/cookie 默认 x_seq |
| `uplink-data-placement` | body，auto 归一 body；header/cookie 仅用于 packet-up |
| `uplink-data-key` | header/cookie payload 必填，body 不接受 |
| `uplink-chunk-size` | header/cookie 默认 `"0"` 自适应；显式区间 64–8192。自适应 header 3072–4096、cookie 2048–3072 |
| `sc-max-each-post-bytes` | packet-up，`"1000000"`，1–16 MiB；这是 POST 上限，不是预分配缓冲大小 |
| `sc-min-posts-interval-ms` | packet-up，`"10"`，0–60000 且最大值须为正；允许 `"0-N"`，不允许纯零 |

session/sequence 均支持 path/query/header/cookie。键使用至多 64 字节的 HTTP 安全 token，禁止互相冲突以及覆盖 padding、payload 或既有 query/header。字符表预定义值包括 `ALPHABET`、`Alphabet`、`alphabet`、`BASE36`、`base36`、`Base62`、`HEX`、`hex`、`number`。

路径遵循 Mihomo：session 或 sequence 任一放在 path 时补尾斜杠，否则保留显式路径。原生 Xray 的 handler 始终补尾斜杠；因此与 Xray 互通且两项均不在 path 时，须显式配置带尾斜杠的路径（例如 `/proxy/`）。这是对端路径配置差异，不通过修改 Vole 的默认规范化规则解决。

header/cookie payload 使用无填充 Base64URL，并按实际请求预算拆块；完整请求（URI、生成字段和自定义头）不超过 16 KiB / 128 项。业务数据按有界块处理，不把整个 POST 限额、对端声明或业务流读入无界 Vec。

H3 响应 HEADERS 的解码字段预算为 16 KiB，编码 payload 预算为其 1.5 倍（24 KiB），在帧声明长度到达时检查；SETTINGS payload 最多 256 字节，携带单个 varint 的控制帧为 1–8 字节。未知非 DATA 帧也受 24 KiB 编码预算限制，超额提前拒绝，不等待完整 payload。这比 quiche 路径最多 16 MiB、流式跳过未知帧的范围更窄，以避免官方 h3 解码器累计整帧造成内存增长；DATA 仍增量交付，不受该整帧预算限制。

Quinn H3 接收适配层分别交付帧头和正文，不跨帧预读；至多保留一个原生接收块的剩余切片，
与原块共享内存。这使应用的读取进度持续约束 QUIC 接收额度，避免合并小 DATA 帧在解码层积压。

packet-up 在发送间隔内聚合小块写入，而不是把每个 write 变成一个 POST。最多保留一个批次，包括 HTTP 正在发送的正文；每批最多 64 KiB，并与本连接采样的 POST 上限取较小值。POST 在途时向写入方施加背压，不另外积累下一批；头部 payload 仍按请求预算拆分。write 完成只表示数据已进入有界缓冲，flush 等待对应 POST 确认；计时器无需调用方再次读写即可发送。shutdown 立即尝试 flush 未发送批次，卡住的 POST 仍受一秒上限控制。计时器/上传任务归节点所有，Stop 同步等待。

批次缓冲按需扩容，分配容量也受该批次上限约束，避免不规则帧尺寸使倍增扩容超过预算；writer 不预分配完整批次。POST 确认后复用已独占的正文 backing；HTTP 尚持有引用时释放本地引用，不为回收再复制正文。每个 writer 至多保留这一批缓冲，逻辑连接关闭时释放。

body/auto 模式的 POST 共享已冻结批次的不可变 backing，不额外复制一份业务负载；
发送任务和批次所有者分别释放引用，头部/cookie 模式继续使用有界编码。
H1 编码保留正文 backing，不将整批正文再次拼入头部写缓冲；每次向所供应 IO 提供的正文片段最多 16 KiB，避免一次提交整批正文使 TLS 同时缓冲多个记录，
并保留原有 flush 确认与 Stop 屏障。

默认间隔使用 10 ms，配合 64 KiB 批次降低持续负载下的积压；这是 Vole 的资源策略，显式配置的间隔保持原值。
首次非空批次等待采样间隔；后续以 POST 发起时间计时，前次交换和空闲时间计入间隔。
空闲超过间隔后可立即发送新批次。底层准入和网络可能推迟发送，计时不代表线上首字节间隔。

## 独立下载腿

`download-settings` 缺省和 `{}` 不等价：存在即启用独立下载连接/池，但仍共用一次 VLESS 握手、会话 ID 和建链上下文。两腿必须汇聚到**同一个原生 XHTTP handler 的会话表**；两个独立 listener 不能构成共享会话。

可覆盖 `server/port/tls/servername/alpn/host/path/headers`、`client-fingerprint`、普通 TLS 的 `skip-cert-verify/name-cert-verify/fingerprint/certificate/private-key/ech-opts`、`reality-opts`、`jls-opts` 和 `reuse-settings`。

- 缺省叶字段继承主腿。headers 是整体替换，`{}` 清空；显式空 host 恢复下载认证名/server 推导。
- `skip-cert-verify: false` 必须覆盖主腿 true；空 name-cert-verify/fingerprint 清除对应 override/pin。
- `client-fingerprint` 缺省继承，显式名称覆盖，`none` / 空串清除。下载腿切到明文或 H3 前必须清除继承的已启用 profile；它不属于证书策略，不因切换 TLS/REALITY 自动清除。六值/四模板见 [TLS 指纹](tls-client-fingerprint.md)。
- certificate/private-key 必须配对替换或同时空串清除；PEM 与密钥匹配在 IO 前检查。
- reality-opts 缺省继承整个对象，`{}` 清除；非空对象必须提供 public-key，short-id 缺省空、support-x25519mlkem768 缺省 false，不按叶合并旧对象。仅提供混合开关不等同空对象，仍须提供 public-key。null 拒绝。
- jls-opts 缺省继承整个身份，非空对象必须完整替换 username/password，`{}` 清除；同腿与 REALITY 和证书策略互斥，切换时须显式清除旧对象。JLS 仅 H1/H2，实际 TLS1.3，无恢复；完整约束见 [JLS](vless.md#jls)。
- ech-opts 缺省继承、对象整体替换，`{}` 清除。`enable: true` 使用非空静态 config 或节点 DNS 的 HTTPS key 5，静态优先；query-server-name 只覆盖查询名。按下载腿实际 TLS backend 从完整来源重选配置。仅标准 TLS，可用于 H1/H2/H3；切换到 REALITY/JLS/明文前必须显式清除继承的 ECH。失败不重拨或重放。
- 切换到明文或 REALITY 不会悄悄丢弃继承的证书策略；须显式清除冲突字段。每条腿独立重新校验最终安全配置。
- 独立地址/端口在实际建立物理连接时通过节点 resolver 分别解析；两腿共享原绝对期限和每个上游组的选择快照，下载失败不会另起超时预算或绕过原图。

## HTTP transport 复用

`reuse-settings` 缺省时，H1/H2 不建立节点池；H3 只共享活动物理连接，每条最多承载 4 个活动逻辑租约。
最后一个租约释放后立即移出候选池，并进入既有的有界传输收尾流程，不保留空闲候选。
这限制了并行连接的重复开销，不是全节点业务准入额度。
`{}` 启用显式复用池，使用下表默认值与有界空闲缓存。
下载配置缺省继承整个主腿 reuse 对象，显式对象整体替换，未填写项回到零，不逐字段继承。

| 字段 | 语义 |
| --- | --- |
| `max-concurrency` | 候选 transport 的并发挑选阈值，默认 `"0"` |
| `max-connections` | 优先扩到的候选数，默认 `"0"`；全部忙时仍可扩容，不是全节点硬上限 |
| `c-max-reuse-times` | 复用次数预算，默认 `"0"`；耗尽后不再分配新流 |
| `h-max-request-times` | 按领取 transport 扣减，默认 `"0"`；不按每个 packet-up POST 扣减 |
| `h-max-reusable-secs` | 按物理 transport 年龄退役，默认 `"0"`；活动逻辑流继续 |
| `h-keep-alive-period` | 整数秒；0 为 H2 45 秒 / H3 10 秒，负数禁用，正数指定周期；H1 仅接受 0 |

前五项接受 0–i32::MAX 的字符串区间。h-max-request-times 和 h-max-reusable-secs 只有最大值为零才禁用；例如 `"0-1"` 采样到零仍按零预算或立即到期处理。c-max-reuse-times 则与 Mihomo 一样，采样值为零即不启用该项限制。两腿池与计数独立。已建物理连接保持原上游选择；创建新连接时才使用当前选择。H1 仅复用完整结束的上传请求连接，不复用取消的下载 GET。节点空闲缓存有界；它不构成业务流数量额度。

## 通用 sing-mux

所有已启用的普通节点协议都接受 `smux`，字段为 enabled、protocol、max-connections、min-streams、max-streams、padding、only-tcp、statistic。enabled 默认 false；protocol 缺省/空为 h2mux，也支持 smux v1/yamux。计数为带符号平台整数；负阈值禁用，两个正 max 字段同时配置时采用 max-connections 分支。padding、only-tcp、statistic 默认 false。Vision 与启用的 sing-mux 互斥。精简构建可独立启用 `sing-mux`，不要求 VLESS；未启用此 feature 时拒绝 enabled=true。

`statistic: true` 在 Running Session 的连接注册表记录每条真实底层认证流，类型 Inner、
目标 sp.mux.sing-box.arpa:444，节点和 provider 名称共享不可变文本。复用流共用一条
Inner 记录。它的字节单独可见，不重复计入业务 uploadTotal/downloadTotal；Controller
关闭此记录会终止底层 I/O 和所有兄弟复用流。退出/Stop 同步回收 driver 与记录。

空闲物理会话优先复用；max-connections>0 分支按连接数量与 min-streams 扩容，否则按 max-streams 阈值复用。两个 max 字段字面值均为零时 min-streams 归一为 8；归一在负阈值禁用之前执行，不把该值解释为所有调度分支的硬额度。每节点和资源代际的池独立，单流关闭不关闭兄弟流，节点 Stop 才取消和等待所有自有驱动。

每条逻辑流的状态字节沿用该次建链的绝对期限；读取前先检查超时，状态已缓冲也不例外。
物理连接复用不重置期限；状态已确认后的业务读取不受原建链期限限制。

smux v1 单流 shutdown 先等待已接受帧写入并 flush，再安排 FIN 并结束整条逻辑流。
h2mux 和 yamux 关闭上传后保留读取与租约，允许对端继续发送尾部；h2mux 的上传
数据须到达上游 IO 的 flush 边界再发送 END_STREAM。节点 Stop 或 Drop 可取消待写，
不承诺异常终止交付。

yamux 的内部资源边界是单物理连接累计分配 64 个流后退役；旧流继续，新请求另建连接，空闲即回收。该边界避免逻辑取消与库内 reset 回收不同步时误关兄弟流，不是全节点额度，详见 [资源策略](runtime-resource-policy.md)。

sing-mux 的外层是底层协议的普通 TCP 到 `sp.mux.sing-box.arpa:444`，VLESS 使用 CommandTCP。对端必须提供 sing-mux 解码；普通 HTTP/SOCKS5 服务器不会自动解码，接受包装配置不等于默认服务器互通。only-tcp=false 时 UDP 使用 mux 的逐包地址格式，经受控解析处理域名，并提供有效 UDP 能力，即使底层 `udp: false`；true 时原样委托底层 UDP，保留其能力、编码、会话和预算。组 disable-udp 仍限制业务。padding 覆盖握手及最初 16 个物理写入帧；接收增量解析和丢弃 padding，不按声明长度无限分配。

## 关闭、安全与验收边界

XHTTP 关闭整条逻辑连接：shutdown 先尝试送完已接受的上传，再取消下载，
所有模式的待决上传最多等待一秒；超时或节点 Stop 可以取消，异常终止不承诺交付。
H1/H2 流式 flush 等待已接受的 payload 到达所供应 IO 的 flush 边界；H3 stream-one / stream-up
flush 等待上传任务写入 QUIC。packet-up flush 等每批 POST 的成功响应与有界响应 body 结束。
shutdown 提交上传 FIN 后释放物理连接租约，不提供逐请求的远端 ACK 屏障。
这些等待不依赖下载响应。需要完整回复的应用必须在关闭前读完；不承诺 TCP 半关闭
后继续收到尾包。复用只延长物理 transport 生命周期，不改变单个逻辑连接的关闭范围。

H3 的 QUIC 驱动、数据报适配器和后台任务归节点所有。物理连接退役立即停止新请求准入，
在既有一秒关闭预算内继续发送和接收，再关闭并 join 内部任务与上游 IO；这段传输收尾
不构成远端 ACK 屏障。未完成的上传取消会 reset 当前请求，已提交 FIN 的发送不因此 reset，
兄弟流继续。shutdown 返回不代表物理驱动已退出；Stop 返回以任务回收为准，不把 Drop 或等待时间当作完成证明。

H1/H2 原生验证优先使用官方 latest Mihomo；H3 使用官方 latest Xray。不被 Xray 直接解码的 packetaddr/sing-mux 使用明确标注的 Xray XHTTP → Mihomo VLESS 分层拓扑；mTLS 使用已批准的 xcaddy/Caddy H3 网关，后端仍是同一个 Xray handler。分层成功不改写直接对端失败。所有服务端与原站在隔离容器中，配置和私钥不入 Git；原生数据、公共入口、资源、跨平台构建和阶段签收分别记录。
