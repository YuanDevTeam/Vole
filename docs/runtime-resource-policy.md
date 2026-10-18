# 运行时资源策略

所有 TUN 运行时使用同一组局部结构上限。Vole 不根据业务流总数或整进程内存读数拒绝正常流量；容量控制放在包、队列、缓冲区、缓存、解析器和生命周期所有者处。

## 原则

1. 数据正确性、安全边界和同步停止优先。
2. 数据面队列、缓冲区、缓存和解析器保留局部容量边界；空闲资源必须有回收机制。容量界与时间回收不是同一保证。GeoData 在所有平台均不设记录条数硬上限、截断或总内存预算。
3. TCP 会话、普通 UDP 关联、半开连接、出站握手和活动 DNS 传输不设置固定业务数量上限。
4. 队列满时按局部协议语义丢当前项目或失败，不能阻塞 TUN 回调或全局循环。
5. 当前值和峰值只用于诊断，不参与 admission。
6. 平台内存采样是尽力而为的遥测，不改变生命周期结果。

长期业务引擎（FFI 的 TUN / 非 TUN 及 Windows Session Host）统一使用
Tokio `new_multi_thread()`，不按 TUN 分叉，不自行读取 CPU 数或设置 worker 数。
worker 数遵循 Tokio 默认行为（包括其 `TOKIO_WORKER_THREADS` 环境覆盖）；
线程栈使用 Tokio / Rust 默认值，不固定为 1 MiB。
启动准备和 `measureDelay` 保留共用的单线程执行策略，不按 TUN 分叉。
工作线程（含阻塞任务线程）继承 Invoke 重入保护，
Apple 平台另保留线程局部日志作用域；同步停止仍等待子任务与运行时线程退出。
Release 构建优先吞吐（`opt-level = 3`），保留 thin LTO 与现有缓冲、队列边界。

## TUN 结构上限

```text
原始包 / MTU                    tun.mtu
最终代理 UDP 负载               配置 MTU - 48
包队列                          256
普通事件 / TCP accept           128
每关联 UDP 入站                 64
普通 UDP 响应                   256
DNS 响应                        128
每个 TUN TCP 方向缓冲区         4 KiB
TLS / XHTTP 缓冲区              64 KiB
DNS 结果总容量（每角色）         默认 4,096 项，dns.cache-max-size
DNS 原始响应缓存                64 项 / 256 KiB
TUN 域名提示                    256 项（按需）
```

MTU 由 `tun.mtu` 配置，默认值和平台限制统一见 [TUN 平台层](tun-platform.md#mtu-与结构上限)。

- 普通 UDP 在 reader 同步分流并直接提交到每源关联，不经过 TCP Driver 或共享 UDP 入站队列；DNS 查询独立提交受跟踪任务。
- 每关联请求、普通响应和 DNS 响应使用独立内部容量，不扩大 128 项的 TCP accept，也不增加公开配置字段。
- netstack 每轮维护 socket 与连接请求后，优先处理已就绪的原始入站批次，再处理内部通知；停止保持最高优先级。原始入站暂满时，当前包最多保留一个协作调度回合并重试，持续满时丢弃；UDP、DNS 和停止继续独立推进，队列容量保持原值。
- TUN 域名提示只在 TUN 配置实际包含域名规则时创建，并从空容量按需增长。
- 域名提示的读写使用短同步锁，临界区内不等待 IO 或执行异步操作；新 TUN IP 流读取当前提示，活动 UDP 五元组保持既定 action。
- ICMP 响应复用原始包出站队列，不创建独立任务或长期状态。
- TUN 读写每批最多处理 8 个已就绪包，不等待凑批。按配置 MTU 复用至多 8 个读缓冲区；
  唯一 writer 公平轮转 TCP/ICMP raw、普通 UDP/DNS 响应三通道，至多暂持 8 包，
  UDP 在复用 MTU frame 中构包，不增加中转队列。非法输出也计入工作预算。批次中途取消或
  失败仍按已完成结果逐包统计；非法包局部隔离，Unix 系统调用保持单包边界。
- 有局部预算的结构在扩容前检查额度；GeoData 保留格式、语法、整数可表示性、正则库默认局部保护和实际分配失败检查，不按记录条数截断。

## TCP 与握手

- TCP 流按需创建任务；TUN 转发每方向缓冲区为 4 KiB。
- netstack 的 TCP 应用队列从空分配按实际写入有界增长，保留每方向 16 KiB 逻辑上限；排空不收缩，连接释放时销毁。smoltcp 收发缓冲仍各为 16 KiB，不用进程内存或连接总数改变容量。
- rustls/XHTTP 的配置缓冲区为 64 KiB；boring 每次应用写入最多 min(节点缓冲预算, 16 KiB)，原生 TLS 记录有界，命名模板证书消息/解压输出另限 128 KiB。
- 标准 TLS 恢复会话总预算为 4，按节点（含独立下载端点）分配；每个缓存绑定不可变的 SNI、ALPN 和证书策略，绝不跨节点复用。TLS 1.3 票据有界、一次性消费，TLS 1.2 会话占用同一额度；额度为 0 则禁用恢复。REALITY 不参与该缓存。
- 共享 TLS 客户端的显式验证名、协议版本、客户端证书身份和 ClientHello profile 也属于不可变策略，单独构造缓存，不跨身份共享。boring 只保存当前节点/SSL 上下文产生的票据，应用层 ALPN 接受前不发布，失败或取消丢弃临时票据。标准 TLS 和 REALITY CloseWrite 只发送 close_notify，刷新最多5秒，保持读方向和底层传输；Drop 释放整个流。XHTTP 仍以逻辑连接整体关闭为准。
- 半开连接、出站握手和活动会话只记录当前值和峰值，不触发资源错误。
- 超时、取消、EOF 和协议错误负责回收；停止必须等待全部已跟踪任务结束。
- 引导解析器最多使用四个工作线程；全部忙时在调用方既有期限内等待，不返回人为容量错误。

### 物理 socket 初始化

TCP/UDP 共用 Dialer：创建 socket、nonblocking、源地址/Windows 接口绑定与 protect
在当前 Tokio runtime 的受跟踪阻塞任务中完成，避免 FD 表扩容等同步系统调用占满
业务 worker。异步 connect、reactor 注册与收发仍在原 runtime，不新增独立线程池、
CPU 数判断、业务数量配额、FD 预热或 DNS socket 复用。

每个初始化作用域最多持有 4 个未完成的阻塞提交，TCP/UDP 共用内部许可。
在登记任务、创建 socket 和 `spawn_blocking` 前异步等待许可，不因繁忙返回容量错误；
等待继承调用方期限和取消，Stop 关闭准入并唤醒等待者。许可由阻塞任务持有到真正
完成或被丢弃，调用方提前取消不会释放已开始工作的许可。它不限制已建立连接，
不增加独立线程池或公开配置；也不把等待调用的数量或整进程内存变成有界保证。

取消关闭结果接收器并跳过尚未开始的初始化；已开始的系统调用或同步 protect 不能
强制中断，完成后丢弃未交付的 socket。每个 Running Session/测速图拥有独立的
初始化作用域。Stop 先关闭 admission，再取消并等待业务/协议任务，最后等待已登记
初始化任务完成，才释放平台回调租约。测速 runtime 的销毁也使用完整 join，不能
以有限 shutdown timeout 脱离在途初始化。protect 仍必须快速、同步、非阻塞；
线程位置变化不放宽宿主回调契约，也不改变保护失败关闭或 Windows 双绑定策略。

## 共享流传输基础

`stream-transport` 仅包装传入 IO，不创建 socket 或 DNS。WS/HTTP响应首部最多16 KiB、100字段；WS用户请求头最多100字段，额外固定升级头和early-data仍计入16 KiB总预算。WS early-data最多2,048原始字节，头名称/路径后缀由类型化选项区分。WS消息和单帧最多64 KiB，写入切块16 KiB；HTTP首包正文直接写入，不整体复制或持续按HTTP正文定界。

共享的无池gRPC/legacy H2适配器每个实例仅拥有一条底层连接与一个逻辑流，不是全局并发许可。Trojan/VMess/VLESS共用节点级gRPC池，物理连接按节点实例隔离，复用保留原上游与安全策略，每条逻辑流独立认证。流窗口64 KiB、连接窗口128 KiB、最大HTTP/2帧和发送缓冲各16 KiB、解码负载64 KiB。读侧按实际消费量释放窗口；每poll最多处理32个片段/控制消息。Trojan池使用内部duplex模式，仅发送END_STREAM并保留读取和lease；VMess/VLESS只结束当前逻辑流。关闭前已接受的数据须到达所提供IO的flush边界，不能仅排入h2队列后立即reset/abort；每个逻辑写端最多一个待确认数据块，Stop可取消等待。节点池最多保留4条空闲连接，PING ACK期限15秒；节点Stop取消并join全部物理驱动。无池模式的owner.stop同样等待驱动任务退出；Drop只做取消兜底，不作为同步停止通过证据。WS/HTTP适配器按底层CloseWrite语义工作，协议包装层可以根据已声明的协议关闭契约结束整个逻辑流。所有握手使用调用方同一个绝对deadline。

XUDP现在只拥有已认证流上的帧编码；VLESS响应头由VLESS包装层处理。元数据仍最多512字节，单payload仍受调用方预算和u16 wire上限约束，不新增全局会话额度。接收直接填充既有的单帧有界缓冲，保留合并到同次读取中的后续帧与取消后的解析进度，不增加固定暂存区。

公共 sing-mux 包装器按节点拥有独立池，只消费底层协议到约定目标的 TCP IO。
每池最多保留16条闲连接；命令/物理写队列16项、写块16 KiB，smux每流接收队列4项。
yamux单连接累计接纳64流后退役，连接接收窗口16 MiB；活动兄弟流继续。
h2mux/yamux上传半关闭保留读取与lease，smux v1关闭整条逻辑流。
图只登记最终包装器；begin_shutdown同时关闭mux和底层准入，shutdown先join全部
mux驱动，再等待底层协议。provider代际与node-only测速复用此屏障，没有全局池。

## 协议局部预算

协议专用上限与关闭语义只维护在[入站](inbounds.md)、[出站](outbounds.md)、
[VLESS](vless.md)和[XHTTP/sing-mux](xhttp.md)。`tests/protocols/limits.json`
绑定实际常量与越界用例，不是第二套运行时配置或可配置业务准入数。

## UDP

普通 TUN UDP 关联：

- 共享已发布代际的不可变节点和策略组注册表，不为每个关联复制指针数组；旧会话保留原代际直到释放；
- 关联表不设固定项数；
- 每个关联的入站队列最多 64 项，满时只丢当前数据报，不等待慢关联并阻塞其他来源；
- 普通响应队列最多 256 项；满时每源关联最多暂持一个已接收响应，暂停该关联继续接收，
  同时等待写回容量、处理请求和取消，不增加队列或任务。取消或错误时丢弃未提交响应；
  没有共享 UDP 入站中转队列；
- 每源关联每处理 32 个实际响应显式退让；共享响应队列占用达到四分之一时提前退让，
  让唯一 writer 与其他关联推进。不等待凑批、不预取包、不按忙碌情况拒绝关联。
  接收的原生合作预算继续保留。
- reader 拥有关联表和入站分发，唯一 TUN writer 直接、公平消费普通/DNS/TCP raw 三个通道；写回等待不阻塞 reader，不增加逐关联写回任务；
- TCP/ICMP ingress 满时非阻塞丢当前完整 IP 包，避免阻塞 UDP/DNS，记录 packet queue drop；TCP 重传恢复，不引入 pending FIFO；
- 使用代次感知所有权和子取消令牌；
- 空闲超时由 `tun.udp-timeout` 配置；
- 清理时先从表中删除，再取消子任务；
- 只有成功入队的请求或响应刷新活动时间；
- 源关联内的 IP 五元组仅保留规则 action、活动时间和可选 QUIC 连接标识，
  不创建逐流任务、队列或 socket；不设流数量上限。各目标按 `tun.udp-timeout` 独立空闲失效，
  关联收发时按维护周期扫描回收并收缩明显过大的表容量；关联关闭释放整个表。
  响应只刷新自身已存在且未过期的目标，不创建状态或复活过期流。
  五元组活动以接收请求或读到匹配出口响应为准；源关联仍只以成功入队刷新，
  响应队列满不会延长源关联所有者的生命周期。
- reader EOF、错误或取消时，先取消其 UDP 子作用域，再删除、取消并等待全部关联和 DNS 任务；父运行时统一取消并等待唯一 writer 与 netstack。UDP 子作用域停止不取消调用者令牌。

开启 Controller 的业务 UDP 按目标独立统计、取消并固定出口。提供多目标与取消安全帧边界的
XUDP、UoT、原生 SS2022 和 HY2 UDP 在同一源关联、同一具体节点和资源代际内共享 transport；仅用于未改写的 IP 目标。
fake-IP、QUIC 目标改写、域名及其它未声明共享能力的协议保留独立 transport。
共享路径只有一个接收者，按回复地址找到仍有效的目标，未请求或过期回复丢弃。
目标退出后物理关联退役，继续服务既有目标，新目标另建关联；防止目标重建或 flow-id 更换后
旧回复串入新会话，不保留历史目标墓碑。最后目标退出关闭关联，Stop 同步释放全部关联。
每目标只登记取消通知，不分配逐目标接收 future、任务或负载队列。
DIRECT 在源关联内共用一个延迟分配的接收暂存缓冲，保留预算加一字节的超长包检测；
交付包只持有实际负载。持续的就绪队列每目标最多一个通知，接收只轮询被唤醒的目标，
不新增逐目标任务或负载队列。Mieru 通过私有单槽响应交接提供相同的就绪轮询，
容量仍为一项，满槽使后台完整包解析器等待；取消、关闭及 reader join 保留。
未提供轮询接口的协议继续使用取消安全的异步接收。
成功接收后的本地 FIFO 重排不唤醒正在运行的接收者；外部就绪、取消和工作预算耗尽仍保留唤醒。
目标访问时检查自身过期，整个表每 10 秒清理并回收多余容量；流量不会推迟该期限。
DELETE 通过取消令牌立即唤醒等待中的接收，关闭与 flow-id 替换移除旧就绪注册。

### 定向数据报预算与受控 QUIC

`DatagramBudget` 分别表达当前层的发送和接收 payload 上限。嵌套协议先为下层申请有界 envelope 空间，再按实际协议/地址族开销扣除下层能力，与调用方预算取交集；不能把接收上限直接当作发送能力。DIRECT、SOCKS5、SS 2022、SS/AnyTLS UoT 和 VLESS XUDP 保留对端/地址校验。超出发送预算在写入前失败，超出接收预算丢当前包并有界让出执行权，close 后不能恢复收发。UoT 的流头不从 UDP payload 预算扣除；SS 首包门控、读取任务与单响应队列的局部上限见[出站](outbounds.md#udp-over-tcp-v2)。

UoT 写入最多暂持一帧及偏移；取消单次发送后，后续收发先完成它，原建链期限不重置。
实际写入失败或超时使关联失效；关闭丢弃未提交帧，并取消、等待既有读取任务。

`quic-transport` 只把已有 `DatagramTransport` 适配成 Quinn/quiche 共用的受控 UDP 接口，没有内部 bind、DNS 或 DIRECT 回落。每个连接双向各最多32个排队数据报，另允许一个正在发送的包；TX满返回WouldBlock，RX满暂停读取。接收等待不会持有发送队列锁；Pending发送不会重复提交。单逻辑peer/物理peer映射和来源校验独立保留，不接受未请求的目标、GSO或源地址覆盖。物理 socket 仍只能来自 Dialer。
已打开且受保护的 UDP 路径可借出一个在途发送操作；驱动等待发送或 pacing 时继续接收，保持32包队列与一个发送中的包。首次发送仍由原路径完成初始化；上游不支持此能力时沿用原发送。停止先释放在途操作，再关闭并释放上游。
立即就绪的读取、发送容量与发送完成检查不登记新的等待者；仅在同一状态锁内确认 Pending 后登记唤醒，保留后续数据、容量恢复、取消与 Stop 的通知。
队列通知采用边沿：TX由空变非空、RX由满变为有容量时通知驱动；已排队TX由就绪条件继续推进。
普通RX消费保持底层已有的接收等待，避免逐包取消并重建同一等待。

XHTTP 和 DoH/H3 通过 `quinn-h3-transport` 使用官方 h3/h3-quinn，共享取消安全的请求包装与
非 DATA 帧编码预算；它不创建 socket、查询池或额外业务 body 队列。未完成发送的请求丢弃时 reset，
成功提交 FIN 后不因丢弃发送半而 reset，也不等待逐请求 QUIC ACK。各协议窗口和并发边界见
[XHTTP](xhttp.md) 与 [DNS](tun-icmp-dns.md)。

未显式配置 reuse-settings 的 XHTTP H3 复用既有活动连接，每条最多 4 个逻辑租约；
最后一个租约释放即移出候选池并按既有预算收尾，不缓存空闲连接。显式复用参数及 H1/H2 默认保持各自契约。

`quiche-h3-transport` 为 TrustTunnel/MASQUE 使用官方 quiche 的低层驱动，共享上述数据报适配器，不创建新的 socket。
接收时移动既有队列中的数据报，独占存储直接交给 quiche 原地解密；共享或不可变存储
使用按接收预算延迟分配的复用暂存缓冲。Quinn 的借用接收接口和两端队列上限保持不变。
每个 quiche H3 stream 的已读取 body 最多保留 64 KiB，每次业务写入最多 16 KiB；
只有本地主动请求创建业务状态，未知 DATAGRAM flow 丢弃，已注册 flow 的交付队列最多 64 项。
这些是局部缓存界限，不宣称 QUIC 库内部总内存固定，也不限制活动业务流总数。

QUIC双向可用payload至少1,200字节；endpoint必须显式把QUIC MTU限制在有效预算内。IPv4/IPv6路径MTU分别先扣除28/48字节IP+UDP头，边界和单字节不足均有定向测试。

QUIC owner.stop先取消并等待驱动，再关闭并释放上游；上游close最多1秒。H3 的关闭预算内停止新请求准入并执行关闭交换，XHTTP 和 quiche 物理连接退役还保留有界的传输收尾机会，不承诺逐流远端 ACK。Driver Drop仅为取消/abort兜底，不能作为同步Stop验收。队列容量是单连接局部界限，不是全局QUIC连接准入数。

TUIC 与 Hysteria2 共用这一接点。接收窗口通过官方 Quinn API 固定设置：
每流 max(initial, min(maximum, 4 MiB))，
连接 initial；默认 TUIC 4 / 6.4 MiB，HY2 64 KiB / 4 MiB，不预分配全部信用额度。
DoQ 初始及最小发送 payload 为 1200 字节，接收预算独立保留，允许较大的合法对端包。

TUIC 的独立会话、关联 ID 退役、控制流、分片负载
及交付队列边界见 [TUIC v5](outbounds.md#tuic-v5)。旧池的待建流也持有所有权，
不能在等待 credit 时被当成空闲池回收。TUIC 业务 UDP 队列使用独立观测类别。

## DNS

- 生产运行时从归一化的`dns.cache-max-size`构造缓存，缺省或零值为4,096项。主、bootstrap及已配置的节点/直连解析角色各拥有独立结果容量；A/AAAA类型化结果与原始响应共用每个角色的这份条目数。原始响应另受64项/256KiB预算约束，TUN域名提示独立为256项。
- `ResourceLimits::dns_address_cache_entries`默认256，只是显式低层构造可传入的容量，生产启动不会用它覆盖`dns.cache-max-size`。WireGuard/MASQUE的私有节点resolver通过独立`DnsConfig::default()`构造，当前默认同为4,096项，不继承用户全局缓存容量覆盖；DNS关闭时的系统ECH metadata resolver另固定64项。这些局部容量不构成进程RSS上限。
- 不设置固定的活动请求或活动传输总许可数。
- 相同 key 的 cache miss 使用 singleflight；leader 取消后 follower 重新选举。
- UDP 传输属于单次请求，同一尝试的重发复用当前传输。
- 上游尝试仅在选择 TCP/TLS 或 DoQ 后分配对应的异步状态；普通 UDP 不内嵌未使用的握手状态。装箱不创建额外任务，取消仍直接丢弃该尝试及其拥有的状态。
- TCP、DoT、DoH 按上游身份、endpoint 和 route target 复用；TCP、DoT、HTTP/1.1 一条连接同时只处理一个查询，HTTP/2 和 HTTP/3 每连接最多 32 个并发查询。DNS TLS 不保留恢复票据，复用已认证连接。
- 活动 TCP 不设固定数量上限；空闲连接总数最多 4，同 key 最多 2，空闲超时 30 秒。
- 查询、单次尝试和 UDP 重发期限分别为 5 秒、3 秒和 1 秒。每次查询最多并发 4 个上游，胜出后取消其余尝试；UDP TC 转同一上游 TCP。
- 响应最多扫描 64 条记录，类型化缓存和提示最多保留 16 个唯一 IP。
- 停止取消打开、发送、接收、重试和响应发送，并释放全部传输。

完整语义见 [TUN ICMP 与 DNS](tun-icmp-dns.md)。

IP-only协议接点持有`ResolutionContext`，runtime DNS通过Weak绑定，不形成DNS→dispatcher→connector强引用环。解析继承同次建链绝对期限和runtime取消；同名递归/超过32层解析依赖立即失败，32是单调用依赖深度而非并发请求额度。独立测速的受控bootstrap上下文不创建Running Session或RuntimeDns。

## 代理组与 Controller

- 每个资源代际内的组成员保持有序且不可变；组保存当前选择、健康与策略状态，协议连接仍由节点拥有。健康探测由该资源代际统一调度，最多并发 10 项，停止时取消并等待完成。
- provider 候选整体验证后发布，既有会话保留原资源代际；不再被使用的旧代际停止探测并释放资源。选择与 fake-IP 持久化由各自的存储所有者管理。
- 组数、每组成员数、重复成员数和嵌套深度没有独立固定上限，统一受 8 MiB YAML 输入与 32 MiB 展开计费上限约束；配置期使用 O(V+E) 的迭代 DAG 校验，运行时也以迭代方式解析当前叶节点。
- 节点上游和全部组成员在同一 DAG 中校验；组连接器只持有声明依赖，按逆依赖顺序释放。建链快照只按需记录本次遇到的组，不成为全局缓存。Hysteria2 的已认证连接为后续端口跳跃保留该快照，直到此物理会话退出；它不再读取实时选择，也不延长原建链期限。
- 同组成功选择是线性化的，不同组独立；选择失败不改变状态，也不创建重试或自动 failover 任务。
- 切换不扫描或迁移现有 TCP、UDP、DNS transport，不刷新 DNS cache/singleflight 或 TCP pool；资源仍由原所有者按既有 timeout、EOF、取消和 stop 语义回收。
- Controller 同时最多跟踪 8 个连接任务。请求 header 和 PUT body 各有 5 秒读取期限，PUT body 最大 1 KiB；超时、超限和解析失败只终止当前请求。

完整接口见 [运行时 Controller](controller-api.md)。

## 离线规则 bundle

`rule-providers.*.path-in-bundle` 使用 `dataDir/BundleMRS.7z` 中的精确成员名；
不展开到目录、不预置资产、不对其他 Provider 生效。初始化依次尝试有效缓存、bundle、
原 file/http 来源；缺失或无效 bundle 沿用原来源。有效成员按原格式解析，原始字节与
无 ETag 的本地来源标识原子写入缓存；本地来源不算已完成 HTTP 获取，重启也保留这一语义。

单次初始化按顺序读取各资源，同一读取只有一个单线程解码器。先检查签名与 CRC、
128 KiB header/decoded header、单 encoded-header packed stream（16 MiB）及至多8个 coder，
再让官方 `sevenz-rust2` 读取 metadata。拒绝加密、外置 metadata 与未审核 codec；
支持 COPY、LZMA1/2、Delta 及 x86/ARM/ARM Thumb BCJ。随后检查所选压缩块的单输入链、
4096项文件表、128 MiB压缩输入和256 MiB解码总量；仅保留目标成员，最多64 MiB，
并受 size-limit 进一步约束。solid前置成员流式丢弃，目标读至EOF后才接受校验结果。

字典、输出和保守metadata计费共享96 MiB准入估计；该估计不包括allocator、解析后的规则
及整个进程其他资源，不能当RSS上界。检查在官方 decoder分配之前执行，metadata中的
计数由受限header长度约束。超过局部边界的bundle使用原来源，不静默截断成员。
读取与解码检查取消、30秒局部期限、累计256 MiB来源读取和65536次I/O操作。
使用同一个打开的文件句柄，异步调用者等待阻塞任务完成，不以丢弃JoinHandle替代停止。

## Provider 名称表达式

普通筛选表达式继续使用线性时间的 `regex`。必要的 lookaround/backreference 使用
`fancy-regex`，限制复杂源码 4 KiB、AST 512 节点/32 层、有限重复数 4096、委托编译和
DFA 缓存各 512 KiB；不接受递归、条件式和控制动词。每次复杂匹配最多 10,000 回溯，
输入名称最多 4 KiB。一次候选共享最多 10,000 次复杂匹配/改名匹配和 100 ms 执行窗口；
改名输出最多 64 KiB，后续表达式继续计费。单次库调用不能中途抢占，调用间检查取消。
编译、预算、运行错误与取消均使候选失败，保留当前资源和 HTTP 缓存，不静默漏选节点。
这些边界仅用于名称表达式，不改变 GeoData/DOMAIN-REGEX 或业务连接准入。

## GeoData

- 所有平台完整加载被引用分类的所选记录，不设记录条数硬上限或截断；GeoIP 与 GeoSite 没有优先额度分配。
- 同种基础 code 按 ASCII 大小写归一，业务规则与 DNS policy 共用分类和值存储。属性取交集；正反选择器共享匹配器，多种属性筛选共享值及已编译正则，不重复解码同一分类。未引用分类不构建匹配器。
- 各平台均不设独立 GeoData 分类、引用、文件大小、累计源码/值字节或总加载内存预算；DNS GeoSite policy 也不保留独立项数/引用数上限。
- DAT Loader 只解析被引用的分类，其他分类按 wire 长度跳过。默认国家 MMDB 与 DAT 二选一；
  Meta 国家库在完整校验后优先将配置引用的分类编为紧凑 CIDR，并释放原始文件缓冲；
  投影不更省或不适合时保留原 Reader。其他国家 schema 与 ASN 保留拥有字节的 Reader，
  按索引借用查询。各路径均不建立逐地址缓存，不截断记录或增加 GeoData 内存准入。
- Domain/Full 匹配器使用紧凑连续存储，运行期查找不分配。Regex 使用共享的
  `regex::bytes::Regex` 并关闭 Unicode 匹配模式；库管理编译状态和搜索缓存，搜索可能
  分配 scratch、增长缓存或竞争共享缓存，不能将 Domain/Full 的无分配性质扩展到 Regex。
- 分类按 code 二分定位；TUN UDP 五元组固定规则 action，不保留 GeoData 快照
  或域名。没有全局目的缓存或旧快照引用；各目标独立空闲回收。
  活动流的规则数据更新在新流生效；DNS 查询、域名目标和非 TUN 路径不受此固定策略影响。
- Vole 不显式构建 dense DFA，也不配置 NFA、DFA 或 determinization 额度；保留正则库
  默认的编译大小、嵌套和搜索缓存保护。不新增正则记录数、累计源码或总内存预算。
  容量账本仅计 Vole 自有容器的可见容量，排除正则内部状态、动态 scratch 和缓存；
  未计入不代表零，账本不能充当进程峰值上界。局部库保护同样不是所有 Regex 的总量保证。
- 格式、整数表示、值与 Regex 语法校验和可恢复分配错误仍失败关闭。属性筛选排除的记录不进入匹配器；有效分类的空筛选仍可反选，缺失/不可用分类不会反选为全匹配。
- 首次缺失或无效资产使对应种类不可用，实例以 degraded 状态继续准备/启动；两种资源可用性独立。
  更新流式落盘、文件结构与 staging 检查期间保留旧代；构建新代前先发布空匹配器，
  等待最后旧读者退出且存储析构结束，避免两代 matcher 同时存活。新请求只跳过
  不可用 Geo 规则，普通选路和 DNS 回落不变，不切全局代理。更新仅构建一次候选，
  磁盘和状态提交后直接发布，不重复加载，也不跨代复用分类存储。
- 管理操作串行，ArcSwap 选路读不等待管理锁。排空期限采用默认下载超时值 90 秒，
  等待最多每 25 ms 检查取消；后台状态观测、begin、commit 和 304 恢复使用受等待的
  阻塞任务。Stop 取消后等待任务完成；CPU 加载不能中途强制取消，但不会发布取消候选。
  排空响应间隔不等于整体 Stop 时限，释放存储也不保证 allocator 立即归还 RSS。
- 卸载后的加载失败只使对应种类不可用，健康另一类仍发布；不恢复旧整体快照。
  卸载前的下载/结构失败保留当前匹配器，失败更新均保留旧磁盘资产并按现有调度重试。
  国家 MMDB 与 ASN 先借用候选校验，再排空旧快照，构建投影或移动候选字节，失败保留/恢复旧代。
  304 在 matcher 已可用时只调度，不可用时重载本地资产。既有 TCP 选路与 TUN UDP
  固定 action 不回溯；没有新增公开 API、业务数量配额或 GeoData 内存预算。

GeoData 行为见 [规则与资产](geodata.md)。性能与压力测试由独立容器测试工具执行，
公开结果见 [benchmark](benchmark.md)，原始记录保留在对应运行中。

## 统一内存策略

所有平台与构建共享上述队列、缓冲、缓存、QUIC 窗口与线程策略。
CLI 和 FFI 使用同一 Invoke 启动路径，无独立内存编译开关、YAML 字段或 Invoke 参数。

TUN 在生命周期边界及运行期间每 30 秒尽力记录进程内存和限频阈值事件。
Apple 使用 `TASK_VM_INFO` 的当前与生命周期峰值 physical footprint；Linux 使用
procfs 的 VmRSS/VmHWM。其他平台的采样不可用时只报告一次诊断，不伪造读数。

GNU/Linux 的 TUN 在工作线程启动前，进程内一次性尝试设置 glibc arena 为 1、
mmap 阈值为 32 KiB；显式 `MALLOC_ARENA_MAX`、`MALLOC_MMAP_THRESHOLD_` 或
`GLIBC_TUNABLES` 覆盖优先。这是进程级 allocator 设置，可能影响同进程中的宿主分配。
Stop 的同步释放屏障完成后，Apple 通过 malloc zone、GNU/Linux 通过 `malloc_trim`
尽力归还空闲内存；不支持该接口的平台保留原 allocator 行为。

- 未使用 TUN 时不配置 allocator、不启动周期采样或 Stop 回收。
- 采样失败只记录一次警告，不写入 `lastError`。
- 43/45 MiB 阈值分别对应 1 Gbps 与 3 Gbps 的预算，仅作诊断；Core 不推断负载档位，最终由 benchmark 按实际负载判定。这些观测不改变 prepare、start、running、stop 或 panic recovery。
- Stop 后的 allocator 回收只执行一次且尽力而为，不保证立即降低进程内存。

内存预算与真实设备范围见[验收边界](acceptance.md)。

## 日志与观测

运行时可记录 TCP、半开连接、UDP、握手和 DNS 的当前值/峰值，以及缓存命中、singleflight、队列丢弃、连接池回收、非法包和 ICMP 统计。

独立 netstack 的 `udp_drops` 只记录通用 UDP endpoint 的入站丢弃；生产 TUN 使用
TCP-only netstack，因此该值为零不代表 UDP 无丢包。运行时记录
`udp_association_queue_drops` 和 `udp_response_queue_drops`，保留两者合计的
`udp_queue_drops`。普通响应暂持等待容量不计丢包，取消或错误后实际丢弃才计数；
TCP/ICMP ingress Full 记录 `packet_queue_drops`。这些计数
不包含物理 socket、内核 TUN 或对端设施中的丢包。

日志必须有界且脱敏，不记录目标、DNS question、UUID、凭据、密钥、负载或完整配置。

仅`cfg(test)`/`interop-test`启用的`ResourceProbe`按测试作用域记录RAII当前值/峰值；子任务显式继承作用域，不使用进程全局reset或更换生产allocator。当前接入物理TCP/UDP、共享流/QUIC驱动与session、数据报association、DNS池/等待者及既有运行时活动guard。Hysteria2 的待完成分片通过 `Reassembly` 登记，交付后释放 Packet ID 和重组资源；零计数必须与实际执行过的重组路径一起解释。


## 变更要求

新增全局 admission、可配置容量或长期缓存前，必须：

1. 证明现有局部边界不足；
2. 定义所有者、上限、取消和停止语义；
3. 增加边界值和越界测试；
4. 记录主机和对应物理平台证据。

没有测量证据时不增加新的资源控制层。实际验证范围见 [验收矩阵](acceptance.md)。
