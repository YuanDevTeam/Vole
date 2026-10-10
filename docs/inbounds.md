# HTTP 与 SOCKS5 混合入站

HTTP 与 SOCKS5 共用一个混合入口，并和 TUN 共用 Dispatcher、规则、DNS、动态策略组及出站图。
字段全集见[配置协议](config.yaml)，Controller 另见[接口](controller-api.md)。

## 监听与认证

- `mixed-port` 省略或 0 关闭，启用时为 1–65535；关闭混合入口和 TUN 的配置仍可启动。
  同一 TCP 端口接入 HTTP 转发、CONNECT、Upgrade 和 SOCKS5 CONNECT、UDP ASSOCIATE。
  SOCKS5 UDP 随入口启用并绑定同地址、同端口，不提供独立入站 UDP 开关。
- 顶层 `port`、`socks-port`、`udp` 和 `listeners` 均拒绝，不迁移或忽略旧字段。
  代理节点的 `port` 和 `udp` 保留各自的出站含义，不控制混合入站。
- 启用混合入口要求同时编译 `inbound-http` 与 `inbound-socks5`；缺少任一 feature
  均无法启动入口。两个协议模块仍可分别编译，但单独启用其 feature 不能提供混合入口。
- `allow-lan: false` 绑定 IPv4 回环，true 绑定通配地址。`ipv6: true` 增加独立
  IPv6-only 回环/通配 socket。仅系统明确不支持地址族时可省略 IPv6，其余绑定错误
  整体回滚。取得 Controller 和全部业务 socket 后才启动接收任务。
- `bind-address` 默认为 `*`；`allow-lan: true` 时可指定单个 IPv4/IPv6 地址，false 仍绑定回环。
  `localhost` 始终使用回环策略，并随 `ipv6` 控制 IPv6 回环 socket。
  `lan-allowed-ips` 默认允许全部 IPv4/IPv6，`lan-disallowed-ips` 的拒绝规则优先。
  两者作用于 TCP 来源；SOCKS5 UDP 必须属于已获准的 TCP 关联。
  `skip-auth-prefixes` 只跳过匹配来源的认证，不跳过来源访问控制。
- `allow-lan` 与 `authentication` 独立；通配绑定不强制认证。
  `authentication` 省略、null 或空列表时，HTTP/SOCKS5 在任何绑定地址均免认证；
  非空接受多个 `user:password`，相同用户名以最后一项为准，
  按第一个冒号拆分，不 trim，允许空用户名或密码。配置和 HTTP 不套用 SOCKS5 的
  长度限制；HTTP 凭据受整个 32 KiB 请求头预算约束，SOCKS5 各字段仍使用一字节 wire 长度。
  配置凭据后 HTTP/SOCKS5 均校验凭据；混合入口关闭时允许保留合法的共享和认证配置。
- Basic / SOCKS 用户密码没有链路加密，只适合可信网络。Controller 按 external-controller 独立监听，
  使用自己的可选 Bearer 认证，不随共享开关改变地址或认证。
- 不设置全局业务连接/关联准入数。Stop 取消并等待全部连接、relay 和接收任务，
  返回后端口可重新绑定。
- 接收的 TCP 连接启用 `TCP_NODELAY`，小包应答不等待 Nagle 聚合。

## 选路元数据

`IN-TYPE` 使用实际入口类型：普通 HTTP/Upgrade 为 HTTP，CONNECT 为 HTTPS，
SOCKS5 为 SOCKS5；HTTPS 类型只表示 CONNECT，不检查目标 TLS。`IN-PORT` 读取
接收连接或授权 UDP socket 的真实本地端口。

`IN-USER` 与 load-balance 的 `hash-key: in-user` 只使用验证成功的配置用户名。
HTTP 每个请求重新验证，SOCKS TCP 和 UDP 授权关联保留握手身份。无认证或
`skip-auth-prefixes` 旁路时身份为空，即使请求声称一个 Proxy-Authorization 用户。
身份随请求/关联保存，只持有用户名，不保存密码、请求头或完整配置代际；Debug 不输出用户名。
业务路由和 dialer-proxy 共用该身份，内部 DNS、资源下载及主动测速没有入口用户。

Mihomo 当前实现不把 SOCKS TCP 身份传给独立 UDP 接收；Vole 的授权 UDP 保留
真实握手身份。Mihomo HTTP 在无认证时也可能记录请求声称的用户，Vole 保持为空。

## HTTP

每个请求独立认证，缺失、错误、重复或非法 Proxy-Authorization 返回 407 并关闭，
不建立上游；前一个请求的授权不沿用到下一请求。

### 普通转发

HTTP/1.0 和 HTTP/1.1 使用绝对 `http://host[:port]/path?query` URI。每个请求重新
确定目标、选路和建链，转发为 origin-form 并重建 Host，上游不跨请求复用。
客户端可以 Keep-Alive 或顺序预发送；固定缓冲保存预读，只有上传完成且响应有明确
边界才处理下一请求。不会把旧目标连接用于下一请求。

- Content-Length 精确转发；没有正文长度的普通请求视为空正文。
- chunked 按块解码并重编码；合法扩展不透传，合法 trailer 保留。
- HEAD/1xx/204/304 无正文；1xx/204 携带正文定界字段失败关闭，HEAD/304 可保留表示长度。
- 转发 100 Continue 等临时响应；上传和响应读取并行。提前最终响应会终止上传、
  转发响应并关闭客户端，不把余下正文误作新请求。
- 无长度响应由 EOF 定界并关闭；HTTP/1.0 客户端接收 chunked 响应时去块后关闭。
- 重复 Content-Length、CL/TE 并存、歧义长度、非法控制字符/分块、截断或超限均失败关闭。
  认证、内部诊断、Connection 指名及逐跳字段不泄漏给目标；trailer 不能携带认证、
  路由、定界或内部字段。

定界遵循 RFC 9112 §6.3，逐跳字段遵循 RFC 9110 §7.6.1；歧义输入严格拒绝。

### 隧道

CONNECT 通常在上游成功后返回 200，保留头后的预读数据。匹配 TCP 嗅探策略时先返回 200，
再读取有界业务前缀并按嗅探结果建链；此后建链失败直接关闭隧道。Upgrade 只接受无正文请求；
合法 101、Connection/Upgrade 一致且选中请求协议时才切隧道，保留双方预读和 TCP
半关闭。非 101 按普通响应处理，非法切换返回 502。

内部测速诊断只在认证通过、监听和客户端均为回环且 CONNECT 显式请求时返回。
无认证本机入口和共享入口不返回内部详情。

### 局部上限

头 32 KiB/100 字段、读头/建链 10 秒；每方向预读/复制 8 KiB。chunk 行 1 KiB，
trailer 8 KiB/100 字段，每个最终响应前最多 16 个临时响应。正文逐次读写空闲期限
30 秒；响应开始后独立计算读头总期限，上传结束后等待响应最多 10 秒。正文长度不
决定分配大小，Stop 覆盖认证、建链、正文及隧道。

## SOCKS5

仅支持 RFC 1928/1929 的 SOCKS5 CONNECT、UDP ASSOCIATE 和用户名密码协商。
不降级绕过已配置认证。精确读取握手并保留 CONNECT 后业务字节；通常在上游成功后回复成功。匹配 TCP 嗅探策略
时先确认 CONNECT，取得业务前缀后建链，失败关闭已确认的连接。
目标保留 IPv4、IPv6 或域名交给 Dispatcher，入站不提前解析。TCP 每方向复制 4 KiB，
保留半关闭。

### UDP 授权

- 一个有效 TCP 控制连接拥有一个关联。未授权 UDP 不创建状态或上游。
- 请求源 IP 必须为未指定地址或 TCP peer IP；回复使用 TCP 连接实际本地地址和配置端口，
  不返回通配 relay 地址。
- 授权键包含 TCP peer IP、从 TCP peer 取得的 IPv6 scope 和 UDP 源端口。
  端口 0 在首个合法且成功入队的数据报学习；同 IP/scope 最多一个待学习关联。
  明确端口可并存但不能重复授权，不同 scope 的链路本地地址互不串包。
- 一关联可访问多目标，分别选路；回包保留出站提供的实际远端地址。
- 非零保留位、分片、非法地址、零目标端口和超长包丢弃，不学习端口或续期。
- TCP EOF/错误/Stop/过期撤销授权；旧任务不能删除新代次关联或发送旧回包。
  这比 Mihomo 任意 UDP 接收创建状态的策略严格。

协商 10 秒；UDP 建链/单次发送/回包和 TCP 建链 15 秒。每关联队列 16 包，满时丢当前包；
全局接收不等待慢建链。空闲 30 秒、每 10 秒检查，仅成功入队/发送的合法流量续期。
wire 最大 65,507 字节，额外 sentinel 识别截断，自有 UDP socket 请求 65,508 字节
发送缓冲；回包负载保守扣最大 262 字节头为 65,245 字节，嵌套出站继续扣预算。
TUN 使用独立 MTU；SOCKS5 数据不计入 Controller 的 TUN 流量。

[验收边界](acceptance.md)区分容器双栈与真实 LAN/物理 IPv6，不能相互替代。
