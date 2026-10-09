# VLESS 出站

`outbound-vless` 使用共享 Dialer、上游图及 TLS/REALITY/JLS，不创建独立 socket 或系统 DNS。
本文定义选定能力集，不承诺上游所有扩展；字段与版本以 [config.yaml](config.yaml) 为准。

## 配置与传输

`type: vless`，`server`、非零 `port` 和标准格式 `uuid` 必填。`udp` 默认 false；`network` 默认 `tcp`，`tls` 默认 false。`encryption` 省略、空或 `none` 关闭该层；其他值见下文。`flow` 省略、空或 `xtls-rprx-vision`。未知字段、null、错型或不匹配的传输选项失败，不隐式迁移配置。

- TCP/WS/gRPC/HTTP 首包伪装/legacy H2 可明文或标准 TLS。TLS 支持 1.2/1.3，TCP 默认不发送 ALPN，WS 默认 `[http/1.1]`，gRPC/H2 默认 `[h2]`。有序 ALPN 保留且必须包含传输要求值；标准 TLS 检查协商结果。`servername` 优先显式值、WS Host 去端口、server；不会改变拨号地址。TLS 关闭时禁止安全选项。
- 标准 TLS 支持 `skip-cert-verify`、SHA-256 `fingerprint`、独立 `name-cert-verify`；沿用共享证书验证器的叶 pin / 非叶信任锚优先级。`certificate` / `private-key` 是配对的内联 PEM，解析或密钥不匹配在 IO 前失败，禁止文件路径。REALITY 不能混用这些标准证书策略。
- `client-fingerprint` 使用 [TLS 指纹](tls-client-fingerprint.md)的七值/四模板，适用于 TCP 上的标准 TLS/REALITY（含 Vision 和 XHTTP H1/H2），与证书 pin 独立；`none` / 空串关闭，H3 拒绝已启用的 profile。
- WS 的 ED 支持默认头、自定义头或路径（上限 2048 字节）。`v2ray-http-upgrade` 开启升级后裸流；`v2ray-http-upgrade-fast-open` 必须与前者一起启用，只允许默认 ED 头。fast-open 提前发协议首包但仍等待合法 101，拒绝不返回连接成功。
- gRPC 接入 `grpc-user-agent`（默认 `grpc-go/1.36.0`）、非负秒数 `ping-interval`（0 不主动 PING），以及三项池阈值。空闲连接总是复用；max-connections>0 时按连接上限/min-streams 扩容，否则按 max-streams 复用阈值扩容。三项全零归一 max-connections=1；显式正 max-connections 与正 max-streams 互斥。阈值不是硬流数上限。物理连接归节点所有，关闭逻辑流不会杀死兄弟流；复用不重选上游组。
- gRPC 不新增业务流/建链数量额度；每个物理连接一个自有驱动，每个等待调用只保留自身 future、取消与原期限，不派生队列任务。每节点最多保留 4 条空闲连接，多余空闲连接退役且不影响活动流。空闲 PING 等待 ACK 最多 15 秒，节点 Stop 取消并 join 所有驱动。
- `network: xhttp` 支持 H1/H2 明文、TLS1.3 或 REALITY，H3 仅标准 TLS1.3。请求字段、独立下载腿、池与版本选择见 [XHTTP](xhttp.md)。H3 的物理 UDP 仍由原 Dialer/上游图创建。
- `smux` 以独立的 h2mux/smux v1/yamux 承载逻辑 TCP/UDP；不是 XUDP。only-tcp、调度及关闭边界见 [XHTTP 与 sing-mux](xhttp.md)。
- Vision 仅允许 `network: tcp`，要求 TLS 1.3/REALITY 或 Encryption；UDP 仅 XUDP。启用 Encryption 后外层 TLS 可省略，存在时仍保持独立认证。配置阶段拒绝 WS/gRPC/HTTP/H2/XHTTP、raw/packetaddr、sing-mux 与 Vision 的组合，包括未启用业务 UDP 但显式选错编码。ECH 和附加安全封装仍拒绝。
- Vision 请求不自动降级；对端用户不支持 Vision 时业务失败。Mihomo 服务端允许为 Vision 用户显式配置空 flow，这属于普通 VLESS 模式，不是错误 flow 的拒绝用例。

## REALITY

`reality-opts.support-x25519mlkem768` 为非 null 布尔值，默认 false。true 强制真实混合
TLS 密钥交换，服务端选择经典组时失败；可用于主连接和 XHTTP 独立下载连接。
仅 `chrome` 或未命名 profile 兼容，模板及下载继承约束见 [TLS 指纹](tls-client-fingerprint.md)。

## JLS

共享凭据身份认证仍使用完整原生 TLS 1.3，不是 skip 或失败后裸流回退。

### 配置

- 对象出现即启用，两项必须都是非空字符串，各 1–65,535 个 UTF-8 字节，不 trim。
  主连接不接受空对象；未知字段、null、错型、缺项及超限在 IO 前拒绝。
- 必须 `tls: true`。同一腿不能混用 REALITY、标准证书策略或客户端证书；
  ECH、其他安全封装、Vision 和 HTTP/3 也不属于此组合。
- `servername`、有序 ALPN、传输必需 ALPN 与已支持的七值/四模板
  `client-fingerprint` 沿用共享配置，不增加全局默认或别名。
- `download-settings.jls-opts` 缺省继承整个身份；非空对象必须完整替换两项，
  `{}` 清除，不能按叶继承另一个身份的密码。其他下载字段独立覆盖。
- 切换下载安全模式须显式清除旧身份及冲突证书策略；设置新对象不会自动删除旧对象。
  两腿仍必须汇入同一个原生 XHTTP handler 的会话表。

### 认证与所有权

锁定的自有 boring JLS hook 认证实际 ClientHello/ServerHello，由原生 TLS
完成 transcript、CertificateVerify、Finished 和记录保护。共享凭据替代 WebPKI
身份，但不会跳过握手签名或 Finished。普通 TLS 证书、错误凭据、篡改握手、
TLS 1.2 和 HRR 都不能满足 JLS；失败不发伪装 HTTP 探测、不重发业务、不回退 DIRECT。
模板保留 TLS 1.2 的声明下限，实际成功协商始终必须 TLS 1.3。

每条腿的连接器身份不可变；不启用 TLS 恢复、PSK 或 early data。自有凭据副本
使用清零容器，原生临时材料按握手/失败清理；不宣称擦除所有配置 String 副本。
连接器只包装既有 Dialer/上游交付的受控 IO，不创建 resolver、socket、后台任务
或额外连接池。建链期限、取消、ALPN 检查和同步 Stop 继承现有运行时。

JLS 继续承载 TLS 记录，CloseWrite 沿用共享 TLS 有界关闭；XHTTP 保持整流关闭。
Encryption 位于外层传输内，身份彼此独立，不能由单层成功推断组合验收。

## 静态 ECH

仅显式静态 ECHConfigList；保护内层 ClientHello 名称，不隐藏 IP、外层名称或流量形态。
无动态 HTTPS RR/bootstrap、公共 DNS 后备或自动更新。

### 配置

```yaml
ech-opts:
  enable: true
  config: "<服务端提供的标准 Base64 ECHConfigList>"
```

- 仅标准 TLS，内层 `servername` 必须是 DNS 名，实际只协商 TLS 1.3。
  同腿不能与 REALITY、JLS 或 Vision 混用；可与 VLESS Encryption、证书策略、
  mTLS 和既有传输组合。命名指纹仍只用于 TCP TLS，H3 仍拒绝命名指纹。
- `enable` 默认 false。启用必须同时提供非空 `config`；不查询 HTTPS RR，
  不接收 `query-server-name`，没有公共 DNS 后备或自动更新配置。
- `config` 是标准带填充 Base64，不是 URL、文件路径或 PEM。解码后的完整
  ECHConfigList 最多 65,537 字节，仍受整份配置 8 MiB 上限限制。
- 支持 ECH 版本 `0xfe0d`、X25519/HKDF-SHA256，以及 AES-128-GCM、
  AES-256-GCM、ChaCha20-Poly1305。预检选取第一个双方后端均支持的条目，
  保留其原始编码；未知版本或不兼容条目可跳过，无兼容条目、畸形长度、非法
  public_name 或不支持的必需扩展在 IO 前失败。不能依赖 BoringSSL 静默忽略。
- `{}` / `{enable: false}` 清除 ECH。关闭时不允许携带非空 config，以免
  用户认为给出的隐私配置已经生效。null、未知字段、错型均拒绝；诊断不回显配置。

`xhttp-opts.download-settings.ech-opts` 缺省继承整个主腿对象；出现时整对象替换，
不逐字段合并，替换密钥须同时写 `enable: true`。显式 `{}` 可仅清除下载腿 ECH。
切换到 REALITY/JLS/明文必须显式清除继承的 ECH，以及其他冲突的证书身份。
两腿仍须汇聚到同一原生 XHTTP handler；各自独立建立和认证外层安全连接。

### 后端与失败边界

无指纹 TCP TLS 与 H3 使用官方 rustls + ring，通过公开 HPKE trait 接入官方
`hpke`；命名指纹使用锁定的自有 boring fork 既有 ECH 接口。本次不修改
第三方 TLS 实现，不恢复 rustls fork，也不扩展 Shadowsocks 的 AWS-LC 例外。

两后端都必须真正接受 ECH 才交出业务连接。rustls QUIC 的 ECH 拒绝作为原生
握手错误传播，H3 在握手完成前不发送 HTTP 请求；TCP 另检查 accepted 状态。
不把 GREASE 当真实 ECH，不自动采用 retry config，不重拨、不回放业务，也不
降级为未加密 ClientHello 的成功连接。错误或轮换后的旧密钥需要宿主更新配置。

静态 ECH 连接禁用 TLS 会话恢复和 0-RTT；XHTTP/gRPC 的已认证物理连接仍可在
原节点内复用。不同节点、主/下载腿、配置替换和后续运行实例不会共享 TLS 票据。
本层只包装调用方提供的 IO，不创建 resolver、socket、后台任务或全局缓存。

正常 ECH 接受后沿用内层证书名称、pin 和 mTLS 策略。拒绝分支不返回业务成功，
也不能发送客户端证书。boring 使用原生 outer-name override，按外层名称和默认
WebPKI 验证拒绝连接，不沿用内层 pin/skip。rustls 的公共 verifier 没有独立的
ECH-rejection 回调：沿用配置的证书策略后仍由原生状态机强制失败；不获取或使用
retry config。该拒绝证书路径不宣称与 Mihomo 完全相同，但不放宽业务成功门槛。

## Encryption

`mlkem768x25519plus.{native,xorpub,random}.{1rtt,0rtt}.<key>[.<key>…][.<padding>…]`。
key 为无填充 URL-safe Base64，解码后 32 字节 X25519 或 1184 字节 ML-KEM-768
公开密钥，可组成有序链；非法 ML-KEM 编码在 IO 前拒绝，X25519 低阶共享密钥
在握手失败关闭。最多 16 个 key、128 个 padding 三元组和 65,536 字节配置串。

padding 采用 Mihomo 的 `概率-下界-上界` 三元组，交替表示字节长度、毫秒间隔。
首组概率至少 100、两端至少 35；长度上界累计不超过 65,553。
概率按 Mihomo 的包含边界比较，区间上界排除；相等/倒序端点允许。
缺省为 `100-111-1111.75-0-111.50-0-3333`，等待受原建链期限及取消控制。

所有密钥交换、AEAD 和 CTR 使用既有官方原语，AES-256-GCM / ChaCha20-Poly1305
根据 CPU 选择，不增加用户算法选项。每节点一个恢复票据；`1rtt` 不复用，
`0rtt` 在票据有效时恢复，过期改为新握手。错误票据/认证失败不会自动重发业务。
节点缓存互相隔离，旧连接失败不清除新一代票据，Stop 清空缓存且禁止再次插入。

该层位于外层传输内、VLESS 请求头外；WS/HTTPUpgrade/HTTP 的 initial data 是
Encryption 握手字节，不能提前发送明文 VLESS 请求头。XHTTP 主/下载腿汇聚为
一条逻辑流后只执行一次 Encryption。普通 Encryption 关闭与 Mihomo CommonConn
一致，flush 后关闭整条逻辑流，不承诺半关闭尾包；不关闭复用池中的兄弟流。

Vision 在独立的 Encryption 记录边界切换：先排空已认证明文，再绕过 AEAD；
已有外层 TLS 保留，random 模式保留记录头 CTR，不重置计数器。
进入 direct 后，native/xorpub 继承底层 CloseWrite 并保留读取方向；random 对齐
Mihomo 不可替换的 XorConn，仍整流关闭。未进入 direct 时三种外观均整流关闭。
验收只覆盖实际列举的组合，不由单层成功推断整个组合或设备通过。

## Vision

Vision padding、TLS 记录过滤和读写切换状态独立管理。内层非 TLS / TLS 1.2 只结束 padding，保持外层加密；识别支持的内层 TLS 1.3 协商后，分别发送/接收 direct 标记才切到裸流。每次发送最多暂存 8 KiB 一帧，接收逐段处理 u16 长度，不按声明长度无限分配。非法 UUID/命令或截断关闭 IO；取消读取保留帧进度。

外层 TLS 使用公开 rustls 或 boring 接口及同一记录边界适配器；每次最多读一个 TLS 记录，不在识别切换标记前吞入后续裸流。切换读取前排空已解密明文，切换写入前 flush 外层密文；Vole 不访问 TLS 私有内存布局。direct 关闭不向裸流插入外层 close-notify；未切换时保留共享 TLS 的有界关闭语义。

## UDP

`packet-encoding` 默认 **xudp**，与既有 Vole 行为一致：

| 配置 | 线上语义 | 目标 |
| --- | --- | --- |
| 省略 / `xudp` | VLESS CommandMux + 共享 XUDP 帧 | 每包携带 IP / 域名 |
| `none` | VLESS CommandUDP + 两字节长度 | 固定首包目标，后续换目标失败 |
| `packetaddr` / `packet` | CommandUDP 到原生约定地址，长度帧内再带地址 | IP-only，域名经受控 ResolutionContext 解析 |

`none` 是 Vole 的显式 raw 拼写，不是对 Mihomo 同名字段的兼容承诺。原生约定地址不做本地 DNS。UDP 443 不额外过滤。

raw/packetaddr 每关联只拥有一个已建流，首次发送前已固定物理上游选择和建链期限；等待首包不会重新选择组或重启期限。packetaddr 不调用系统 resolver：运行期使用本 Running Session DNS，独立测速使用受控 bootstrap。

收发预算独立与调用方预算取交集。raw/XUDP payload 受 u16 上限约束，packetaddr 另扣 IPv4 7 / IPv6 19 字节地址头（未解析域名按较大开销预检）。raw/packetaddr 接收 wire 最多 65,537 字节，逐段读取，合法超接收预算的整包丢弃。对端可能有更小容量，原生夹具预算不能冒充生产协议上限。

部分发送取消立即关闭 IO，不允许接着发送半帧；接收取消保留帧进度。非法帧或响应头关闭关联，不切换编码、不回退 DIRECT。显式 close 后不能恢复收发。

## 关闭和期限

VLESS 响应头允许延迟到业务响应前；TCP 不等待它才允许发送请求。读取、首次响应和传输握手共用原建链期限，错误或超时释放 IO。UUID 和业务目标不进入 Debug/诊断。

普通 TCP/TLS 按底层 CloseWrite 语义工作；HTTP 首包伪装没有 Mihomo CloseWrite，shutdown 释放整个逻辑流并唤醒读侧。gRPC/H2 结束当前逻辑流，gRPC 的兄弟流与节点池不受影响。XHTTP 上传 EOF/shutdown 关闭整条逻辑连接，包括下载腿；需要完整响应时在关闭前读完。验收分别检查正常完整性和对齐 Mihomo 的关闭行为，不要求所有传输半关闭后都收到尾包。

## 验证边界

所有服务端、原站、DNS 和对照入口遵守[隔离规则](testing-isolation.md)。
ignored 未执行不计通过；精确组合与源/对端身份在当次报告记录，不拼接旧成绩。
HTTPUpgrade/fast-open 与 sing-mux 的未列举组合不从单层结果推导。

静态 ECH 的 H3 使用 Xray，packetaddr/sing-mux 使用明确标注的 XHTTP → Mihomo 解码。
HTTP/H2/扩展 WS 可用 Xray TLS 网关 → V2Ray transport；需 UDP/Encryption 时另由
Mihomo 解码。网关使用官方 XRAY_BUF_SPLICE=disable，避免下行 raw splice 绕过 TLS；
不代表 V2Ray 直接支持 ECH。无指纹 JLS/gRPC 及 Safari ECH/gRPC 的官方对照缺口采用
明确标注的 Chrome 关闭参照；Vole 原配置的数据面单独验证，不声称同配置差分。
VLESS 不接受动态 ECH、ShadowTLS 或 Restls 配置；ShadowTLS v3 仅用于 SS2022 插件。

WS + REALITY（普通 WS、HTTPUpgrade、fast-open）的数据及认证使用真实 Mihomo listener；关闭验证采用明确标注的分层参照。当前 Mihomo WS 客户端分支未接入 REALITY，不能作为同组合对照，因此使用标准 TLS 的同种传输客户端关闭基线，并独立验证 REALITY。不得将该结果写成 Mihomo WS + REALITY 客户端互通或同组合差分通过。
