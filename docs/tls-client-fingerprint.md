# TLS 证书与客户端指纹

两个字段相互独立：

| 字段 | 含义 | 接受值 |
| --- | --- | --- |
| `fingerprint` | 服务端证书 DER 的 SHA-256 pin | 64 个十六进制字符，可带冒号 |
| `client-fingerprint` | 客户端 ClientHello 的命名模板 | 下列十值；空串也关闭 |

| 公开值 | 实际模板 |
| --- | --- |
| `none` | 关闭命名指纹，不关闭 TLS 或 REALITY 认证 |
| `chrome` | Chrome133 |
| `firefox` | Firefox120 |
| `safari` | Safari16.0 |
| `ios` | iOS14 |
| `android` | Android11 OkHttp，TLS1.2 |
| `edge` | Edge85 |
| `360` | 360 Browser7.5 的已实现能力子集，TLS1.2；YAML 中写为字符串 |
| `qq` | QQ11.1 |
| `random` | 进程首次按 Chrome133/Safari16/iOS14/Firefox120 = 6:3:2:1 选中一个模板 |

节点省略时关闭，显式启用推荐 `chrome`；这是节点级选项，无全局默认。
大小写敏感，未知名称、`null`、错型全部拒绝；不接受带版本号的名称、
其它未列出名称、废弃的 `randomized` 或 PSK/PQ 专用名称。短名只随显式依赖升级和验收变更，不随 OS 自动选择。
`random` 仅共享不可变模板选择，后续连接、配置替换及 Stop/Start 不重抽，不共享 TLS 会话。
兼容约束按实际选中模板检查，不能通过 random 绕过 TLS 版本或 H3 限制。

## 适用范围

AnyTLS、Trojan、VMess、VLESS 的普通 TLS 和已支持的 REALITY/JLS/ShadowTLS 身份复用共享连接器；
TrustTunnel H2 保持标准 TLS。各协议可用身份与传输范围见 [出站](outbounds.md#流式安全身份)。
TCP、WS、gRPC、HTTP 首包伪装、legacy H2、Vision、XHTTP H1/H2 仍遵守各自的协议约束。
关闭 TLS 时不能携带该字段。SS2022 + ShadowTLS v3/JLS 复用上述模板，作用于插件握手；两种身份均强制 TLS1.3，
未命名握手也由 boring 执行。SOCKS5 和裸 SS 不接入 TLS 指纹。

XHTTP `download-settings.client-fingerprint` 缺省继承主腿，显式名称覆盖，`none` / 空串清除。
下载腿即使与主腿使用同一服务器，也拥有独立的 TLS 策略、身份和缓存。
切换到明文或 H3 前必须显式清除继承的非空 profile；H3 不支持此模板，不回退 H2。

```yaml
type: vless
tls: true
client-fingerprint: chrome
# fingerprint: <certificate SHA-256> # 与 ClientHello 模板独立
```

## 后端与认证

- 默认验证公开信任链、名称及有效期。叶证书 pin 匹配时以叶证书为显式信任依据，
  不再要求公共根、名称或有效期；匹配非叶证书时将其作为信任锚，仍验证叶链、名称和有效期。
  skip 只跳过常规验证，不能覆盖不匹配的 pin；所有策略仍验证握手签名。
- 未启用指纹的流 TLS，以及 HY2/TUIC/DoQ/XHTTP H3/DoH H3 的 Quinn QUIC，使用官方 rustls + ring。
  TrustTunnel/MASQUE 的 H3 使用官方 quiche 与同一 boring；H3 不应用命名指纹。
- 命名指纹的标准 TLS，以及所有 REALITY/JLS，使用自有 boring fork；开发及 PR/发布的来源规则见 [TLS 依赖](tls-dependencies.md)。
- 普通 TLS、Quinn 与采用标准 TLS 认证的 quiche H3 共用同一个 WebPKI 证书验证器和会话信任根；叶 pin、非叶信任锚、
  独立验证名、skip 优先级不变。TLS 握手签名仍由各自后端强制验证。
- HTTP、SOCKS5、AnyTLS、Trojan、TrustTunnel、VMess、VLESS、Hysteria2、TUIC v5 与 SS2022 ShadowTLS cover 的 mTLS 使用配对内联 PEM 或文件路径，
  配置校验与资源生成时读取文件并检查密钥匹配；客户端证书不增加服务端信任根，profile 不修改身份。
- quiche H3 的 ECH 仅支持 X25519/HKDF-SHA256，AEAD 为 AES128/256-GCM 或 ChaCha20-Poly1305。
  静态和 DNS 来源按该后端选择；不兼容或未实际接受时失败，不用 GREASE 替代，不降级为明文 ClientHello。
- REALITY 仅允许自身临时证书认证，不能混用 pin/skip/mTLS 或降级到普通站点证书。
- [JLS](vless.md#jls) 使用共享凭据身份和完整原生 TLS1.3，不启用恢复或 PKI 回退；profile 不改变身份。
- 连接器只包装 Dialer/上游交付的 IO；动态 ECH 通过既有解析上下文请求原始 HTTPS 记录，
  DNS 角色与物理 IO 仍由运行时和共享 Dialer 拥有，不绕过平台 protect。

证书与密钥的相对路径从初始化的 `dataDir` 解析；CLI 校验模式使用 `-d` 的目录而不初始化它。
未初始化的普通 `validateConfig` 和直接 Rust `Config::parse_yaml` 使用当前工作目录，绝对路径原样使用。
每个资源生成过程读取的身份文件合计最多 8 MiB，只接受普通 UTF-8 PEM 文件；错误不回显路径或内容。
内联身份固定；文件身份由运行时既有资源工作器每秒检查元数据，稳定读取并校验整对后发布，
失败保留旧身份。TLS 握手不读取文件。配置对象仍保留校验时的内联快照，文件更新不重建
代理图、不重置规则、DNS 或健康状态，也不更新业务 HTTP/MITM CA。
活跃的不同文件对按其当前已发布 PEM 输入大小合计最多 8 MiB；被旧 Provider 节点持有的
来源也计入，同一路径对共享材料。新来源或更新超出预算时保留可用身份/资源；文件读取候选
同样有界。已建立的连接只持有其实际 TLS 所需的旧代材料，不能阻塞同一文件对继续轮换。

## 客户端信任根

`tls.custom-certifactes` 使用 Mihomo 的真实字段拼写，接受证书内容字符串数组，
不读取路径，也不增加 `custom-certificates` 别名。内容在配置校验时解码，非法证书
使 Vole 校验失败；与 Mihomo 对非法条目发警告后继续的行为不同。未知 TLS 字段
继续拒绝。同一个顶层 `tls` 对象也接受 HTTPS Controller 的服务端证书与客户端认证字段，
由独立的服务端加载器消费，不加入出站信任根；契约见 [Controller](controller-api.md)。
独立测量配置仅接受客户端 `custom-certifactes` 子集。

启动时读取可用系统根，合并内置 WebPKI 和自定义根，构造一份会话共享的不可变根库。
普通/指纹 TLS、QUIC、DNS 各角色、WireGuard 私有 DNS、Provider/GeoData 下载及
健康探测都使用该根库。资源更新复用它，不重读系统根；新启动才能取得新的系统信任。
独立 `measureDelay` 配置也接受该客户端对象，节点与最终 HTTPS 探测共享其工作器根库。
纯校验只解析显式证书内容，不读取系统证书存储。客户端身份不增加服务端根。

系统读取使用官方 rustls-native-certs：macOS 读取可导出的信任设置，Windows 读取
Current User ROOT，Linux 发现 CA 文件/目录。SSL_CERT_FILE/SSL_CERT_DIR 可按该库
规则覆盖来源，读取失败保留基础根和有效自定义根，不关闭验证或转为明文。
导出根后的证书验证仍为 WebPKI，不承诺 native verifier 的全部信任、撤销与策略行为。
Android、iOS 和 tvOS 在此库的 Unix 发现分支中，不能完整读取平台系统/用户信任；
这些平台保留内置与自定义根，实际可读文件仅补充来源，不宣称完整系统信任等价。
Windows UWP/AppContainer 的真实根读取仍需独立设备验证；交叉编译不构成签收。

## 命名模板边界

模板由 fork 固定密码套件、组/share、签名算法、扩展排列及受限扩展编码。

| 模板 | 主要差异 |
| --- | --- |
| Chrome133 | 普通 TLS 与显式混合 REALITY 使用原生 X25519MLKEM768 和 X25519 双 share，无 padding |
| Firefox120 | 自有 cipher 顺序、固定扩展顺序、X25519/P-256 双 share，无 GREASE/ALPS/证书压缩 |
| Safari16.0 | 固定扩展和签名顺序、GREASE、条件 padding、真实 Zlib 解压，模板本身不加 ECH/ALPS |
| iOS14 | 独立套件与扩展顺序、GREASE、条件 padding，无证书压缩；真实 c023/c027/003c CBC-SHA256 协商 |
| Android11 OkHttp | 独立套件与扩展顺序，无 GREASE、证书压缩或 TLS1.3 声明 |
| Edge85 | 固定扩展顺序、GREASE、X25519 share、Brotli 证书解压 |
| 360 Browser7.5 | TLS1.2、P-256/P-384/P-521；不启用假 DHE/DSA、RC4 或禁用套件 |
| QQ11.1 | 独立命名模板，固定扩展顺序、GREASE、X25519 share、Brotli 证书解压 |

TLS 版本范围、SNI、ALPN、证书策略、身份和恢复预算仍由节点及传输决定。
Android/360 的参考模板只有 TLS1.2 能力；要求 TLS1.3 的身份与传输拒绝此组合，不伪造 share 或改名。
因此名称表示版本固定的 TLS 模板，不承诺完整浏览器行为或所有上下文的逐字节相同。
最低 TLS1.2；Safari/iOS 的 TLS1.0/1.1 声明裁剪，Vision/XHTTP/REALITY 继续强制 TLS1.3。
普通 Vision/XHTTP 的版本约束同时省略 TLS1.2 cipher 及仅用于旧握手的
EC point formats、extended master secret、session ticket、renegotiation info 扩展。
命名 REALITY 则保留模板的 TLS1.2 声明与字段，由原生 REALITY 在 ServerHello 阶段
拒绝非 TLS1.3 协商；这与关闭命名指纹时的 TLS1.3-only 默认 offer 分开。
Core 使用标准 H2 SETTINGS，不声明 TLS ALPS，也不复制 Mihomo 某些 WS 调用中的额外 h2 ALPS。
classic REALITY 移除 Chrome133 的 ML-KEM group/share，并绑定实际 X25519 私钥；
Firefox 的额外经典 share 不产生第二份 REALITY 身份。REALITY 仍拒绝 HRR、恢复和 0-RTT。

`reality-opts.support-x25519mlkem768`：默认 false，true 允许在同次握手中协商
真实 X25519MLKEM768（4588）或经典组。Chrome133 与未命名 profile 提供混合/X25519
双 share，其余 TLS1.3 模板保留各自真实经典 share，不伪造混合能力或自动改成 Chrome。
Android/360 的模板只有 TLS1.2，不能用于 REALITY；这项限制来自实际模板版本，
并非新增协议限制。下载腿继承/整体替换 REALITY 后独立验证最终 profile。
服务端选择允许的经典组不触发重试；HRR、认证失败仍终止，不降级为普通 WebPKI。
ML-KEM 增强 TLS 密钥交换，REALITY 身份认证仍基于 X25519，不宣称后量子身份认证。

Firefox 的 FFDHE、delegated credentials、record size limit 及 Safari/iOS 的模板专用
cipher 声明不开放新的配置能力；不能真实完成的对端选择明确失败，不静默换模板。
iOS 的 c024/c028/003d 与 Safari/iOS 的 c008 仅声明，对端选中会失败；003c 使用
已有原生 RSA/AES-CBC/SHA256 实际协商，并保留 deprecated 标记，默认套件不启用。

模板不模拟浏览器 HTTP/2 SETTINGS、QUIC 参数，也不会自动启用实际 ECH。
VLESS/VMess/Trojan/AnyTLS/Hysteria2 可另行显式配置 [ECH](vless.md#ech)：具备 TLS1.3 能力的六种模板可使用，届时强制 TLS1.3、
加入真实 ECH 并关闭恢复；不再声称与未启用 ECH 的历史浏览器模板逐字节相同。
当前 HTTP 驱动不导入 TLS ALPS 中的应用设置，握手时不声明该可选扩展，
由标准 SETTINGS/ACK 初始化。意外协商的非空 ALPS 仍失败，不能静默忽略设置。Brotli/Zlib 解压输出和原生证书消息上限均为 128 KiB；
超限、截断、错误算法和损坏压缩流失败，不能绕过证书认证。

## 所有权与关闭

节点的 SNI、ALPN、验证策略、版本范围和 profile 不随文件更新改变。每条新物理 TLS/QUIC
连接使用一次已发布的 mTLS 身份快照；既有 H2/gRPC/QUIC 物理连接可继续使用原身份。
rustls 按身份代缓存不可变 resolver/config，Boring 在独立 SSL 对象中安装该次身份，
quiche 在该条物理连接的上下文中安装身份，均不修改进行中的握手。
原生证书表示只由实际使用它的 TLS 客户端持有，材料登记只保留弱缓存；失败候选释放其原生需求和缓存。
每次独立构造建立独立缓存，clone 只共享同一节点。标准 TLS 的运行时票据总预算为 4；
文件身份换代后，旧代票据不能恢复新连接，旧连接晚到的票据也不进入新代缓存；
各代共享原节点的固定容量，不随轮换次数增加缓存。身份检查工作器随资源工作器同步停止。
TLS 1.3 票据只消费一次，TLS 1.2 会话也计入预算，过期票据清除，零预算关闭恢复。
非零 TLS1.2 ticket lifetime hint 与原生 session timeout 取较短者；零提示不扩大原生期限。
Safari16/iOS14 不声明 TLS1.2 session-ticket 扩展，该版本的恢复使用会话 ID，不能把不存在的
票据提示当作它的过期时间。TLS1.3 的票据期限已由原生握手收敛。
握手及应用层 ALPN 策略通过前，暂存票据不会进入节点缓存。REALITY 始终不恢复。
同一模板的使用不扩大节点/下载腿缓存归属。冷连接和恢复连接分开验收；Vole 的
票据策略不同于 Mihomo，恢复 hello 不宣称逐字段相同，也不伪造 PSK/binder。
quiche H3 为每条物理连接构造独立原生 TLS 上下文，禁用恢复与 0-RTT；
节点内已认证的 H3 连接仍可复用，关闭和取消由其驱动所有者同步回收。
XHTTP H3 与 DoQ/DoH H3 同样禁用恢复与 0-RTT；ECH 从完整来源按 rustls 后端选择，未接受时握手失败。

CloseWrite 刷新 close_notify 最多 5 秒，保留底层连接和读方向；重复关闭幂等，
关闭后拒绝写入。Vision direct 切换保留同一 TLS 记录边界，先排空明文/刷新密文，
不向裸流插入外层 TLS alert。XHTTP 仍按其整条逻辑连接关闭契约工作。

## 验证与发布

验证使用真实公开配置、共享连接接口和独占容器内的原生协议对端；
编解码及纯内存 TLS 测试不启动宿主监听器。命令见 [构建与检查](../scripts/README.md)，
指纹分层与 golden 比对见 [指纹验证](../tests/fingerprints/README.md)，
结果的证明范围见 [验收边界](acceptance.md)。设备、性能、体积和发布许可证审查各自独立，
本地互通或交叉编译不替代这些门禁。
