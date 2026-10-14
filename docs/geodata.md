# GeoData 规则与资产

Vole 管理 `dataDir/geodata` 下的 `geosite.dat`、DAT 模式的 `geoip.dat` 和独立 `ASN.mmdb`，
国家 MMDB 位于 `dataDir` 根目录。`geodata-mode` 缺省为 false（MMDB），true 使用 DAT。
只为当前配置实际引用的
分类与属性交集构建匹配器。主规则和所有 `sub-rules` 定义中的谓词、逻辑子项及
classical provider 内容共同收集引用；每个定义只遍历一次，不沿调用边展开。所有平台均不设 GeoData 条数上限，不按数量截断记录，
也不设总内存预算。资产缺失或加载失败时，对应种类不可用，跳过相应 Geo 规则并继续
普通选路；卸载前的下载或结构校验失败保留当前快照。配置、格式、整数表示和
可恢复分配错误仍然失败关闭。

## 规则

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,cn,DIRECT
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,main-select
```

语法：

```text
GEOSITE,[!]<code>[@<attribute>...],<target>
GEOIP,[!]<code>,<target>[,no-resolve][,src]
SRC-GEOIP,[!]<code>,<target>
IP-ASN,<asn>,<target>[,no-resolve][,src]
SRC-IP-ASN,<asn>,<target>
```

- 规则类型和 `code` 不区分 ASCII 大小写，route target 名称大小写敏感并精确匹配。
- `target` 可以是 `DIRECT`、`REJECT`、当前资源中的代理节点或已支持的代理组。
- 基础 `code` 必须匹配 `[A-Za-z0-9][A-Za-z0-9._+!-]{0,63}`，按 ASCII 大小写折叠后定位。
- `GEOSITE` 恰好三段；`GEOIP` 接受大小写敏感的 `no-resolve`、`src`，顺序无关。
  `src` 和 `SRC-GEOIP` 使用真实来源 IP，不触发 DNS。
- `GEOSITE,cn@ads@cn,DIRECT` 只保留同时存在 `ads` 和 `cn` 属性 key 的记录，多个属性为 AND。
  属性只检查 key 存在，不解释 bool/int 值；`false`、`0` 或无 typed value 均不代表 key 缺失。
- 属性名按 Mihomo 的先小写、后 Unicode simple-fold 比较语义归一；交集顺序与重复 key 不改变
  结果。空 `@` 项忽略，非空属性首尾空白移除，但内部空白、控制字符和逗号不允许。
- 前置 `!` 对整个正向匹配结果取反：`!cn@ads` 是 NOT(匹配 `cn@ads`)，不是“没有 ads 的记录”。
  `cn@!ads` 查找字面 key `!ads`；`geolocation-!cn` 是字面分类名。
- GeoIP 支持前置 `!`，不支持属性或单条多个 code。`lan` 是内置分类：私有、未指定、
  回环、多播与链路本地单播地址；来源与目标均可使用，不读取 GeoIP 资产。
- `IP-ASN` 的 payload 逐字匹配 ASN 十进制值，不转换 `AS` 前缀或补零；
  `src` 和 `SRC-IP-ASN` 使用实际来源 IP，不触发 DNS。不可用的 ASN 不触发惰性 DNS。
- rule 模式按顺序首条命中，未命中 DIRECT；可选的 `MATCH` 使用 `DIRECT`、`REJECT`、实际代理节点或代理组。

DNS `nameserver-policy` 中的 `geosite:<selector>[,<selector>...]` 接受相同的属性与反选语义，
逗号连接的 selector 为 OR。业务规则与 DNS policy 共享基础分类、value arena 与正则，
每个基础分类只解码一次；不同属性交集保留各自匹配索引，正反选不复制记录。
普通域名与通配域名 policy 不加载 GeoData，其匹配顺序见 [DNS Policy](tun-icmp-dns.md#policy)。

存在分类但属性筛选为空时，该 selector 仍可用：正选不匹配，反选匹配所有合法非空域名。
分类缺失、资产不可用或未声明的 selector 不能通过反选变成全匹配；没有域名时所有 GeoSite
selector 均不命中。属性折叠使用依赖的 Unicode 16 simple-fold 表；不保证与采用其他
Unicode 版本的 Mihomo 在所有新字符上完全等价。

## 资产格式

| 规则 | 文件 | 顶层消息 | 内容 |
| --- | --- | --- | --- |
| `GEOSITE` | `geosite.dat` | `GeoSiteList` | code 与 Domain 记录 |
| `GEOIP` | `geoip.dat` | `GeoIPList` | code 与 IPv4/IPv6 CIDR |
| `GEOIP`（默认模式） | 根目录国家 MMDB | MaxMind DB | 直接 IPv4/IPv6 索引查询 |
| `IP-ASN` / `SRC-IP-ASN` | `ASN.mmdb` | MaxMind DB | IPv4/IPv6 ASN 索引 |

- YAML 不能指定本地路径或环境变量。MMDB 在 `dataDir` 的直接子文件中按文件名字典序，
  不区分大小写寻找 `Country.mmdb`、`geoip.db`、`geoip.metadb`，选择第一个并保留实际名称；
  不因它损坏而改选另一个数据库。缺省下载目标为 `geoip.metadb`。
- 所有资产必须是普通文件；DAT 校验外层帧、code、分类引用、实际选中的 CIDR / Domain 记录。
- DAT 第一遍扫描建立 code 到文件范围的索引，容量按需增长；第二遍只解析被配置引用的分类。
- 只引用属性交集时，先流式检查属性；未命中任何交集的记录按 wire/length 边界跳过，
  不校验 value 或编译 Regex。引用无属性 selector 时则包含该分类的全部记录。
- DAT 目标 code 缺失、重复或损坏时，整份对应种类的快照不可用，不能当作空分类。
- GeoSite、GeoIP 和 ASN 分别校验和报告可用性，一类不可用不影响其他种类或基础规则。

## 国家 MMDB

国家库支持 MaxMind `country.iso_code`、`sing-geoip` 根字符串和 `Meta-geoip0` 根字符串/字符串数组。
MaxMind 国家代码按 ASCII 大小写折叠，sing/Meta 保留原字符串大小写。国家库与 DAT 二选一，
GEOIP、来源规则、classical/地址选择器及 DNS fallback 共用一个 owned Reader；查询借用字符串，
Meta 多 code 的临时索引只保存引用。没有全量 CIDR 展开或逐地址缓存。缺库、坏索引和无效记录
不通过反选成为全匹配；有效库的无记录地址按空 code 集合处理。
保留 maxminddb 的默认单次解码与索引验证保护；解码错误不当作合法的空记录。

国家 MMDB 更新与 ASN 同样先借用候选字节完整校验，旧读者排空后移动该缓冲到 owned Reader；
无效候选、取消或提交失败保留/恢复旧代。模式和实际文件名共同绑定调度来源与 ETag/hash，
下载暂存及原子替换始终使用被选中的实际路径，GeoSite/ASN 的存储与状态目录不变。

## ASN MMDB

仅在规则或 classical 内容引用 ASN 时读取 `ASN.mmdb`。支持数据库类型
`GeoLite2-ASN`、`DBIP-ASN-Lite (compat=GeoLite2-ASN)` 和
`ipinfo generic_asn_free.mmdb`；前两者读取 `autonomous_system_number`，后者读取
`asn` 并移除其 `AS` 前缀。合法的数值型数据库无记录时按 ASN `0` 匹配；数据库
不可用、索引错误或记录字段无效不会被当作 ASN `0`。IPinfo 无记录不匹配。

使用一个拥有文件字节的 MMDB Reader，直接查询 IPv4/IPv6 索引，不展开 CIDR，也不
建立按地址增长的缓存。查询只解码所需字段，不复制完整记录。ASN 与目标 GEOIP 共用
既有惰性 DNS 路径；`no-resolve` 不主动解析，但可使用先前规则已解析的地址。

更新先以唯一候选字节缓冲构造借用 Reader，完整校验 metadata、树、separator 和
数据图；校验失败时保留当前内存与磁盘代次。校验期间旧文件字节与候选字节必然重叠，
验证还会临时分配第三方 metadata 和图检查状态。借用 Reader 释放后，暂停新快照读取、
等待旧读者结束；超时或取消时恢复旧快照。旧存储析构后才将同一候选缓冲移入 owned
Reader，重建 metadata，避免另一份全量候选复制。

ASN 提交保留旧磁盘文件的 hard link（不可用时复制）；提交失败先丢弃候选内存，再
恢复旧稳定文件和调度状态并重新加载旧匹配器。恢复磁盘或状态遇真实 I/O 错误时报告
该错误；不能恢复旧文件时 ASN 降级，其他健康种类继续可用。停止仍等待管理任务完成。
普通 DAT 更新与外部重载保留后文的独立降级契约。

## 自动更新

HTTP 传输由共享资源模块维护，所有跳转经过当前 Core dispatcher。下载、管理阻塞任务和解析均在停止屏障内；取消及下载 future 被丢弃时清理未发布的暂存文件。

四个 URL 字段独立可选。缺省使用 MetaCubeX meta-rules-dat 的 latest GeoIP/GeoSite DAT、
国家 `geoip.metadb` 与
`GeoLite2-ASN.mmdb` URL；自动更新默认关闭，周期默认 24 小时：

```yaml
geodata-mode: true # DAT；省略或 false 使用国家 MMDB
geox-url:
  geoip: https://assets.example.com/geoip.dat
  mmdb: https://assets.example.com/geoip.metadb
  geosite: https://assets.example.com/geosite.dat
  asn: https://assets.example.com/ASN.mmdb
geo-auto-update: true
geo-update-interval: 24
```

约束：

- `geox-url` 只能包含 `geoip`、`mmdb`、`geosite` 和 `asn`；URL 必须是以域名为主机、无 userinfo/fragment 的绝对 HTTPS URL。
- `geo-update-interval` 单位为小时，支持非负整数；0 停用周期更新。
- `validateConfig` 和准备阶段不下载。运行后仅为当前引用的资产启动资源任务；缺失或不可用时获取默认或配置的 URL，自动更新控制可用资产的周期检查。
- 下载按当前 mode 与业务规则选路，未命中使用 DIRECT；可选目标包含内置动作、节点和代理组。选中代理组时，每次新建下载物理 transport 时沿嵌套组解析到当时选中的叶节点；失败不自动换成员，也不隐式回退 DIRECT 或系统代理。
- 缺失资产立即检查；失败后按 1 分钟、5 分钟、15 分钟、1 小时退避，之后保持 1 小时上限。成功后恢复配置的更新周期。
- `global-ua` 控制资源请求的 User-Agent，默认 `Vole/` 加 Core 版本；`etag-support` 默认 true，false 时不发送条件请求。ETag、SHA-256、源 URL 和下次检查时间保存在 Vole 管理的状态中。合法 304 在匹配器
  已可用时只推进调度；有必需种类不可用时，先按相同重载流程从本地资产恢复匹配器。
- 下载以固定大小缓冲流式写入同目录暂存文件，不限制资产总字节；保留 90 秒期限、取消、HTTPS/HTTP 解析边界和字节计数溢出检查。流式落盘期间保留当前快照；文件大小、wire 结构和 staging 检查通过后，先卸载并排空旧匹配器，再构建候选。分类需求校验成功后原子替换文件，SHA-256 随状态保存；失败保留上一份磁盘资产，不保证恢复旧内存快照。
- 跨进程更新锁和原子重命名只保护共享数据目录，不提供多实例调度协议。

隔离实验可显式编译独立、非默认 `benchmark-geodata-http` feature，使 GeoData 更新
接受以域名为主机、无 userinfo/fragment 的 HTTP fixture；仍通过同一个 dispatcher 和
流式下载器，不建立 TLS。HTTP 重定向可保持 HTTP 或升级到 HTTPS，HTTPS 不允许降级。
该入口没有环境变量或新的 YAML/FFI 开关；未编译该 feature 时仍强制 HTTPS，HTTPS 的
会话共享信任根和完整证书验证不变。平台构建及 delivery 拒绝该测试 feature。HTTP 实验只验收
更新逻辑与资源占用，不构成生产 HTTPS 信任链验收，不应启用 `interop-test`。

## GeoSite 匹配

TUN 的 IP 目标采用以下选路提示优先级：

```text
嗅探域名 > 原始/恢复的域名 > DNS 提示 > 无域名
```

DNS 提示只在目标缺少域名时使用；嗅探域名优先参与域名规则。启用嗅探的目标覆盖时替换
实际出站目标。没有域名时，`GEOSITE` 不匹配，也不触发 DNS。

运行时目标、嗅探和 DNS 提示的域名规范化（不是资产加载条件）：

1. 移除一个末尾点；
2. 使用 UTS #46 non-transitional 和 STD3 生成 ASCII A-label；
3. 转为 ASCII 小写；
4. IDNA 失败时，只允许严格的 1–253 字节 ASCII DNS 名称，每个 label 为 1–63 字节且只含字母、数字和内部连字符。

目标域名两条路径都失败时拒绝当前会话或数据报；IP 目标的嗅探/DNS 提示则是尽力注解，
无法规范化时忽略提示，不使合法 IP 目标不可达。规范化结果写入有界选路上下文供后续规则复用。

资产中的 `Domain` / `Full` 是静态字面匹配值，不是将要解析的 DNS 主机名，不再以
STD3、LDH 字符、63/253 字节或合法 Punycode 作为加载条件。移除一个末尾点、转小写；
ASCII 值直接处理，不为每条记录分配规范化字符串。Unicode 值尽可能转换为 ASCII
A-label，保持现有 IDN 匹配；转换失败则保留小写 UTF-8 字面值，不丢弃记录，也不使
整个分类失效。引号、下划线、反斜杠等字符不擅自删除，`*` 不新增通配语义。

仍要求记录字段、类型、UTF-8 与规范化后的非空值合法，保留整数与 arena 表示边界。
这些静态值不会直接传入 DNS、TLS 或连接接口；能加载不代表每个值都能成为合法的
运行时目标。实际目标的现有规范化、DNS wire 长度检查和 TLS 身份验证不受此调整影响。
Mihomo 也不以严格 DNS 主机名语法校验 GeoSite 值；其 Unicode/尾点模式行为不同，
Vole 使用合法 IDN 和单尾点规范化，不宣称所有模式语义完全一致。

支持的 Domain 记录：

| 类型 | 语义 |
| --- | --- |
| `Plain` / `Substr` | 完整域名包含 value |
| `Domain` | 等于 value 或属于其子域 |
| `Full` | 完全相等 |
| `Regex` | 在规范化后的完整 ASCII 域名上执行搜索 |

Domain/Full 在加载时原地排序紧凑记录，运行时对完整名称及逐 label 后缀做二分查找，
未命中也不线性遍历全部 Domain/Full，不复制 value arena。Substr
与 Regex 仍按各自语义匹配，分类内各记录是集合并集，不影响外层规则的首命中顺序。

选中的 `Regex` 只接受 ASCII 源和 RE2 类子集，不支持 look-around、backreference 或
额外内联模式，不宣称完整 Go 正则兼容。每条正则编译为共享的
`regex::bytes::Regex`，使用 `RegexBuilder::unicode(false)` 保持 ASCII 匹配语义；
不显式构建 dense DFA，也不在 Vole 中配置 NFA、DFA 或 determinization 额度。
保留 `regex` 库默认的编译大小、语法嵌套和搜索缓存保护，超出库边界的所选表达式
使候选加载失败，而不是丢弃记录。Vole 不设置正则条数、累计源码或总内存预算。
正则的编译与搜索状态由库管理；搜索可能分配 scratch、增长缓存或竞争共享缓存，
不再承诺 Regex 热路径无分配。Domain/Full 的紧凑无分配查找保持不变。
库的局部保护不是全部正则合计内存或整进程峰值的上界。

GeoSite 正则保持上述大小写敏感的 Go/RE2 类行为，不使用 `DOMAIN-REGEX` 的默认 IgnoreCase
或复杂引擎。业务规则、DNS selector、fake-IP filter 与嗅探决策把其线性搜索计入同一
sticky 执行预算；预算失败向调用者传播，不能通过反选变为命中或默认直连。此预算限制
单次决策的执行工作，不限制 GeoData 记录数量、加载量或资产总内存。

## GeoIP 与 `no-resolve`

- 目标已经是 IP 时直接匹配同地址族 CIDR，`no-resolve` 不改变结果。
- 目标只有域名且规则带 `no-resolve` 时，不触发 DNS，继续后续规则。
- 之后首条不带 `no-resolve` 的 IP 类规则最多触发一次运行时 DNS，结果只供当前和后续规则复用。
- A 结果先于 AAAA；第一个命中 CIDR 的有效地址成为当前会话或数据报的固定目标。
- `dns.ipv6: false` 时不请求或采用 AAAA。
- 运行时 DNS 不可用或上游失败时继续下一条规则，不使用引导解析器替代；
  规则执行预算、取消或引擎错误终止本次决策。
- `GEOIP,!cn,...` 对同一次 CIDR 匹配结果取反，不执行反向 DNS。DAT 的 `reverse_match`
  字段按 Mihomo loader 行为接受但忽略；是否取反只由 selector 的前置 `!` 决定。

## 生命周期

- `validateConfig` 只校验结构、URL、selector 和去重，不读磁盘、不联网；不限制 GeoData 唯一引用数或 GeoSite DNS policy 数。
- `prepare` 注册去重后的需求并读取当时可用的本地快照，不等待更新。
- Manager 只为当前公共实例构建匹配器；停止或销毁实例时释放需求和快照。
- 更新在下载和 staging 检查期间继续使用当前快照。构建新匹配器前，原子发布空匹配器、
  释放 Manager 的旧快照引用，并等待最后一位旧选路读者完成、旧匹配器存储析构结束。
  此后只构建一次候选；磁盘与调度状态提交成功后直接原子发布，不从最终文件重复加载。
  国家 MMDB 与 ASN 使用前文的完整预校验与失败恢复流程。
- 注册、重载与更新提交通过 Manager 管理锁串行，避免旧重载覆盖新发布；业务和 DNS
  的 ArcSwap 读取不获取该锁，也不等待排空。旧读者继续完成本次求值；排空、加载期间
  新请求复用首次资产缺失的语义，仅跳过不可用的 Geo 规则，继续普通规则与既有 DNS
  policy/回落路径。没有全局代理切换、新的 YAML/FFI 模式或 DNS 准入门禁。
- 排空期限沿用默认下载超时值 90 秒，等待期间最多每 25 ms 检查一次取消；超时或
  取消不构建或发布新候选。后台状态观测、开始更新、提交和 304 恢复均移出业务 worker，
  Stop 取消后仍等待管理任务结束，不遗留后台发布。已开始的 CPU 加载不能中途强制
  中断；结束后检查取消并丢弃候选，因此 25 ms 不是完整 Stop 的耗时保证。
- 重载按已注册的 selector 与 ASN 需求重建匹配器，三类可用性独立。卸载后的所选记录
  加载失败使对应种类保持不可用，仍发布另一类健康数据；不重新安装旧整体快照。
  更新候选无效时保留旧磁盘文件并记录失败，后续继续按现有调度重试。
- 重载首次取消检查前先记录待重载状态。卸载前取消保留旧匹配器；即使新磁盘代次
  已被观测并缓存，后续未取消的状态观测仍从本地恢复，无须等待另一代次或网络下载。
  排空超时或卸载后取消保持空匹配器及待重载状态，自动更新关闭时亦可恢复。
  已发布的独立降级结果不标记为待重载，失败种类保持不可用，直到下一次明确重载或更新。
- 新流使用当时的可用快照；已经完成的 TCP 选路和 TUN UDP 固定 action 不回溯。
  当前完整重建所需的各类数据，不跨代复用分类存储；排空防止两代 owned matcher 同时存活，
  ASN 校验期的字节重叠见上文，
  不保证 allocator 立即归还 RSS，也不限制单代加载峰值。
- 分类表在加载时按 code 排序，运行时大小写无关二分定位；规则仍按配置顺序首命中。
  每次业务选路捕获一份当前不可变快照，整次求值复用，不在每条 Geo 规则上重复读取 ArcSwap。
- DNS `nameserver-policy` 的一次同步选择同样捕获并复用一份不可变快照，跨 selector
  和 policy 项保持一致；空快照沿用资产缺失回落。选择函数返回时释放快照，不复制规则，
  不跨上游 I/O 的 `await` 持有。
- TUN UDP 的 IP 目标按五元组固定 action；源地址/端口、UDP 和入口由源关联固定，
  关联内按目的 IP/端口独立记录。首包完成嗅探与选路后，活动流不再逐包读取 DNS
  提示或匹配规则，DNS/GeoData 更新只影响新流。状态仅保留 action、活动时间和
  可选的已认证 QUIC 连接标识，不持有域名、DNS 答案或 GeoData 快照。
- 已启用的 QUIC 嗅探端口中，同五元组出现新认证 Initial 时重新选路；同标识重传、短头、未认证候选和
  不支持版本不使既有流重新选路。每目的 30 秒空闲失效，10 秒间隔在关联活动时
  回收，完全空闲的源仍由既有关联清理回收；不创建逐流任务、队列或 socket。
- 显式域名目标和非 TUN UDP 继续逐包选路/解析，不把域名冻结为旧 DNS 答案。
  固定 action 不是固定代理组叶子：同源关联仍复用每 route target 的物理 transport，
  已有 transport 保持原成员，只有新建物理 transport 读取新的组选择。
  相比 Mihomo 的按源关联首包选路，本实现细分到五元组，不宣称两者完全同义。
- Controller 切换代理组不会重启正在进行的下载或迁移既有连接；只有之后新建的 GeoData 下载物理 transport 使用新选择。
- `measureDelay` 不注册 GeoData、匹配器或更新任务。

## 内存与安全边界

所有平台均不设置 GeoData 原始记录、分类、唯一引用、累计 value/Regex 源码字节或
资产文件大小的独立额度，也不设置 GeoData 总内存预算；不因数量静默截断或丢弃记录。
DNS GeoSite policy 没有独立项数/引用数上限。普通 YAML 8 MiB、显式 rules 65,536 条/
合计 8 MiB/单条 16 KiB 仍是配置入口边界，不是 DAT 内记录数限制。

基础分类、字面值和正则只存一份，属性交集使用共享 arena 的紧凑索引；多个交集仍会
增加索引容量与加载成本，不能把共享存储理解为内存常量。保留 checked arithmetic、
fallible Vec 扩容、合法 protobuf 帧/长度、code、选中匹配值的 UTF-8 与非空检查、CIDR
地址宽度/前缀和选中正则的语法检查。紧凑 value/Regex arena 的 offset/length 仍须
能表示为 u32；这是存储表示边界，不是可配置的内存预算。CIDR 仍无损去重、删除被覆盖
前缀并合并对齐 sibling。分配失败可能返回错误；系统 OOM 或第三方不可恢复分配失败
不保证可恢复。

容量账本仅作诊断：统计 Vole 自有 matcher/index/value/临时 Vec 的可见容量，扩容时
记录新旧缓冲可能重叠的容量；没有最大值、不控制准入。`regex::bytes::Regex` 不提供
完整内部状态的准确 `memory_usage`；国家/ASN 文件缓冲容量计入快照容量，借用候选
验证期的新旧字节重叠、Meta 多 code 查询的临时引用索引与 MMDB metadata/图校验状态未计入。因此账本**不包含正则内部编译状态、搜索缓存、
动态 scratch、配置需求集合、allocator 开销或整个进程 footprint**。这些未计入的
内存并不是零；accounted peak 不能作为加载或运行期峰值上界。
进程 RSS 的硬上限与 2Gbps 联合负载目标统一见[验收边界](acceptance.md#性能采纳标准)，
它们是压力测试标准，不是加载器保证。

互通和内存/吞吐压力由公开 [container-benchmark](https://github.com/YuanDevTeam/container-benchmark)
维护；`interop`、`stress` 和 `compare` 以 `--source vole=PATH` 显式指定被测 checkout。
Vole 自有脚本仅负责编译。压力与横向比较固定只引用完整 `geosite:cn` / `geoip:cn`，
更新下载保留原始增强 DAT，但不因此加载其他分类。真实资产的类型分布、明确标识的四类型/复杂正则合成用例、
属性/反选见证、加载与真实更新期间的峰值、联合吞吐/DNS/RSS 结果以 benchmark 的本轮文字结论为准。
历史 Domain/Full 子集或单纯离线加载不能替代完整真实资产的 fd-TUN 压力，也不能证明
任意正则的加载峰值。Linux RSS 不替代 Apple Network Extension physical footprint；
少量转发见证不等同逐条规则语义穷举。

## 失败语义

- 非法规则、URL 组合、selector 或通用配置入口越界使配置校验失败。
- 文件缺失、损坏、下载失败或检查超时不使实例生命周期失败；更新前下载、文件大小、
  wire 结构或 staging 检查失败发生在卸载之前，当前快照继续可用。
- 首次加载、外部资产重载或卸载后的所选记录加载失败，使对应种类不可用；健康种类
  独立发布。排空超时或卸载后取消也保持已卸载状态，不能通过反选绕过不可用语义。
  DAT 失败更新保留旧磁盘资产，不恢复旧内存快照；国家 MMDB 与 ASN 更新按前文恢复旧代。
- 不可用的 GeoIP 或 ASN 规则不得触发惰性 DNS。
- 调度状态损坏时在更新锁内重置；异常退出留下的更新状态在锁释放后恢复。

自动化与实机覆盖范围见 [验收矩阵](acceptance.md)。
