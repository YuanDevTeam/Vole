# 运行时 Controller API

Controller 是当前 Running Session 的 HTTP 接口。它提供业务连接管理、有效设置与规则查询、一次性 TUN 流量快照，以及静态与动态 `select`、`url-test`、`fallback`、`load-balance` 代理组的状态查询和实时选择；它不是 Invoke API，也不承诺完整 Mihomo Dashboard 兼容。

## 配置与生命周期

```yaml
external-controller: 127.0.0.1:9090
external-controller-tls: 127.0.0.1:9443 # 可单独启用或与 HTTP 同时启用
external-controller-cors:
  allow-origins: ["https://ui.example"]
  allow-private-network: false
secret: "vole-runtime-secret"
```

- 两个 Controller 地址均省略或空串时不启动 Controller，也不采集业务连接、规则命中和建链诊断；配置中的 `secret` 可保留。代理组选择、健康检查、资源更新与 TUN 原始流量统计独立运行。
- `external-controller` 接受 IP、`localhost` 或空 host 与数值端口组成的地址，如 `127.0.0.1:9090`、`0.0.0.0:9090`、`[::]:9090`、`localhost:9090`、`:9090`。端口范围为 0–65535，0 由系统选择端口；`localhost` 使用 IPv4 回环。其他域名和命名服务端口不在当前范围内。静态节点、纯 DIRECT 及关闭业务入口的配置均可使用。
- 空 host、`0.0.0.0` 和 `[::]` 均优先使用允许 IPv4 映射连接的双栈通配监听，仅地址族不可用时改用 IPv4。Controller 的地址族选择独立于顶层 `ipv6`。
- `external-controller-tls` 使用相同地址格式、绑定与端口范围。HTTP/HTTPS 共享当前会话、API handler、选择状态和 Bearer 认证；HTTPS 按实际 ALPN 提供 H2/H1，无 ALPN 使用 H1；明文 HTTP 仅 H1。
- `secret` 始终可选，省略或空串表示不要求认证；配置非空值时保护本文定义的业务路由，CORS 预检在认证之前处理。配置仅受整体 YAML 大小预算约束，HTTP 请求头仍限 32 KiB。
- `measureDelay` 的 node-only 配置不能包含 Controller 或代理组字段。
- `validateConfig` 只校验 Controller 字段；`start` 加载服务端证书并绑定端口，任一失败则启动失败。`stop` 和 `destroyInstance` 关闭两种监听器并等待请求与证书 watcher 回收。

Controller 与公共运行时 session 同生共灭。`profile.store-selected` 默认 true，Core 将显式选择保存到 dataDir/selected.json，在下次启动时恢复有效成员；不写回 YAML。关闭该选项后只保留会话内选择。写入失败不回滚已生效的选择，`GET /proxies` 的 `selectionError` 给出脱敏原因。

## HTTPS 证书与客户端认证

```yaml
tls:
  certificate: controller.pem
  private-key: controller.key
  client-auth-type: require-and-verify
  client-auth-cert: controller-client-ca.pem
```

`certificate/private-key` 接受配对 PEM 内容或 dataDir 内的文件路径。两者均空时生成随机 RSA 2048 密钥与自签证书，没有配置域名或公共信任；没有 HTTPS 地址时不加载服务端材料。内联证书在本会话中固定，文件证书对每秒检查一次：匹配且有效的完整候选原子替换，坏候选保留旧证书；在途 TLS 使用已选择的证书，新握手取得新候选。只读取普通文件，证书对合计最多 8 MiB；错误不输出内容、私钥或路径。

`client-auth-type` 对客户端证书的要求如下；TLS 始终校验客户端 CertificateVerify 握手签名。

| 值 | 无客户端证书 | 提供客户端证书 |
| --- | --- | --- |
| 省略、空串或其他字符串 | 允许，不请求证书 | 不要求证书 |
| `request` | 允许 | 校验结构与握手签名，不校验信任链 |
| `require-any` | 拒绝 | 校验结构与握手签名，不校验信任链 |
| `verify-if-given` | 允许 | 必须通过配置 CA 的证书验证 |
| `require-and-verify` | 拒绝 | 必须通过配置 CA 的证书验证 |

默认模式携带非空 `client-auth-cert` 时自动提升为 `require-and-verify`；显式 `request/require-any` 保留原要求。CA 接受 PEM 内容或 dataDir 内普通文件，最多 8 MiB，只在启动读取；不随服务端证书 watcher 自动更新。客户端认证与 API Bearer 分别执行，成功的 TLS 握手不会跳过非空 secret。服务端证书、客户端 CA 与 `tls.custom-certifactes` 的出站信任根分别消费。

## CORS

`external-controller-cors.allow-origins` 缺省、空数组或含 `*` 时允许全部来源，响应为 `Access-Control-Allow-Origin: *`；其它列表按忽略大小写的精确匹配或单个 `*` 通配匹配，成功时回显请求来源。无 Origin 或来源不匹配时不返回允许来源头，普通 API 请求仍走原路由与 Bearer。

OPTIONS 携带 Origin 和非空 `Access-Control-Request-Method` 时为预检，在 Bearer 前返回 200。允许 GET/POST/PUT/PATCH/DELETE，OPTIONS 同样有效；请求头仅允许 Content-Type、Authorization 与参考自动加入的 Origin，缓存 300 秒，不返回 Allow-Credentials。拒绝的预检仍为 200，但不返回允许头。普通响应含 `Vary: Origin`，预检另含请求 method/headers 的 Vary。

`allow-private-network` 缺省 true；只对成功预检且请求 `Access-Control-Request-Private-Network: true` 返回相应允许头，显式 false 禁止返回该头。CORS 不改变 Controller 地址、secret 或 API 支持范围。

## 请求预算与停止

HTTP/HTTPS 合计最多 8 条活动连接。H1 每连接处理一个请求后关闭；H2 每连接最多 8 条并发请求，超出准入复位 stream，接收窗口每流 1 KiB、连接 8 KiB，发送缓冲每流 16 KiB。头部上限 32 KiB/100 字段，H2 target 上限 8 KiB，PUT body 上限 1 KiB；握手、H1 读头、body 与写响应各有 5 秒期限。停止取消活动请求、关闭协议 driver，并等待所有 H2 请求和文件候选读取完成。

## Bearer 鉴权

配置非空 `secret` 后，除上述 CORS 预检外每个请求都必须携带：

```http
Authorization: Bearer vole-runtime-secret
```

要求：

- scheme 必须精确为 `Bearer`，token 必须与当前 session 配置完全一致；
- 缺失、重复、格式错误或不匹配都返回 `401 Unauthorized`；
- 比较过程不能通过日志、响应或明显的提前返回时序泄漏 token；
- 省略或空串 `secret` 时不要求 `Authorization`；Controller 不使用 HTTP Basic，顶层 `authentication` 只属于 HTTP/SOCKS5 业务代理。
- `allow-lan` 只控制业务代理监听，不改变 Controller 的监听地址或 Bearer 鉴权。

## `GET /traffic`

授权请求立即返回一次 `application/json` 快照：

```json
{
  "up": 1024,
  "down": 4096,
  "upTotal": 65536,
  "downTotal": 262144
}
```

字段均为非负整数，单位为字节：

- `up`：最近一个完整的一秒窗口内，从宿主 TUN 进入 Vole 的原始 IP 包字节数；
- `down`：最近一个完整的一秒窗口内，由 Vole 写回宿主 TUN 的原始 IP 包字节数；
- `upTotal`：本次 TUN session 的累计上行字节数；
- `downTotal`：本次 TUN session 的累计下行字节数。

Apple utun 的四字节包信息头不计入统计。统计只覆盖跨过 TUN L3 边界的包，包括 TUN DNS 和 ICMP；不重复计算 TLS、XHTTP 或其他代理封装，也不包含 HTTP/SOCKS5 代理入站、GeoData 下载、Controller 请求和 `measureDelay`。

请求不会等待下一次采样，不保持分块响应，不升级 WebSocket，也不为调用方保存“上次读取”状态。首个采样窗口完成前和空闲窗口内，`up`/`down` 为 0；累计值在同一 session 内单调不减并采用饱和语义。没有 TUN 的代理组 Controller 对该路由返回 `404 Not Found`。

TUN 按最多 8 包中有效消费／平台报告成功的包合并记账，取消或错误不会遗漏已经完成的前缀。批次恰好跨越一秒采样边界时，该批字节统一归入记账时的窗口，累计值不受影响；流量快照不是逐包时间戳统计。

## 代理组查询

`GET /group` 按 YAML 声明顺序返回代理组，并在末尾包含自动生成的 `GLOBAL`（如未显式声明）：

```json
{
  "proxies": [
    {
      "name": "main-select",
      "type": "Selector",
      "all": ["edge-a", "fallback-select", "DIRECT", "edge-a"],
      "now": "edge-a"
    }
  ]
}
```

以下两个请求返回同一个组状态对象：

```http
GET /group/{name}
GET /proxies/{name}
```

- `name` 是组定义名，`type` 分别为 `Selector`、`URLTest`、`Fallback` 或 `LoadBalance`；
- `all` 是配置中的直接成员，严格保留顺序和重复项；
- `now` 是当前选中的直接成员名。若该成员是嵌套组，`now` 仍返回组名，不展开为最终叶节点；
- 名称和值大小写敏感并精确匹配，不做大小写折叠或 Unicode normalization。

`GET /proxies` 返回以名称为键的 `proxies` 对象，包含组状态及节点的 `alive/history`。
`GET /proxies/{name}` 也可查询节点。history 当前保留最近一次探测，delay 单位毫秒，
time 为 Unix 秒；未探测节点初始 alive 为 true、history 为空。HTTP 健康状态不声明 UDP 可用性。

load-balance 根据每条新连接的元数据选择成员，响应不含 `now`，不接受手动选择。业务 UDP 按目标会话固定出口。

url-test/fallback 的手动选择在该成员健康时保持固定，失败后恢复自动选择。url-test 使用 tolerance 抑制小幅切换，fallback 按成员顺序选择与恢复。

## 主动探测与内存

`GET /proxies/{name}/delay?url=https%3A%2F%2Fexample.com%2F&timeout=5000&expected=200-299`
通过当前节点或代理组探测 URL，成功返回 `{"delay":12}`，单位毫秒。
`GET /group/{name}/delay` 使用相同 query，返回成功成员的名称到毫秒映射，并清除自动组的手动固定选择。
url-test 组采用配置中的测试 URL，其他组采用请求 URL。
`timeout` 必须传入：节点路由为有符号 16 位毫秒，组路由为有符号 32 位毫秒；非正数立即到期。
`expected` 可省略，或使用现有状态范围语法。未知目标返回 404，无效请求 400，探测超时 504，节点失败或零 delay 503。
HTTP 响应完成时即返回延迟，即使状态不符合 `expected`；该 URL 的健康记录会记为失败。
节点的一般存活状态记录传输是否完成，与配置 URL 的健康状态分开。

`GET /providers/proxies/{name}/healthcheck` 使用 Provider 已配置的健康 URL、timeout 和 expected-status，
完成后返回 204；单个成员失败写入共享健康状态，不使整个响应失败。探测使用当前资源代际、DNS 和出口，
排除业务连接和流量统计，不触碰 lazy 活动时间。主动与自动探测共用每代际 10 个并发槽，停止取消所有等待。
每个节点只保留一份最近手动结果；任意 URL 不增加无界历史。同 URL 的配置探测状态同步更新，供自动组选路使用。

`GET /memory` 返回一次 `{"inuse":123456,"oslimit":null}` 快照：Linux/Android 读取自身 `/proc/self/status` 的 VmRSS，
Apple 使用自身 Mach task resident size，Windows 使用当前进程 working set。单位均为字节；读取失败为 null。
未获取进程内存上限，oslimit 为 null。该路由不提供 Mihomo 的周期流式响应，不启动后台采样；不同平台口径不能直接横比。

## `PUT /proxies/{name}`

切换组的当前直接成员：

```http
PUT /proxies/main-select HTTP/1.1
Authorization: Bearer vole-runtime-secret
Content-Type: application/json
Content-Length: 26

{"name":"fallback-select"}
```

成功返回 `204 No Content` 和空正文。`name` 必须是该组 `all` 中的直接成员；重复名称命中第一项。请求不接受传递成员、数组、索引、CAS/version 或其他字段。

请求正文边界：

- `Content-Type` 必须是唯一且不带参数的 `application/json`；
- 必须有且只有一个十进制 `Content-Length`，不接受 `Transfer-Encoding` 或 chunked；
- 正文最大 1 KiB，读取 header 和 body 各有 5 秒期限；
- JSON 必须是 UTF-8 对象并且恰好包含一个字符串字段 `name`；缺失、未知或重复字段、malformed JSON 和尾随 JSON 都会失败；
- 未知组、未知成员和任何无效请求都不得改变当前选择。

同一组的成功写入是线性化的，最后一个成功提交的请求胜出；不同组独立更新，不提供跨组事务或 CAS。

## 名称与路径

节点和代理组定义名共享一个大小写敏感的命名空间，名称为非空 UTF-8 字符串。保留定义名为 `DIRECT`、`REJECT`、`REJECT-DROP`、`COMPATIBLE`、`PASS` 和 `PASS-RULE`；其中当前可用的内置动作是 DIRECT 与 REJECT。

路径中的 `{name}` 对 percent-encoding 严格解码一次；原始路径分隔符、无效 `%` 和无效 UTF-8 会失败。名称中的 `/`、`?`、`#`、`%` 等字符应 percent-encode；`%252F` 表示字面名称 `%2F`，不会再次解码。`+` 保留为 `+`。请求总大小仍受 HTTP 边界约束。

## 选择生效边界

静态成员来自配置，动态成员随 provider 成功更新；Controller 读取当前可用的成员和选择：

- 新建的物理 TCP 连接使用切换后的当前叶节点；既有 TCP 连接保持原路径；
- 新建 UDP 目标会话使用切换后的当前叶节点；既有目标会话不迁移；
- 新建的 DNS transport 使用切换后的当前叶节点；DNS cache、singleflight 状态和已在池中的 TCP transport 不清空、不迁移；
- 切换不主动断开连接、不刷新缓存、不重启运行时，也不修改 YAML；可按 profile 配置保存选择；
- 选中节点、`DIRECT` 或 `REJECT` 时按原样执行；选中嵌套组时继续解析其当前成员。select 的失败按原样返回；自动组根据探测结果选择后续连接的成员。

`dialer-proxy` 与规则、DNS 共享同一组选择，但经共享连接器直接建链，不重新执行业务规则。上游组的 `DIRECT` 连接当前节点按需解析的服务器，`REJECT` 使建链失败。单次建链对同一组只读取一次选择，SOCKS5 UDP 的控制连接和 relay 路径共享该快照；不同组之间不提供原子快照。已经读取旧选择的在途握手继续原路径。复用旧 AnyTLS 会话的新业务流也保留原路径，只有真正新建底层 transport 才读取新选择。

Hysteria2 已认证 QUIC 会话也保留其 `dialer-proxy` 上游组快照，包括复用该会话的新业务流和端口跳跃所需的新物理 socket；这些不是新的认证会话，不能因切组而迁移原路径。只有重新建立的认证会话才读取新的上游组选择。节点本身作为路由组成员时，后续业务的路由选节点仍按当前组选择执行。

## Provider 资源

`GET /providers/proxies` 与 `GET /providers/rules` 返回 `{"providers":{"name":{...}}}`；
`GET /providers/{proxies|rules}/{name}` 查询单个资源，`PUT` 同一路径主动刷新，成功返回 204。
配置缺失返回 404，下载、解析或候选校验失败返回 503，旧资源继续服务。

状态包含 `name/type/vehicleType`、`available`、`downloaded`、`updating`、`updatedAt`、
`count` 与脱敏的 `error`。`updatedAt` 为 Unix 秒，未成功获取时为空；inline 或 bundled payload
可以在未下载时可用。响应不包含订阅 URL、认证头或节点凭据。

HTTP proxy provider 收到 `Subscription-Userinfo` 后另含 `subscriptionInfo` 对象，
字段为 `Upload`、`Download`、`Total`、`Expire`，均为有符号整数；前三项为订阅字节数，
Expire 为 Unix 秒。未知时省略该对象，缺失子项为 0；不以本地业务流量代替订阅信息。
数值接受十进制整数、有限小数和科学计数法，小数向零截断；非法或超范围子项忽略。
成功候选或合法 304 才更新元信息；未带该头时保留旧值，失败更新保留已发布对象。
缓存恢复只接受与配置 URL 和内容 hash 一致的元信息。

更新将节点、组和规则作为完整候选检查，发布时保留仍存在的当前选择。
既有会话持有旧资源，最后一个使用者释放后回收；下载通过当前可用的运行配置建立出口，
不等待候选资源。空动态组使用配置的 `empty-fallback`，默认 COMPATIBLE（直连）。
组响应另含 `hidden` 与 `icon`，`disable-udp` 会拒绝该组的业务 UDP。

## 业务连接和诊断

`GET /connections` 返回 Mihomo 对应字段 `uploadTotal`、`downloadTotal`、`connections`、
`memory`。业务连接包含 `id`、`metadata`、`upload`、`download`、`start`、`chains`、
`providerChains`、`rule`、`rulePayload`。时间使用 RFC 3339；端口为字符串。

- 只统计 TUN、HTTP、SOCKS5 的业务 TCP/UDP 负载，排除 TUN DNS 拦截、ICMP、Controller、
  Core 资源下载和健康探测。累计值在本次 Running Session 内保留，provider 更新不会重置。
- TCP 为一条业务流，UDP 为同一来源与目标的会话；每个 UDP 目标有独立 transport，
  会话超时、关闭或新的 QUIC flow-id 后重新选择出口。资源代际不会迁移既有会话。
- `chains` 按叶节点到业务路由组排列；当前不展开节点内部的 `dialer-proxy` 协议链。
  `providerChains` 给出这些节点关联的 provider 名称，可与 provider 状态中的脱敏 `error` 对照。
- `metadata` 提供来源、目标、入口、协议、嗅探域名与 `dnsMode`，不查询进程或 ASN。
  扩展字段 `dnsPath` 是当前建链任务实际经过的有界 DNS 阶段标签，例如缓存、policy、
  fallback、fake-IP 与解析角色；不包含上游地址、URL 或认证头。
- 扩展字段 `errors` 最多保留最近 32 次建链/数据报失败的连接信息与固定错误码，
  不返回底层错误原文。`memory` 是本次请求采集的当前进程 resident bytes，不可用时为 null。

连接元数据保存原生地址、端口和时间，重复的节点、组及规则文本共享存储。
查询只在短锁内取得连接引用，再固定计数和 DNS 路径并直接序列化；快照不保活
业务 I/O 或资源代际。字节计数即时饱和累计，零字节 I/O 不更新计数。

`DELETE /connections/{id}` 取消指定连接，`DELETE /connections` 取消当前全部连接。
均返回 204，未知 ID 同样返回 204；取消唤醒正在等待的 I/O 并释放对应流资源。
这不禁止用户重新建连，也不重置累计流量。正常 stop 会取消全部连接并沿既有停止屏障回收。

`GET /rules` 返回 `rules` 数组，包括规则索引、类型、payload、目标及命中次数和最后命中时间。
计数属于当前资源代际，只记录业务的新选路，不将每个 UDP 包重复计为一次选路。
没有采集未命中次数、GeoData 记录大小；`size` 为 -1。规则列表反映当前有效路由模式。

`GET /configs` 返回归一化后的运行设置：mixed 入口、mode、log-level、IPv6、sniffing、
连接选项、profile 和 TUN 字段。它使用字段白名单，不提供完整 YAML、节点凭据、订阅位置、
认证头、Controller secret 或认证用户列表；不支持 PUT/PATCH 配置修改。

`GET /dns/query?name=example.com&type=A` 使用当前上游 resolver 与相同缓存查询；支持 A/AAAA，
省略 type 使用 A。响应包含 `Status/Question/Answer/TC/RD/RA/AD/CD` 和扩展 `QueryPath`。
与 Mihomo 一样，此诊断接口跳过入口的 hosts、fake-IP 与 IPv6 响应过滤，返回上游真实答案；
policy 与 fallback 仍生效。DNS 关闭或查询失败返回 500。这里只输出地址/CNAME 答案，
不提供其他 qtype、Authority/Additional 展开或后台 DNS 查询日志。

这些接口复用 Controller 的 Bearer 鉴权。目标与 DNS 路径只通过显式查询返回，
不会写入普通日志。`/connections` 是业务负载统计，`/traffic` 继续表示 TUN 原始 IP 包流量，
`/proxies` 的节点健康数据继续表示探测结果，三者不可相互替代。

`POST /cache/dns/flush` 清除当前资源代际所有 DNS 角色的普通地址、负响应、原始响应缓存和
域名提示，成功返回 204；DNS 未启用时同样返回 204。旧在途查询可以完成，但不能回填
清理后的缓存，新查询不会复用这些旧查询。fake-IP 映射和活动业务会话保留。

## HTTP 状态与协议边界

| 状态 | 含义 |
| --- | --- |
| `200 OK` | 查询成功，返回 `application/json` |
| `204 No Content` | 选择、刷新或清理成功，正文为空 |
| `400 Bad Request` | 路径、JSON、长度格式或成员无效 |
| `401 Unauthorized` | Bearer 鉴权失败 |
| `404 Not Found` | 路由、组或当前 session 中的 TUN 流量资源不存在 |
| `405 Method Not Allowed` | 路由存在但方法不允许 |
| `408 Request Timeout` | header 或 body 读取超时 |
| `411 Length Required` | PUT 缺少 `Content-Length` |
| `413 Payload Too Large` | PUT 正文超过 1 KiB |
| `415 Unsupported Media Type` | PUT 不是严格 `application/json` |
| `503 Service Unavailable` | 探测或资源更新失败 |
| `504 Gateway Timeout` | 主动探测超时 |

当前不提供配置修改、WebSocket 推送、Controller 版本协商或完整 Dashboard response。除本文列出的连接、规则、配置、DNS、主动探测、内存和 provider 路由、`GET /proxies`、`GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}` 外，其他路径和方法均不属于公共协议。

Windows WinRT VPN 的完整运行时和 Controller 位于独立 Session Host；桌面 Wintun 的
Controller 位于普通业务运行时。宿主通过配置的 HTTP 地址直接访问实际 Running Session；
组查询和切换不经过 `VoleInvoke`、Windows bridge 或 Provider 控制管道，
不携带 `instanceId`，也不占用 Invoke 命令锁。
