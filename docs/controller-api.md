# 运行时 Controller API

Controller 是当前 Running Session 的回环 HTTP 接口。它提供一次性 TUN 流量快照，以及静态与动态 `select` 代理组的状态查询和实时选择；它不是 Invoke API，也不承诺完整 Mihomo Dashboard 兼容。

## 配置与生命周期

```yaml
external-controller: 127.0.0.1:9090
secret: "vole-runtime-secret"
```

- 省略 `external-controller` 表示不启动 Controller，此时不能单独配置 `secret`。含代理组但没有 Controller 的配置合法，组在本次 session 内保持初始选择。
- `external-controller` 只接受带显式非零端口的回环 IP 地址。它要求启用 TUN 或至少显式定义一个 `proxy-groups`；非 TUN 配置须通过 `mixed-port` 满足运行配置的入站要求。
- 只要同时显式配置代理组与 Controller，`secret` 就必填；仅有 TUN 流量接口时可省略。`secret` 出现时必须为 1–255 UTF-8 字节，并保护本文定义的全部路由。
- `measureDelay` 的 node-only 配置不能包含 Controller 或代理组字段。
- `validateConfig` 只校验字段；`prepare` 不监听端口；`start` 绑定端口，绑定失败则启动失败。`stop` 和 `destroyInstance` 关闭监听器。

Controller 与公共运行时 session 同生共灭。代理组选择只保存在 Vole 当前 session 的内存中；Vole 不写回配置。宿主如需跨 session 保留选择，必须自行持久化，并在下次 `configYaml` 中提供对应的 `default-selected`。

## Bearer 鉴权

配置 `secret` 后，每个请求都必须携带：

```http
Authorization: Bearer vole-runtime-secret
```

要求：

- scheme 必须精确为 `Bearer`，token 必须与当前 session 配置完全一致；
- 缺失、重复、格式错误或不匹配都返回 `401 Unauthorized`；
- 比较过程不能通过日志、响应或明显的提前返回时序泄漏 token；
- 未配置 `secret` 时不要求 `Authorization`；Controller 不使用 HTTP Basic，顶层 `authentication` 只属于 HTTP/SOCKS5 业务代理。
- `allow-lan` 只控制业务代理监听，不改变 Controller 的回环限制或 Bearer 鉴权。

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

- `name` 是组定义名，`type` 固定为 `Selector`；
- `all` 是配置中的直接成员，严格保留顺序和重复项；
- `now` 是当前选中的直接成员名。若该成员是嵌套组，`now` 仍返回组名，不展开为最终叶节点；
- 名称和值大小写敏感并精确匹配，不做大小写折叠或 Unicode normalization。

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
- 新建的 UDP association/物理 transport 使用切换后的当前叶节点；既有 association 不迁移；
- 新建的 DNS transport 使用切换后的当前叶节点；DNS cache、singleflight 状态和已在池中的 TCP transport 不清空、不迁移；
- 切换不主动断开连接、不刷新缓存、不重启运行时，也不修改 YAML 或下一次 session 的默认值；
- 选中节点、`DIRECT` 或 `REJECT` 时按原样执行；选中嵌套组时继续解析其当前成员。失败按原样返回，不自动选择其他成员。

`dialer-proxy` 与规则、DNS 共享同一组选择，但经共享连接器直接建链，不重新执行业务规则。上游组的 `DIRECT` 连接当前节点按需解析的服务器，`REJECT` 使建链失败。单次建链对同一组只读取一次选择，SOCKS5 UDP 的控制连接和 relay 路径共享该快照；不同组之间不提供原子快照。已经读取旧选择的在途握手继续原路径。复用旧 AnyTLS 会话的新业务流也保留原路径，只有真正新建底层 transport 才读取新选择。

Hysteria2 已认证 QUIC 会话也保留其 `dialer-proxy` 上游组快照，包括复用该会话的新业务流和端口跳跃所需的新物理 socket；这些不是新的认证会话，不能因切组而迁移原路径。只有重新建立的认证会话才读取新的上游组选择。节点本身作为路由组成员时，后续业务的路由选节点仍按当前组选择执行。

## Provider 资源

`GET /providers/proxies` 与 `GET /providers/rules` 返回 `{"providers":{"name":{...}}}`；
`GET /providers/{proxies|rules}/{name}` 查询单个资源，`PUT` 同一路径主动刷新，成功返回 204。
配置缺失返回 404，下载、解析或候选校验失败返回 503，旧资源继续服务。

状态包含 `name/type/vehicleType`、`available`、`downloaded`、`updating`、`updatedAt`、
`count` 与脱敏的 `error`。`updatedAt` 为 Unix 秒，未成功获取时为空；inline 或 bundled payload
可以在未下载时可用。响应不包含订阅 URL、认证头或节点凭据。

更新将节点、组和规则作为完整候选检查，发布时保留仍存在的当前选择。
既有会话持有旧资源，最后一个使用者释放后回收；下载通过当前可用的运行配置建立出口，
不等待候选资源。空动态组使用配置的 `empty-fallback`，默认 COMPATIBLE（直连）。
组响应另含 `hidden` 与 `icon`，`disable-udp` 会拒绝该组的业务 UDP。

## HTTP 状态与协议边界

| 状态 | 含义 |
| --- | --- |
| `200 OK` | 查询成功，返回 `application/json` |
| `204 No Content` | 选择成功，正文为空 |
| `400 Bad Request` | 路径、JSON、长度格式或成员无效 |
| `401 Unauthorized` | Bearer 鉴权失败 |
| `403 Forbidden` | 请求来源不是回环地址 |
| `404 Not Found` | 路由、组或当前 session 中的 TUN 流量资源不存在 |
| `405 Method Not Allowed` | 路由存在但方法不允许 |
| `408 Request Timeout` | header 或 body 读取超时 |
| `411 Length Required` | PUT 缺少 `Content-Length` |
| `413 Payload Too Large` | PUT 正文超过 1 KiB |
| `415 Unsupported Media Type` | PUT 不是严格 `application/json` |

当前不提供 health check、自动 failover、`url-test`/`fallback`/`load-balance`、delay 测试、连接管理、配置修改、WebSocket 推送、Controller 版本协商或完整 Dashboard response。除本文列出的 provider 路由、`GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}` 外，其他路径和方法均不属于公共协议。

Windows WinRT VPN 的完整运行时和 Controller 位于独立 Session Host；桌面 Wintun 的
Controller 位于普通业务运行时。宿主通过回环 HTTP 直接访问实际 Running Session；
组查询和切换不经过 `VoleInvoke`、Windows bridge 或 Provider 控制管道，
不携带 `instanceId`，也不占用 Invoke 命令锁。
