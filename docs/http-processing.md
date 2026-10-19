# HTTP 处理

独立 HTTP 配置作用于 TUN 和 mixed-port 的业务 TCP。Core 的 DNS、provider、GeoData、节点握手及 Controller 不进入业务重写。主代理配置仍使用 Mihomo YAML。

## 配置与资源

`httpConfigYaml` 使用单份 YAML 文档。未知字段、旧格式、重复键、类型错误及 `null` 冒充省略值均拒绝。四个顶层字段均可省略：

```yaml
http-ports: [80, 8080]
rewrite-providers: {}
rewrite:
  enabled: false
  rules: []
mitm:
  enabled: false
  ports: [443]
  domains: []
  exclude-domains: []
```

端口有效且不可重复。`rewrite.enabled` 控制真实执行，关闭仍校验直接规则与 inline 内容；规则和引用的 `enabled` 默认 true。关闭引用不读取来源。MITM 为独立本机授权，远程规则不能扩大它。

```yaml
rewrite-providers:
  local: {type: file, path: ./rules/local.yaml}
  remote:
    type: http
    url: https://rules.example.com/http.yaml
    path: ./rewrite-cache/remote.yaml
    interval: 86400
    header:
      Authorization: ['Bearer example-token']
  builtin:
    type: inline
    payload:
      - {url: 'https://example.com/debug', match: exact, action: reject}
rewrite:
  enabled: true
  rules:
    - {url: 'http://old.example/v1/', match: prefix, action: replace, replacement: 'https://new.example/v2/'}
    - {rule-set: local}
    - {rule-set: remote}
    - {rule-set: builtin, enabled: false}
```

file 只接受必填 `path`；inline 只接受必填 `payload`；http 接受必填 `url` 和可选 `path`、`interval`、多值 `header`。外部文件只有 `payload`，与本机直接规则同形，不能嵌套引用或携带本机授权／CA。按引用位置展开，不允许重复引用或未知名称。

file 相对路径锚定宿主提供的 HTTP 文件目录，HTTP 缓存锚定初始化的数据目录；缓存不能与主文件、源文件或其他缓存冲突。URL 与规范化请求头绑定来源；认证变化不能借用旧缓存。304 要求完整有效的同来源内容。全部来源及总体编译通过后，才提交缓存与完整待应用候选；失败保留旧内容。

file 在显式准备时读取；http 的 interval 默认 86400 秒，0 只关闭周期更新。准备与下载使用底层资源路径，不经过本次 HTTP 业务处理。

当前工程上限为主文档与实际外部内容合计 1 MiB、展开规则 64 条、选择器／搜索各 2 KiB、非正文规则文本合计 64 KiB、单个 URL 结果 8 KiB。正则编译与 DFA 缓存分别限 128／64 KiB；YAML 别名、模板输出及并行准备也受限。超限失败，不截断规则；这些准入上限不代表进程 RSS。

## URL 阶段

规则共有必填 `url`、`action`，可选 `match`、`enabled` 和展示用 `name`。`match` 为 regex（默认）、exact 或 prefix，不根据文本猜测。URL 动作为 replace、redirect302、redirect307、reject；前三者必须有 replacement，reject 不接受替换参数。

`replacement-mode` 默认 match：exact 替换整个 URL，prefix 保留后缀，regex 仅替换首个匹配片段。显式 url 使用整个展开结果。prefix 只在无查询的 replacement 以 `/` 结尾、后缀也以 `/` 开头时去掉一个边界斜杠，不拼接路径或合并查询。

正则模板支持 `$0`、`$N`、`${N}`、`${name}`、`$$`，不支持 `$name`；未知捕获加载失败，可选未参与捕获为空。字面模式不展开捕获。仅接受合法绝对 HTTP(S) URL，拒绝 userinfo、fragment、端口 0、控制／空白字符和反斜杠。离线输入 trim 并去掉 fragment；配置目标不允许 fragment。

所有阶段按原始规范化 URL（U0）筛选。URL 动作首条命中产生 U1，不递归。非法生成目标本地返回空 502；redirect 与 reject 本地结束，不访问原站，reject 为空 403。相同 origin 的路径／查询改写保留已选 IP；跨 origin 重选路、重建 authority，先清理收到的 Authorization／Cookie。原始目标与入口身份保留。

## 选择性 HTTPS

```yaml
mitm:
  enabled: true
  domains:
    - {pattern: private.example}
    - {pattern: '*.example.net', enabled: true}
  exclude-domains:
    - {pattern: excluded.example.net}
  ports: [443]
```

域名项只有 pattern 和默认 true 的 enabled。支持精确名称及 `*.suffix` 子域匹配，后者不包含域本身；启用排除项优先，关闭项仍校验。开启要求有效允许域名、端口及匹配的有效 CA／私钥。关闭不构造 CA；宿主提供独立私密输入，规则、payload 和普通快照不承载私钥。

只终止允许的 SNI／端口；无 SNI、ECH（含 GREASE）、未授权名称和 UDP／QUIC 保持透明。每个原始 HTTP authority 独立授权，同一 H2 连接不扩大权限。最终上游按实际目标验证证书，使用受保护出口；不通过关闭验证处理 pinning 或客户端证书要求。

H1 上游协商 HTTP/1.1，H2 下游对接实际协商的 H2 或 H1。普通 H2 CONNECT 返回 405；WebSocket 使用 H1 Upgrade。叶证书最多 32 项、材料预算 256 KiB、空闲 10 分钟，有效期不超过 24 小时或 CA。

H2 每连接最多 8 个活动请求，流／连接接收窗口 32／64 KiB，头最多 32 KiB／100 字段，帧 16 KiB，关闭动态 HPACK 表。上游不跨请求复用。上传使用 30 秒无进展期限；上传完成后响应头另有 30 秒等待期限，提前响应仍与上传并发。取消和 Stop 覆盖上下游、正文与驱动。

当前会话固定主设置、实际 payload、授权和 CA。保存／资源刷新只产生待应用候选，节点选择和分流更新继承 active。显式重连准备候选后切换，后续启动失败使用旧实际内容恢复，不重读已变化文件；普通 Stop 释放私密材料。共享入口见 [Invoke API](invoke-api.md) 与 [CLI](cli.md)。
