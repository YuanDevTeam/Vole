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

HTTP 处理需要编译启用 `inbound-http`。缺少该能力时，非空 HTTP 配置在静态校验时拒绝，不读取 provider 或私密 CA；省略或空输入仍表示不启用。

## URL 阶段

规则共有必填 `url`、`action`，可选 `match`、`enabled` 和展示用 `name`。`match` 为 regex（默认）、exact 或 prefix，不根据文本猜测。URL 动作为 replace、redirect302、redirect307、reject；前三者必须有 replacement，reject 不接受替换参数。

`replacement-mode` 默认 match：exact 替换整个 URL，prefix 保留后缀，regex 仅替换首个匹配片段。显式 url 使用整个展开结果。prefix 只在无查询的 replacement 以 `/` 结尾、后缀也以 `/` 开头时去掉一个边界斜杠，不拼接路径或合并查询。

正则模板支持 `$0`、`$N`、`${N}`、`${name}`、`$$`，不支持 `$name`；未知捕获加载失败，可选未参与捕获为空。字面模式不展开捕获。仅接受合法绝对 HTTP(S) URL，拒绝 userinfo、fragment、端口 0、控制／空白字符和反斜杠。离线输入 trim 并去掉 fragment；配置目标不允许 fragment。

所有阶段按原始规范化 URL（U0）筛选。URL 动作首条命中产生 U1，不递归。非法生成目标本地返回空 502；redirect 与 reject 本地结束，不访问原站，reject 为空 403。相同 origin 的路径／查询改写保留已选 IP；跨 origin 重选路、重建 authority，先清理收到的 Authorization／Cookie。原始目标与入口身份保留。

## Header 与正文

`request-header-set/add/remove/replace` 和 `response-header-set/add/remove/replace` 按规则顺序累计执行。`header` 为字段名；set/add 必须有字面 `value`，remove 不携带值，replace 使用 `search` 与 `replacement`。多值字段逐项处理；set 覆盖原值，add 追加独立值。协议控制字段、Connection 提名字段不能修改。阶段失败时整个 header 阶段回退；跨 origin 清理旧凭据后，规则可明确设置新的 Authorization／Cookie。

正文动作是 `request-body-set/replace/json-patch` 和对应的 `response-body-*`。set 使用 UTF-8 字面 `value`，包含空字符串；replace 使用 `search`、`replacement`。`search-mode` 默认 literal，可选 regex；`occurrences` 默认 all，可选 first。只有 regex search 的替换展开其自身捕获，其他值不展开 URL 捕获。所有正文操作按序执行，一条失败则整个正文阶段原文旁路，保留独立 header 阶段的成功修改。

```yaml
rewrite:
  enabled: true
  rules:
    - {url: 'https://api.example/v1/', match: prefix, action: request-header-set, header: X-Client, value: Vole}
    - url: 'https://api.example/v1/settings'
      match: exact
      action: response-body-json-patch
      patch:
        - {op: add, path: /enabled, value: true}
        - {op: replace, path: /message, value: ready}
    - {url: 'http://example.com/', match: prefix, action: response-body-replace, search: old, replacement: new}
```

JSON Patch 支持 RFC 6902 的 add/remove/replace/move/copy/test 和 RFC 6901 Pointer；`value` 可为真正的 null、布尔、数值、字符串、数组、对象。配置数值必须能无损转换，不能静默舍入；业务 JSON 保留数值原文并拒绝重复键。空 patch 不触发解析或重新编码。非法 JSON、Pointer 或失败的 test 导致整个正文阶段原样旁路。

只有被正文规则选中的消息才缓冲。原始、解码、中间和最终正文各限 256 KiB；进程共享 2 MiB 正文工作区，包含 JSON 与 codec 临时空间。先预留再分配，无额度直接旁路；发送期间保留额度。未知长度最多探测上限加一字节，超限按原实体字节回放已读前缀和余下数据，不截断。传输中断、超时和取消仍是错误，不能假装完成。

支持 identity、gzip、deflate、br；按收到的 Content-Type、charset、Content-Encoding 和原始请求 Accept-Encoding 判断资格。改写后使用 UTF-8 identity，修正长度与表示元数据并删除失效的校验／签名字段。没有实际改动时保留原始编码表示。未知编码、非法文本、压缩校验失败或预算不足均整阶段原文旁路。

HEAD、无正文状态、206/Content-Range、CONNECT、Upgrade、SSE、gRPC、multipart 及带 trailer 的消息不做正文改写，普通 header 规则仍可执行。选中正文的 H1 Expect: 100-continue 在读取前完成握手；未匹配消息保持原有流式背压、早响应和半关闭语义。H1/H2 与成功解密的 HTTPS 共用规则与预算。

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
