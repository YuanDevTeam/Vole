# HTTP 处理

独立 HTTP 配置作用于 TUN 和 mixed-port 的业务 TCP。Core 的 DNS、provider、GeoData、节点握手及 Controller 不进入业务重写。主代理配置仍使用 Mihomo YAML。

SOCKS5 CONNECT、普通 HTTP 代理请求、HTTP CONNECT 和 TUN TCP 使用同一处理实现。
明文按原始目标端口与 `http-ports` 准入；普通 HTTP 不因目标端口在 `mitm.ports` 而切换为
TLS 隧道。SOCKS5/CONNECT 的候选流先确认代理握手，再读取业务数据；未识别或未获 MITM
授权时，已读字节完整回放后继续嗅探/选路。连接沿固定 HTTP 资源代际执行，原始入口类型和
认证身份不变。UDP/QUIC 不进入此 HTTP 处理路径。

主配置 sniffer 与独立 HTTP 处理分别准入。关闭 sniffer、协议端口不匹配或命中其排除项，
不会自动关闭已显式授权的 HTTP rewrite/MITM；嗅探得到域名也不能扩大 MITM 授权。
普通 HTTP 每请求重新检查端口、执行规则并选路；离开处理端口时退役该下游此前保留的处理上游。

明文 H1 在改写前对原始 authority 复用主配置的嗅探准入、HTTP 端口、force/skip 与目标覆盖策略；关闭或排除时不隐式补域名，`override-destination: false` 只提供选路提示并保留已选 IP，HTTPS 仍沿固定 SNI 和逐 authority 授权。

## 配置与资源

`httpConfigYaml` 使用单份 YAML 文档。未知字段、旧格式、重复键、类型错误及 `null` 冒充省略值均拒绝。五个顶层字段均可省略：

```yaml
http-ports: [80, 8080]
rewrite-providers: {}
rewrite:
  enabled: false
  rules: []
http-scripts:
  enabled: false
  scripts: []
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

## 内联 HTTP 脚本配置

`http-scripts.enabled` 独立于 `rewrite.enabled`，默认 false；`scripts` 默认为空列表。每项必填 `name`、`phase`、`url` 和内联 `source`；`phase` 仅 request/response，`match` 默认 regex，可为 exact/prefix，`body` 默认 none，可为 text/bytes。名称不能为空或包含控制字符。选择器使用原始规范化 URL，按声明顺序执行所有匹配项；仅脚本启用时也可进入配置的 HTTP 端口，不要求原生规则非空。

```yaml
http-scripts:
  enabled: true
  scripts:
    - name: tag-request
      phase: request
      url: 'https://api.example/'
      match: prefix
      body: none
      source: |
        function rewrite(input) {
          return {
            type: "modify",
            headers: [{op: "set", name: "x-vole", values: ["1"]}]
          };
        }
```

脚本只能在本机文档中内联声明。rewrite provider 只携带原生规则。静态校验始终检查脚本 schema、选择器和 AST，包括关闭总开关时。启用脚本的实际会话准备会校验执行后端，当前后端可用性限于 Apple。初始化只处理受信任的运行库，用户脚本在命中业务请求或响应时执行。

脚本声明最多 64 项，名称与选择器合计不超过 64 KiB，选择器沿用每项 2 KiB 和原生正则编译预算；内联源码计入已有的 1 MiB 文档/实际资源总上限。未知字段、空值冒充省略值、无效 AST 或超限均拒绝整个候选，不截断。实际 source、声明与编译结果随 HTTP 会话候选固定，资源刷新或后续编辑不改变正在运行的脚本。

源码必须定义唯一同步入口 `function rewrite(input) { ... }`。当前语法支持 let/const、if/else、return、普通 for/while/do-while、无标签 break/continue、普通对象和稠密数组、成员读取/简单赋值、局部变量自增减及赋值运算、条件/逻辑表达式与原始值的有限算术比较。对象不会被隐式转换成字符串或数字。静态 AST 检查遍历最多 16,384 项、递归深度 128；未知语法明确拒绝，不用字符串过滤代替语法解析。

AST 解析前检查词法复杂度。局部变量使用未转义的 ASCII 标识符。

工具调用只开放 `String/Number/Boolean` 的单参数原始值转换，`JSON.parse/stringify`，`Object.keys/values/entries`，`Array.isArray`，`Number.isFinite/isInteger`，`Math.abs/floor/ceil/round/trunc/min/max` 和 `Uint8Array.from`。字符串可用 slice/substring/charAt/at/includes/startsWith/endsWith/indexOf/lastIndexOf/trim/toLowerCase/toUpperCase/split/replace/replaceAll；replace 的搜索参数只接受字符串，保留 JavaScript 字符串替换模板语义。数组可用 push/pop/slice/concat/join/indexOf/includes/reverse/at，Uint8Array 另支持 subarray。工具拒绝用户回调和隐式对象转换，输出在分配或导出前受大小、结构和工作预算检查。

不支持 import/export、额外函数或闭包、递归、async/await/Promise、class/new、try/catch/throw、正则字面量、模板字面量、解构、spread、可选链、动态函数调用和属性自增/复合赋值。不能访问 eval、constructor、prototype、原型链修改入口或内部执行工具；不提供文件、网络、KV、通知、timer、DOM 或平台对象。普通 JS JSON Number 与重复键行为不等于原生无损 JSON Patch。

输入含 `phase`、只读原始 URL/方法、当前 request、response 阶段的当前 response，以及本次声明选择的 body。headers 是保留同名多值顺序的 `{name,value}` 序列，不承诺 H2 的原始完整线序。none 的 body 为 not-requested；text 是严格 UTF-8 字符串，bytes 是完整解码实体的 Uint8Array，空正文与未提供正文不同。输入修改不直接提交；不能无损构造字符串 header 快照时跳过调用，不丢字段或有损替换。

返回值必须是普通有限数据记录：`{type:"pass"}` 保留输入，modify 可包含 url/method/status/headers/body，respond 以 status、初始 headers 和正文生成完整本地响应，`{type:"abort"}` 关闭当前 H1 交换或 reset 当前 H2 流。modify 的 headers 只能是有序 set/add/remove 操作，set/add 的 values 是非空字符串数组；respond 的 headers 是初始 `{name,value}` 序列。响应阶段不能改 URL/方法，请求阶段不能改 status。未知字段、undefined/null/Promise、accessor、自定义 toJSON、非有限数、孤立 surrogate、共享/循环结果和非法字节载荷均使整次调用失败。

普通请求 method 可改合法 token，但不允许涉及 HEAD/CONNECT 的方法转换；OPTIONS `*` 的请求脚本只提供 none，modify 只改普通 headers。普通完整响应 status 可在 200..599 之间变更；204/205/304/206 或带 Content-Range 的响应不变更 status，普通响应也不能改成这些特殊状态。respond 不生成 1xx/101/206 或 Content-Range；HEAD、204/205/304 不允许非空实体。framing、Host、Content-Encoding 等协议字段仍由 Core 管理；JS 另不能写代理认证字段。每次结果最多 100 个 header 操作/初始字段、100 个 set/add 值，控制字段按现有开销算法累计最多 32 KiB。

混用顺序固定为原生 URL → 原生 request header/body → request JS → 最终目标规划与上游转发 → 原生 response header/body → response JS → Core 校验发送；全部选择器继续使用原始 URL。JS 按声明顺序串行累计，失败只回到该次输入，保留原生和前序脚本结果；跨 origin 先清继承的 Authorization/Cookie，回退不恢复前序已清理凭据。respond/abort 终止后续链，本地响应不再递归执行 response 脚本。

原生与 JS 共用 256 KiB 单份实体和 4 MiB 非等待正文账本，桥接实际副本与输出也计费；没有正文需求不缓冲全文。原生正文继续使用 UTF-8 资格与事务；bytes 模式不要求 UTF-8，但保留 HEAD/无体/部分响应、流式、trailer 和原始协商排除。JS text 变化输出 UTF-8 identity，bytes 变化输出 binary identity，不自动追加 UTF-8 charset；无变化保留该次输入表示。正文不可用时跳过要求正文的脚本，none 仍可执行。

Apple 后端对可证明等价的闭合脚本使用静态执行计划，其余受支持的脚本使用独立 JavaScriptCore 上下文。两条分支执行相同的事务、期限与资源准入规则。调用内对输入对象的修改仍需经结果校验才能应用。

单次调用的期限为 100 ms（包含排队），最多 100,000 次受控 tick。请求和响应 JS 阶段各有 1 秒总期限，正文收集与传输使用各自的期限。取消及超时后的回收等待同步操作和实际执行 owner 结束；2 MiB 的累计分配工作预算约束执行工作量。正文许可随实际输入、输出、桥接副本和发送引用持有至最后一次释放。

## 编译期诊断

启用非默认构建功能 `http-diagnostics` 后，可通过 [Invoke](invoke-api.md#gethttpdiagnostics仅-http-diagnostics-构建) 读取 HTTP、脚本与 TUN 的进程级计数。活动工作、累计量与峰值分开解释。通过真实 Stop 和 owner 退出后的静止快照核对资源释放。脚本计量区分静态 Plan 与 JavaScriptCore；设备或性能验收使用实际测试窗口。

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

只有被正文规则选中的消息才缓冲。原始、解码、中间和最终正文各限 256 KiB；进程共享 4 MiB 正文工作区，包含 JSON 与 codec 临时空间。先预留再分配，无额度直接旁路；发送期间保留额度。未知长度最多探测上限加一字节，超限按原实体字节回放已读前缀和余下数据，不截断。传输中断、超时和取消仍是错误，不能假装完成。

符合正文条件的消息在限额内收集一次，原生规则和脚本共用工作区。收集或解码失败时回放原始消息，传输失败按真实错误处理。发送切片保留实际缓冲区的预算占用。

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

MITM 支持 HTTP/1.1 与 HTTP/2。HTTP/3 MITM 暂不支持；UDP／QUIC（含 H3）按原字节透明转发，不进入 URL/header/body rewrite，也不通过阻断 QUIC 强制客户端回落。

只终止允许的 SNI／端口；无 SNI、ECH（含 GREASE）和未授权名称保持透明。每个原始 HTTP authority 独立授权，同一 H2 连接不扩大权限。最终上游按实际目标验证证书，使用受保护出口；不通过关闭验证处理 pinning 或客户端证书要求。

下游 rustls 写侧缓冲使用统一 TLS 默认值 64 KiB；这是 HTTP 上下文的固定默认策略，不接收节点或低层调用者的容量覆盖。它与 TUN 发送缓冲、H2 窗口及 4 MiB 正文账本分别计量；正文许可继续持有至实际发送 owner 释放，TLS 局部容量不代表进程 physical footprint。

H1 上游协商 HTTP/1.1，H2 下游对接实际协商的 H2 或 H1。普通 H2 CONNECT 返回 405；WebSocket 使用 H1 Upgrade。叶证书最多 32 项、材料预算 256 KiB、空闲 10 分钟，有效期不超过 24 小时或 CA。

## 业务上游复用

同一下游连接可保留一个可接收新请求的 H1 上游或 H2 会话。每个请求仍需独立授权、改写并按最终目标选路。复用要求最终 origin、资源代际、入口上下文及完整静态连接器身份一致。HTTPS 还要保持整个改写链的原 origin，并通过最终目标的证书、SNI 和 ALPN 校验。跨 origin 或 scheme 的请求建立独立上游，即使后续再次改回。

- **H1** 要求持久的 HTTP/1.1、空正文或固定长度请求，以及原始响应的完整 Content-Length 消费。HEAD、CONNECT、`OPTIONS *`、Expect、Upgrade、分块与 trailer 使用独立交换。早响应、未完整上传、关闭、截断或传输错误会退役上游；已发送请求的失败按原错误返回。
- **H2** 要求实际协商 HTTP/2。空正文可随 HEADERS 发送 END_STREAM，其余上传在实际正文、trailer 和 END_STREAM 完成后才算完整。早响应、上传失败及停止可使上游退役。复用时如果在提交请求前观察到远端 GOAWAY，旧连接停止准入，当前请求沿已选路由和原连接期限拨号一次。已在途请求继续持有原 driver 至结束。已提交请求按原错误路径处理。单次路径有独立的上游所有权。
- **H2 局部上限**为每个下游连接 8 个活动请求，流及连接接收信用各 64 KiB，头 32 KiB／100 字段，帧 16 KiB，动态 HPACK 表关闭。下游每流响应发送容量为 64 KiB，每次最多提交 16 KiB；上游发送容量为 16 KiB。上传以 30 秒无进展为限，完成后另等待响应头至多 30 秒。共享正文预算延续至最后发送引用释放。

固定连接器资格由实际出站图提供。动态策略组、未知上游路径、会改变安全身份的外部资源以及已停止的节点走单次路径。VLESS 的上传、下载腿分别校验其真实 TCP 或 UDP 载体；在 macOS 上，`mptcp: true` 沿用普通 TCP 路径。各协议的静态端点、安全身份和封装限制见 [出站契约](outbounds.md)、[VLESS](vless.md) 和 [XHTTP](xhttp.md)。保留的业务连接继续拥有其协议逻辑流和租约，直到退役、下游结束或 Stop。

## 会话边界

运行会话固定主设置、实际 payload、脚本、授权和 CA。保存与资源刷新产生待应用候选，节点选择和分流更新沿用运行中的 HTTP 资源。显式重连先准备候选再切换，失败恢复原会话的实际内容。普通 Stop 释放私密材料。[Invoke API](invoke-api.md#独立-http-设置与私密上下文) · [CLI](cli.md) · [离线回归](../tests/README.md#http-处理与-invoke)
