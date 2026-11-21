# HTTP 处理

独立 HTTP 配置作用于 TUN 和 mixed-port 的业务 TCP。Core 的 DNS、provider、GeoData、节点握手及 Controller 不进入业务重写。主代理配置仍使用 Mihomo YAML。

SOCKS5 CONNECT、普通 HTTP 代理请求、HTTP CONNECT 和 TUN TCP 使用同一处理实现。
明文候选端口从 HTTP origins 得出，解析请求后按原始 origin 匹配。普通 HTTP 代理请求始终按明文处理。SOCKS5/CONNECT 的候选流先确认代理握手，再读取业务数据。未识别或未获 MITM
授权时，已读字节完整回放后继续嗅探/选路。连接沿固定 HTTP 资源代际执行，原始入口类型和
认证身份不变。UDP/QUIC 只参与 H3 回退识别，正文处理走 TCP 上的 HTTP。

主配置 sniffer 与独立 HTTP 处理分别准入。关闭 sniffer、协议端口不匹配或命中其排除项，
不会自动关闭已显式授权的 HTTP rewrite/MITM；嗅探得到域名也不能扩大 MITM 授权。
普通 HTTP 每请求重新检查端口、执行规则并选路；离开处理端口时退役该下游此前保留的处理上游。

明文 H1 在改写前对原始 authority 复用主配置的嗅探准入、HTTP 端口、force/skip 与目标覆盖策略；关闭或排除时不隐式补域名，`override-destination: false` 只提供选路提示并保留已选 IP，HTTPS 仍沿固定 SNI 和逐 authority 授权。

## 插件 YAML

CLI 与 App 提交同一份插件原文。单份用 `httpConfigYaml`，多份用有序的 `httpConfigYamls`，CLI 可重复传 `-http-config`。Core 按文档、目标组、规则顺序执行。订阅下载、授权、启停、原文缓存和导出由宿主管理。插件 YAML 只定义自身的目标和操作，运行开关与 CA 由本机提供。

```yaml
name: Example API Rewrite
targets:
  - origins:
      - http://api.example.com:8080
      - https://api.example.com:8443
    rules:
      - match:
          method: GET
          path-prefix: /v1/
        request:
          headers:
            - set: {x-vole-client: example-api}
        response:
          headers:
            - set: {cache-control: no-store}
          js:
            body: none
            source: |
              function rewrite(input) {
                if (input.response.status !== 200) {
                  return {type: "pass"};
                }
                return {
                  type: "modify",
                  headers: [{op: "set", name: "x-vole-rewrite", values: ["example-api"]}]
                };
              }
```

- `name` 是可选显示名。`targets` 中每组必须声明 `origins`。每个 origin 绑定协议、主机和端口。省略端口时 HTTP 为 80、HTTPS 为 443。HTTPS 使用 DNS 名，HTTP 可使用字面 IP。origin 使用 `scheme://host[:port]`。`https://*.cdn.example.com:8443` 匹配该端口的一层及多层子域。根域须单列。通配只接受完整左侧 `*.` 标签和带可注册域的 DNS 后缀。按 IDNA、大小写和尾点规范化后检查同组重复。
- `rules` 按声明顺序执行。省略 `match` 时匹配组内全部请求。`path-exact` 和 `path-prefix` 匹配原始 URL 路径，`url-regex` 匹配原始规范化完整 URL。三种选择器互斥，可与单个 `method` 合用。规则可指定可选 `name`。
- `request` 支持 `url`、`headers`、`body`、`js` 或独立的 `respond`，`response` 支持 `when`、`headers`、`body`、`js`。编译后的规则只匹配所属组的 origins。
- 未知字段、旧格式、重复键、类型错误与以显式 `null` 代替省略值均拒绝。最多 64 份插件，原文合计最多 1 MiB。目标组、origin 和规则各最多 64 项，展开后的操作和脚本另受编译预算约束。此能力需要 `inbound-http` 构建功能。

## 参数与分阶段条件

`description` 和 `parameters` 是可选的插件字段。每个参数指定 `type`（boolean、integer 或 string）和同类型的 `default`，可选 `label`、`description` 和同类型的 `choices`（字符串或整数）。整数须在安全整数范围内。每文件最多 32 项，字符串最多 2 KiB。本机参数覆盖合计最多 64 KiB，Core 校验后冻结有效值。参数键和可选规则 `id` 为小写 ASCII 字母起始，后续允许小写字母、数字及连字符，长度最多 64。规则 ID 在单文件内唯一。

`match.request-headers` 按原始请求头筛选，`match.parameters` 按已解析参数精确匹配。响应的 `when.status` 和 `when.headers` 按上游最终响应的改写前状态及头判断。所有条件合取。头条件由 `name` 和 `exists`、`equals` 或 `regex` 中之一组成。头名按 ASCII 忽略大小写，值逐项比较，重复值不合并。无法解码为 UTF-8 的字段值可匹配存在条件。H1 入口仍使用其现有头解析约束。请求和响应各自在改写前冻结匹配条件结果，脚本继续看到前序动作的当前提交值。

```yaml
parameters:
  profile: {type: string, default: stable, choices: [stable, beta]}
targets:
  - origins: ['https://*.cdn.example.com:8443']
    rules:
      - id: annotate
        match:
          method: GET
          request-headers: [{name: x-mode, exists: true}]
        response:
          when:
            status: 200
            headers: [{name: content-type, regex: '^application/json'}]
          headers:
            - set: {x-profile: {param: profile}}
```

`{param: key}` 适用于普通 header set/add 及文本正文的字面字符串位置。源和目标 URL、正则、Location、私密或控制字段、JS 源码及正文模式保留固定声明。JS 使用只读的 `input.parameters` 读取有效值。发布原文可携带非私密默认值，本机覆盖独立输入。

## 本地回包

```yaml
targets:
  - origins: ['http://api.example.com']
    rules:
      - match: {method: POST, path-exact: /telemetry}
        request:
          respond:
            status: 200
            headers: [{name: content-type, value: application/json}]
            body: {text: '{}'}
```

`request.respond` 是整条规则的唯一动作。Core 按规则顺序统一选择首条 URL 动作或本地回包。回包无需上游、请求正文和后续规则。响应状态支持 200–599（206 除外），204/205/304 只允许空正文。省略正文表示空。可选 `body.text` 或标准 `body.base64`，单份最多 256 KiB，全候选解码正文最多 1 MiB。响应头保留顺序和重复项，协议控制字段由 Core 生成。HEAD 只发响应头，H1 完成后关闭，H2 只结束当前流。客户端拒绝 identity 且需要发送实体时返回空 406。本地发送准备因工作区不足时返回空 503。

## 内联 HTTP 脚本

`request.js` 或 `response.js` 使用内联 `source` 和可选的 `body`（默认 `none`，可选 `text`、`bytes`）。作用阶段由所在字段决定，命中条件与原生动作相同。静态校验始终检查选择器与脚本 AST。运行时依据本机开关和有效目标决定是否准备脚本后端，当前后端可用性限于 Apple。用户脚本在命中业务请求或响应时执行。

源码必须定义唯一同步入口 `function rewrite(input) { ... }`。当前语法支持 let/const、if/else、return、普通 for/while/do-while、无标签 break/continue、普通对象和稠密数组、成员读取/简单赋值、局部变量自增减及赋值运算、条件/逻辑表达式与原始值的有限算术比较。对象不会被隐式转换成字符串或数字。静态 AST 检查遍历最多 16,384 项、递归深度 128；未知语法明确拒绝，不用字符串过滤代替语法解析。

AST 解析前限制词法扫描工作、局部运算链与嵌套深度。平铺语句各自计算运算链。局部变量使用未转义的 ASCII 标识符。

工具调用只开放 `String/Number/Boolean` 的单参数原始值转换，`JSON.parse/stringify`，`Object.keys/values/entries`，`Array.isArray`，`Number.isFinite/isInteger`，`Math.abs/floor/ceil/round/trunc/min/max` 和 `Uint8Array.from`。字符串可用 slice/substring/charAt/at/includes/startsWith/endsWith/indexOf/lastIndexOf/trim/toLowerCase/toUpperCase/split/replace/replaceAll；replace 的搜索参数只接受字符串，保留 JavaScript 字符串替换模板语义。数组可用 push/pop/slice/concat/join/indexOf/includes/reverse/at，Uint8Array 另支持 subarray。工具拒绝用户回调和隐式对象转换，输出在分配或导出前受大小、结构和工作预算检查。

| `Vole` 工具 | 输入与结果 |
| --- | --- |
| `query([plusAsSpace])` | 读取 Core 校验过的原始 URL。返回有序的 `{name,value}` 记录，保留重复键。键无等号时值为 `null`，等号后无内容时值为空字符串。忽略空的 `&` 分段。无查询时返回空数组 |
| `percentDecode(text[, plusAsSpace])` | 严格解码百分号序列及 UTF-8。两个查询工具均默认保留字面 `+`，显式传 `true` 时将其解释为空格 |
| `utf8Encode(text)`、`utf8Decode(bytes)` | 在字符串与 `Uint8Array` 间严格转换，拒绝无效 UTF-8 和孤立 surrogate |
| `base64Encode(bytes)`、`base64Decode(text)` | 转换标准 Base64。解码要求规范的填充与尾位 |
| `copyBytes(bytes[, start[, end]])`、`concatBytes(parts)` | 复制合法的半开区间，或按顺序拼接 `Uint8Array` 数组。省略区间时复制整份字节 |

工具运行在现有同步脚本事务内。扫描和分配计入调用预算，工具错误回退当前脚本。

不支持 import/export、额外函数或闭包、递归、async/await/Promise、class/new、try/catch/throw、正则字面量、模板字面量、解构、spread、可选链、动态函数调用和属性自增/复合赋值。不能访问 eval、constructor、prototype、原型链修改入口或内部执行工具；不提供文件、网络、KV、通知、timer、DOM 或平台对象。普通 JS JSON Number 与重复键行为不等于原生无损 JSON Patch。

输入含 `phase`、只读原始 URL/方法、当前 request、response 阶段的当前 response，以及本次声明选择的 body。headers 是保留同名多值顺序的 `{name,value}` 序列，不承诺 H2 的原始完整线序。none 的 body 为 not-requested；text 是严格 UTF-8 字符串，bytes 是完整解码实体的 Uint8Array，空正文与未提供正文不同。输入修改不直接提交；不能无损构造字符串 header 快照时跳过调用，不丢字段或有损替换。

返回值必须是普通有限数据记录：`{type:"pass"}` 保留输入，modify 可包含 url/method/status/headers/body，respond 以 status、初始 headers 和正文生成完整本地响应，`{type:"abort"}` 关闭当前 H1 交换或 reset 当前 H2 流。modify 的 headers 只能是有序 set/add/remove 操作，set/add 的 values 是非空字符串数组；respond 的 headers 是初始 `{name,value}` 序列。响应阶段不能改 URL/方法，请求阶段不能改 status。未知字段、undefined/null/Promise、accessor、自定义 toJSON、非有限数、孤立 surrogate、共享/循环结果和非法字节载荷均使整次调用失败。

普通请求 method 可改合法 token，但不允许涉及 HEAD/CONNECT 的方法转换；OPTIONS `*` 的请求脚本只提供 none，modify 只改普通 headers。普通完整响应 status 可在 200..599 之间变更；204/205/304/206 或带 Content-Range 的响应不变更 status，普通响应也不能改成这些特殊状态。respond 不生成 1xx/101/206 或 Content-Range；HEAD、204/205/304 不允许非空实体。framing、Host、Content-Encoding 等协议字段仍由 Core 管理；JS 另不能写代理认证字段。每次结果最多 100 个 header 操作/初始字段、100 个 set/add 值，控制字段按现有开销算法累计最多 32 KiB。

混用顺序固定为原生 URL → 原生 request header/body → request JS → 最终目标规划与上游转发 → 原生 response header/body → response JS → Core 校验发送；全部选择器继续使用原始 URL。JS 按声明顺序串行累计，失败只回到该次输入，保留原生和前序脚本结果；跨 origin 先清继承的 Authorization/Cookie，回退不恢复前序已清理凭据。respond/abort 终止后续链，本地响应不再递归执行 response 脚本。

原生与 JS 共用 256 KiB 单份实体和 4 MiB 非等待正文账本，桥接实际副本与输出也计费。没有正文需求时保留流式传输。原生文本动作和 JS text 要求 UTF-8。原生 protobuf 和 JS bytes 沿用 HEAD、无体、部分响应、流式、trailer 和原始协商排除。文本变化输出 UTF-8 identity，二进制变化输出 binary identity。无变化保留该次输入表示。正文不可用时跳过要求正文的脚本，none 仍可执行。

Apple 后端对可证明等价的闭合脚本使用静态执行计划，其余受支持的脚本使用独立 JavaScriptCore 上下文。两条分支执行相同的事务、期限与资源准入规则。调用内对输入对象的修改仍需经结果校验才能应用。

单次调用的期限为 100 ms（包含排队），最多 100,000 次受控 tick。请求和响应 JS 阶段各有 1 秒总期限，正文收集与传输使用各自的期限。取消及超时后的回收等待同步操作和实际执行 owner 结束；2 MiB 的累计分配工作预算约束执行工作量。正文许可随实际输入、输出、桥接副本和发送引用持有至最后一次释放。

## 编译期诊断

启用非默认构建功能 `http-diagnostics` 后，可通过 [Invoke](invoke-api.md#gethttpdiagnostics仅-http-diagnostics-构建) 读取 HTTP、脚本与 TUN 的进程级计数。活动工作、累计量与峰值分开解释。通过真实 Stop 和 owner 退出后的静止快照核对资源释放。脚本计量区分静态 Plan 与 JavaScriptCore；设备或性能验收使用实际测试窗口。

## URL 阶段

`request.url` 选择 `replace`、`redirect` 或 `reject` 之一。`{replace: 'https://example.com/v2'}` 替换完整 URL，`{redirect: {status: 302, to: 'https://example.com/'}}` 重定向，也可使用 307。`{reject: true}` 返回 403。默认 `mode: url` 使用完整目标。对 `url-regex` 使用 `{replace: {value: '/v2/', mode: match}}` 时替换首个匹配片段。对 `path-prefix` 使用 `mode: match` 时在目标 URL 后保留未匹配的路径后缀，目标没有查询参数时保留原查询。

正则模板支持 `$0`、`$N`、`${N}`、`${name}`、`$$`，不支持 `$name`；未知捕获加载失败，可选未参与捕获为空。字面模式不展开捕获。仅接受合法绝对 HTTP(S) URL，拒绝 userinfo、fragment、端口 0、控制／空白字符和反斜杠。离线输入 trim 并去掉 fragment；配置目标不允许 fragment。

所有阶段按原始规范化 URL（U0）筛选。URL 动作首条命中产生 U1，不递归。非法生成目标本地返回空 502；redirect 与 reject 本地结束，不访问原站，reject 为空 403。相同 origin 的路径／查询改写保留已选 IP；跨 origin 重选路、重建 authority，先清理收到的 Authorization／Cookie。原始目标与入口身份保留。

## Header 与正文

每个方向的 `headers` 和 `body` 各为有序操作列表。Header 支持 `set`、`add`、`remove`、`replace`。`set` 和 `add` 各接收一个名称／字面值映射，`remove` 接收字段名，`replace` 接收 `name`、`search`、`replacement` 和可选搜索参数。set 覆盖原值，add 追加独立值。协议控制字段、Connection 提名字段不能修改。阶段失败时整个 header 阶段回退。

正文支持 `set`、`replace`、`json-patch`、`json-filter` 和 `protobuf-remove`。搜索参数 `search-mode` 默认为 literal，可用 regex，`occurrences` 默认为 all，可用 first。正则搜索替换只展开自身捕获。正文操作失败时整个原生正文阶段原文旁路，已完成的 header 阶段保留。

```yaml
targets:
  - origins: [https://api.example.com]
    rules:
      - match: {path-exact: /v1/settings}
        response:
          body:
            - json-patch:
                - {op: add, path: /enabled, value: true}
                - {op: replace, path: /message, value: ready}
```

JSON Patch 支持 RFC 6902 的 add/remove/replace/move/copy/test 和 RFC 6901 Pointer；`value` 可为真正的 null、布尔、数值、字符串、数组、对象。配置数值必须能无损转换，不能静默舍入；业务 JSON 保留数值原文并拒绝重复键。空 patch 不触发解析或重新编码。非法 JSON、Pointer 或失败的 test 导致整个正文阶段原样旁路。

```yaml
body:
  - json-filter:
      path: /data/bottomBarControl/tabs
      remove-where:
        path: /tabType
        in: [home, entry, mall]
```

`json-filter` 用 JSON Pointer 定位数组，再对每个元素按相对 Pointer 比较 `equals` 或 `in` 中的标量。比较区分类型，数值使用精确比较。`in` 最多 32 个选项。数组路径缺失时保留原样，容器存在但类型错误时回退正文阶段。元素谓词路径缺失或类型不同则保留该元素。剩余元素、字段顺序和数字原文照录。零删项保留原始字节及编码。

```yaml
body:
  - protobuf-remove:
      paths: [[7], [68], [9, 18]]
```

`protobuf-remove` 处理单个 raw protobuf 实体。每项最多 32 个路径，深度最多 8，声明中拒绝空、重复或重叠的路径。删除所有终点匹配项，只沿指定路径解释嵌套消息。保留未知字段和原始顺序，仅修正发生变化的祖先长度前缀。默认接受原始 `Content-Type` 为 `application/protobuf` 或 `application/x-protobuf`。可通过 `media-types` 指定非空子集，也可明确允许 `application/octet-stream`。非法 wire、截断或嵌套字段类型不符导致原生正文阶段回退。零删项保留原始字节及编码。

只有被正文规则选中的消息才缓冲。原始、解码、中间和最终正文各限 256 KiB；进程共享 4 MiB 正文工作区，包含 JSON 与 codec 临时空间。先预留再分配，无额度直接旁路；发送期间保留额度。未知长度最多探测上限加一字节，超限按原实体字节回放已读前缀和余下数据，不截断。传输中断、超时和取消仍是错误，不能假装完成。

符合正文条件的消息在限额内收集一次，原生规则和脚本共用工作区。收集或解码失败时回放原始消息，传输失败按真实错误处理。发送切片保留实际缓冲区的预算占用。

HEAD、无正文状态、206/Content-Range、CONNECT、Upgrade、SSE、gRPC、multipart 及带 trailer 的消息不做正文改写，普通 header 规则仍可执行。选中正文的 H1 Expect: 100-continue 在读取前完成握手；未匹配消息保持原有流式背压、早响应和半关闭语义。H1/H2 与成功解密的 HTTPS 共用规则与预算。

## 选择性 HTTPS

HTTPS origins 同时声明目标组的 MITM 范围。Core 只考虑启用且含有效操作的目标。诊断用的 `intercept-only: true` 需要本机明确允许。`httpContext.mitmEnabled` 默认 false，`httpContext.excludeDomains` 默认空，按精确域名或 `*.suffix` 排除所有插件及端口。通配符覆盖多层子域，根域需单独排除。排除只作用于 MITM。启用后若仍有可拦截的 HTTPS origin，宿主通过独立私密入口提供有效的 CA 与匹配私钥，客户端需要信任该 CA。明文规则可以独立运行。

MITM 在 TCP 上按 ALPN 优先协商 HTTP/2，再接受 HTTP/1.1。开启本机 `mitmEnabled` 和 `rewriteEnabled` 后，有生效原生规则或已启用 JS 的 HTTPS origins 自动启用 H3 回退。全局排除和每个插件的授权范围优先，仅解密目标继续透传 QUIC。

TUN 和 SOCKS5 UDP 对候选端口使用有界的 QUIC v1/v2 Initial 检查。仅在可见 SNI 和实际目的端口命中该 HTTPS origin，且 ClientHello 的 ALPN 均为 HTTP/3 时抑制这次 Initial 握手及其重传。支持 TCP 回退的客户端可重连，再由 TLS 协商共同支持的 HTTP 版本。普通 UDP、其他 QUIC、ECH、无法确认的 Initial，以及尚未识别的已建立连接继续转发。使用缓存中的其他 UDP 端口时，仍按实际目的端口匹配。仅支持 H3 的客户端无法使用 TCP 回退。 [RFC 9114 §3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1)

作用域内的 H1/H2 响应在改写结束后移除可识别的 H3 `Alt-Svc` 声明，保留其他替代服务。若删完所有声明，发送 `Alt-Svc: clear` 清除已有缓存。 [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3)

握手时按已授权的 SNI／端口判断，本机排除同时适用于通配的实际主机。无 SNI、ECH（含 GREASE）和未授权名称保持透明。在执行规则前重新检查每个 H1 请求和 H2 流的原始 authority。未获授权的 authority 返回 403。每条规则还须匹配所属实例获准的 origin。最终上游按实际目标验证证书，使用受保护出口。不通过关闭验证处理 pinning 或客户端证书要求。

下游 rustls 写侧缓冲使用统一 TLS 默认值 64 KiB；这是 HTTP 上下文的固定默认策略，不接收节点或低层调用者的容量覆盖。它与 TUN 发送缓冲、H2 窗口及 4 MiB 正文账本分别计量；正文许可继续持有至实际发送 owner 释放，TLS 局部容量不代表进程 physical footprint。

H1 上游协商 HTTP/1.1，H2 下游对接实际协商的 H2 或 H1。普通 H2 CONNECT 返回 405；WebSocket 使用 H1 Upgrade。叶证书最多 32 项、材料预算 256 KiB、空闲 10 分钟，有效期不超过 24 小时或 CA。

## 业务上游复用

同一下游连接可保留一个可接收新请求的 H1 上游或 H2 会话。每个请求仍需独立授权、改写并按最终目标选路。复用要求最终 origin、资源代际、入口上下文及完整静态连接器身份一致。HTTPS 还要保持整个改写链的原 origin，并通过最终目标的证书、SNI 和 ALPN 校验。跨 origin 或 scheme 的请求建立独立上游，即使后续再次改回。

- **H1** 要求持久的 HTTP/1.1、空正文或固定长度请求，以及原始响应的完整 Content-Length 消费。HEAD、CONNECT、`OPTIONS *`、Expect、Upgrade、分块与 trailer 使用独立交换。早响应、未完整上传、关闭、截断或传输错误会退役上游；已发送请求的失败按原错误返回。
- **H2** 要求实际协商 HTTP/2。空正文可随 HEADERS 发送 END_STREAM，其余上传在实际正文、trailer 和 END_STREAM 完成后才算完整。早响应、上传失败及停止可使上游退役。复用时如果在提交请求前观察到远端 GOAWAY，旧连接停止准入，当前请求沿已选路由和原连接期限拨号一次。已在途请求继续持有原 driver 至结束。已提交请求按原错误路径处理。单次路径有独立的上游所有权。
- **H2 局部上限**为每个下游连接 8 个活动请求，流及连接接收信用各 64 KiB，头 32 KiB／100 字段，帧 16 KiB，动态 HPACK 表关闭。下游每流响应发送容量为 64 KiB，每次最多提交 16 KiB；上游发送容量为 16 KiB。上传以 30 秒无进展为限，完成后另等待响应头至多 30 秒。共享正文预算延续至最后发送引用释放。

固定连接器资格由实际出站图提供。动态策略组、未知上游路径、会改变安全身份的外部资源以及已停止的节点走单次路径。VLESS 的上传、下载腿分别校验其真实 TCP 或 UDP 载体；在 macOS 上，`mptcp: true` 沿用普通 TCP 路径。各协议的静态端点、安全身份和封装限制见 [出站契约](outbounds.md)、[VLESS](vless.md) 和 [XHTTP](xhttp.md)。保留的业务连接继续拥有其协议逻辑流和租约，直到退役、下游结束或 Stop。

## 会话边界

运行会话固定主设置、由插件原文编译的规则和脚本、本机设置及 CA。插件保存及订阅更新由宿主管理，节点选择和分流更新沿用运行中的 HTTP 输入。显式重连先准备候选再切换，失败恢复原会话的实际内容。普通 Stop 释放私密材料。[Invoke API](invoke-api.md#http-插件与本机设置) · [CLI](cli.md) · [离线回归](../tests/README.md#http-处理与-invoke)
