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

源码只接受本机主文档的内联字符串，不读取文件、URL 或 script provider；rewrite provider 仍只能携带原生 `payload`。禁用总开关仍检查全部脚本的 schema、选择器及源码 AST；静态校验不初始化脚本后端、不执行源码、不获取外部资源。实际准备遇到不支持的执行后端明确失败，不把脚本静默丢弃；当前执行后端为 Apple JavaScriptCore。

脚本声明最多 64 项，名称与选择器合计不超过 64 KiB，选择器沿用每项 2 KiB 和原生正则编译预算；内联源码计入已有的 1 MiB 文档/实际资源总上限。未知字段、空值冒充省略值、无效 AST 或超限均拒绝整个候选，不截断。实际 source、声明与编译结果随 HTTP 会话候选固定，资源刷新或后续编辑不改变正在运行的脚本。

源码必须定义唯一同步入口 `function rewrite(input) { ... }`。当前语法支持 let/const、if/else、return、普通 for/while/do-while、无标签 break/continue、普通对象和稠密数组、成员读取/简单赋值、局部变量自增减及赋值运算、条件/逻辑表达式与原始值的有限算术比较。对象不会被隐式转换成字符串或数字。静态 AST 检查遍历最多 16,384 项、递归深度 128；未知语法明确拒绝，不用字符串过滤代替语法解析。

AST 解析前另有保守的词法资源预检：括号嵌套、静态控制关键字、运算符字符及未分隔冒号链各限 128；最多 65,536 个词法状态、256 个 slash 歧义分支和 8 MiB 累计扫描。字符串与普通注释作为数据跳过，不从内容猜测语法；slash 同时考虑除法/正则词法目标，最终仍由 AST 拒绝正则。超出预检界限明确失败，不承诺支持所有合法 JavaScript。局部变量使用未转义的 ASCII 标识符，不接受字符串/注释以外的标识符转义。

工具调用只开放 `String/Number/Boolean` 的单参数原始值转换，`JSON.parse/stringify`，`Object.keys/values/entries`，`Array.isArray`，`Number.isFinite/isInteger`，`Math.abs/floor/ceil/round/trunc/min/max` 和 `Uint8Array.from`。字符串可用 slice/substring/charAt/at/includes/startsWith/endsWith/indexOf/lastIndexOf/trim/toLowerCase/toUpperCase/split/replace/replaceAll；replace 的搜索参数只接受字符串，保留 JavaScript 字符串替换模板语义。数组可用 push/pop/slice/concat/join/indexOf/includes/reverse/at，Uint8Array 另支持 subarray。工具拒绝用户回调和隐式对象转换，输出在分配或导出前受大小、结构和工作预算检查。

不支持 import/export、额外函数或闭包、递归、async/await/Promise、class/new、try/catch/throw、正则字面量、模板字面量、解构、spread、可选链、动态函数调用和属性自增/复合赋值。不能访问 eval、constructor、prototype、原型链修改入口或内部执行工具；不提供文件、网络、KV、通知、timer、DOM 或平台对象。普通 JS JSON Number 与重复键行为不等于原生无损 JSON Patch。

输入含 `phase`、只读原始 URL/方法、当前 request、response 阶段的当前 response，以及本次声明选择的 body。headers 是保留同名多值顺序的 `{name,value}` 序列，不承诺 H2 的原始完整线序。none 的 body 为 not-requested；text 是严格 UTF-8 字符串，bytes 是完整解码实体的 Uint8Array，空正文与未提供正文不同。输入修改不直接提交；不能无损构造字符串 header 快照时跳过调用，不丢字段或有损替换。

返回值必须是普通有限数据记录：`{type:"pass"}` 保留输入，modify 可包含 url/method/status/headers/body，respond 以 status、初始 headers 和正文生成完整本地响应，`{type:"abort"}` 关闭当前 H1 交换或 reset 当前 H2 流。modify 的 headers 只能是有序 set/add/remove 操作，set/add 的 values 是非空字符串数组；respond 的 headers 是初始 `{name,value}` 序列。响应阶段不能改 URL/方法，请求阶段不能改 status。未知字段、undefined/null/Promise、accessor、自定义 toJSON、非有限数、孤立 surrogate、共享/循环结果和非法字节载荷均使整次调用失败。

普通请求 method 可改合法 token，但不允许涉及 HEAD/CONNECT 的方法转换；OPTIONS `*` 的请求脚本只提供 none，modify 只改普通 headers。普通完整响应 status 可在 200..599 之间变更；204/205/304/206 或带 Content-Range 的响应不变更 status，普通响应也不能改成这些特殊状态。respond 不生成 1xx/101/206 或 Content-Range；HEAD、204/205/304 不允许非空实体。framing、Host、Content-Encoding 等协议字段仍由 Core 管理；JS 另不能写代理认证字段。每次结果最多 100 个 header 操作/初始字段、100 个 set/add 值，控制字段按现有开销算法累计最多 32 KiB。

混用顺序固定为原生 URL → 原生 request header/body → request JS → 最终目标规划与上游转发 → 原生 response header/body → response JS → Core 校验发送；全部选择器继续使用原始 URL。JS 按声明顺序串行累计，失败只回到该次输入，保留原生和前序脚本结果；跨 origin 先清继承的 Authorization/Cookie，回退不恢复前序已清理凭据。respond/abort 终止后续链，本地响应不再递归执行 response 脚本。

原生与 JS 共用已有 256 KiB 单份实体和 2 MiB 非等待正文账本，桥接实际副本与输出也计费；没有正文需求不缓冲全文。原生正文继续使用 UTF-8 资格与事务；bytes 模式不要求 UTF-8，但保留 HEAD/无体/部分响应、流式、trailer 和原始协商排除。JS text 变化输出 UTF-8 identity，bytes 变化输出 binary identity，不自动追加 UTF-8 charset；无变化保留该次输入表示。正文不可用时跳过要求正文的脚本，none 仍可执行。

原生 literal 替换在非空搜索串且替换字节数不增加时，输出缓冲容量按实际输入字节数预留；可能增长、空搜索或 regex 仍预留单实体上限。该容量在分配前计费，输出及其 Bytes 切片继续持有真实 owner，直到最后引用释放；不提前退款，也不改变整阶段失败回滚。

有正文输入的调用一次取得独立输入副本、Rust 输出缓冲与 C API 桥接工作区。静态前端仅在原已接受 AST 的全部返回路径均为新建结果记录、text 正文由只读原始 body.data／局部别名／不可增长 ASCII 单字符 replaceAll／字面字符串组成，且整程序效果审查排除相关写入和未知调用时生成保守 UTF-8 输出界限 O=min(256 KiB,max(实际输入字节数 I,最大已证明字面正文 UTF-8 长度))；分析不确定或达到自身上限时 O 仍为 256 KiB，不改变源码准入或生成 JS。Rust 输出预留 O；0<O<256 KiB 时另预付一个公开 UTF-8 API 的 NUL scratch 字节，逻辑正文仍严格限于 O。

设 M=256 KiB、Q=UTF-16 Vec bookkeeping，所有输入模式的独立预付视图 V=max(3O,min(7I+Q,3M))；text 输入另付 retained backing 2I 与 Q，二者不能借给视图。未知输出 O=M 时，原 bridge 总量保持 3M+(text?2I+Q:0)。UTF-16 构造临时部分最多 2I；ASCII 无 NUL 的 UTF-8 构造仅在 V>=3I+1 时使用，覆盖 CString I+1 与可能 decoder 2I 的峰值，retained backing 2I 独立计费。MAX 输入回 UTF-16 构造，避免末尾 +1 改变旧准入边界。bridge 整体许可跨实际 context 释放，Rust 输出 Vec 不能重复支付 API 字符副本；bytes 输入仍可返回 text，不能省略独立视图。

none 调用不提前占正文输入／输出或桥接槽。成功 Finish 后，私有可信 helper 对原始 String 读取 .length；原生端重新检查原始 String/Number、有限整数单元数 N、N<=O，再于任何 API 字符复制前非等待支付 3N 视图。复制后重验实际 API 长度，严格 UTF-8 字节长度不超过 O 后才准备／写入 Rust 输出；bytes 输出同样在复制前检查长度<=O。空 text 没有字符载荷，不占视图槽。API 视图和 Rust 输出同时存活时分别计费，所有退出先释放 API owner 再归还临时许可。预算耗尽仍允许没有正文结果的 pass/header-only 调用及空本地响应。该保守桥接载荷账本不覆盖所有 VM StringImpl/ArrayBuffer、GC 或框架分配器开销；这些仍进入进程内存验收。

Apple 后端每次调用使用独立上下文，单次期限 100 ms（包含排队）、最多 100,000 次受控 tick；请求/响应各自的 JS 阶段另有 1 秒总期限，不把它当作正文收集或 HTTP 传输总期限。循环与入口均插入检查，数据增长和工具调用也检查预算。系统内建函数的一次受限同步操作不能被抢占；其输入、控制流与结果有界，期限/取消必须等待实际调用结束才返回，不以换线程或提前完成 Future 冒充终止。2 MiB 累计 allocation-work 是当前执行器的工作准入计数，不能称为 JavaScript VM heap 或进程 RSS 上限，也不替代正文账本。实际系统求值依赖 Apple JavaScriptCore；非 Apple 平台可纯静态校验源码，但启用非空脚本列表时实际准备明确失败。`testHttp` 当前也明确拒绝启用的非空脚本列表，不能把原生离线演算当成已执行 JS。

受信任 prelude 对至少 4096 个 UTF-16 单元的非 quoted 字符串可调用私有 ASCII 判定，以公开 JSC API 读取有界字符视图。Execution 记录预付视图 V 及已借给累计保留输出 backing 的 B，另保留最终导出 floor F=3O，累计保留 backing 只能借 V-F；可用临时部分 A=V-B 始终至少为 F。判定与导出均按实际单元数 N 先支付 max(3N-A,0) 的同账本缺额，再创建 API 副本，先释放 API owner 再归还临时缺额。最终输出界限不能当成中间字符串界限。无法取得判定视图时回原正则判定，Unicode、短字符串和 quoted 路径保持原逻辑与 tick。helper 不暴露给用户源码，不允许字符串对象或用户转换回调，也不把 API 字符副本称为零复制。

受信任 prelude 在保留原字符串大小预检、allocation-work 计费和 tick 次数后，可为至少 4096 个 UTF-16 单元的 replaceAll 尝试私有原生 literal 工具。工具只处理整个输入均为 ASCII、search/replacement 各一个 ASCII 单元且 replacement 不是 `$`、命中数至少为输入单元数的 1/16（向上取整）的情形；其他语义、短／稀疏输入或准入失败继续使用原 JS intrinsic。工具不暴露给用户源码，不进行对象隐式转换，期限／取消仍在原检查点生效并等待实际同步调用返回。

原生 literal 工具按当前实际字符串 N 单元，在任何 API 字符复制前支付临时 T=5N+Q 与新输出 backing R=2N。从可用 A 超过最终导出 floor F=3O 的部分中先划分 b=min(R,max(A-F,0)) 给本次待保留 backing，临时视图只能使用 A-b；同一账本先分别预留 R-b 与 max(T-(A-b),0) 的缺额，任何一步失败回原 JS intrinsic。输入 retained backing 和 Rust export Vec 不能代替这些额度。生成 host UTF-16 输出 Vec 后先实际释放输入 API 视图，再创建输出 API／MakeString 副本，避免所有字符副本和 host Vec 额外并存。输出 API 创建前才提交 B+=b 并合并额外保留 reservation；之后即使 API 分配失败，也保守持有至实际 context 释放后。最终已准入正文的 3N<=3O<=A 导出不再争取全局额度；后续 native 缺额不足在工具入口回退。中途覆盖 JS 变量不会归还 B 或累计保留额度；创建输出 API 之前的语义回退则退款本次未使用保留计划。所有原始 tick、allocation-work、错误回退和 deadline 保持；该账本仍不是 VM heap／RSS 上限。

多线程 Tokio runtime 在持有同一执行 lane 时，为每次求值创建一个有作用域的 OS 线程，全部 JSC 对象在该线程创建、使用和释放；同步 join 后才返回并归还 lane、借用缓冲及桥接许可。线程启动和调度仍使用原绝对期限，线程创建失败按该次调用失败处理，panic 保持展开语义；不遗弃线程或保留跨调用 VM。单线程 runtime 继续同步执行。此处不引入 VM/context 池或新的并行 lane。

## 编译期诊断

非默认 Cargo feature `http-diagnostics` 提供隐藏的 Rust 观测入口 `http_processing::diagnostics::snapshot()`；默认构建不保留计数器或新增采样时钟。它不增加 Invoke/Controller API，不改变脚本、排队、正文准入或错误回退。固定字段按进程寿命累计，不按 URL/脚本名扩张，不保存正文、头或私密材料，也不提供并发 reset。

快照覆盖匹配/跳过原因、完整 CallBuffers 组合准入及 input/最大 output/bridgeWorkspace 请求量、独立桥接准入失败、ASCII 视图请求/准入/预算回退、排队和实际求值结果、正文收集/解码/原生转换失败点、context 生命周期，以及成功和失败的六段求值时间、最终 JSON 解析、context 释放、整体求值时间和 tick 汇总。各段是当前实现的实际边界：context 段含 callback 安装，invoke 段含结果整理；整体时间另含最终检查、解析及清理，阶段总和不保证等于整体时间。求值计时从后端进入开始，不含排队及 scoped 线程启动/join；调用者总耗时和吞吐须另行测量。计时单位为微秒，固定聚合只含次数/累计/最大值；不是分位延迟或逐请求追踪。

各字段独立采样，活跃快照不保证跨字段一致；生命周期守恒应在真实 Stop 屏障后检查。`bodyWorkspace.current/peak` 是跨账本的影子 telemetry，分配/释放与采样存在窄排序窗口，peak 不等于单账本硬上限；`maxSingleBudget` 来自真实成功准入时的账本占用。额度仍由原账本控制并随最后 Bytes owner 释放，这些数值均不是 JS heap、RSS 或 Network Extension footprint。

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

MITM 支持 HTTP/1.1 与 HTTP/2。HTTP/3 MITM 暂不支持；UDP／QUIC（含 H3）按原字节透明转发，不进入 URL/header/body rewrite，也不通过阻断 QUIC 强制客户端回落。

只终止允许的 SNI／端口；无 SNI、ECH（含 GREASE）和未授权名称保持透明。每个原始 HTTP authority 独立授权，同一 H2 连接不扩大权限。最终上游按实际目标验证证书，使用受保护出口；不通过关闭验证处理 pinning 或客户端证书要求。

H1 上游协商 HTTP/1.1，H2 下游对接实际协商的 H2 或 H1。普通 H2 CONNECT 返回 405；WebSocket 使用 H1 Upgrade。叶证书最多 32 项、材料预算 256 KiB、空闲 10 分钟，有效期不超过 24 小时或 CA。

H2 每连接最多 8 个活动请求，流／连接接收窗口 32／64 KiB，头最多 32 KiB／100 字段，帧 16 KiB，关闭动态 HPACK 表。上游不跨请求复用。上传使用 30 秒无进展期限；上传完成后响应头另有 30 秒等待期限，提前响应仍与上传并发。取消和 Stop 覆盖上下游、正文与驱动。

当前会话固定主设置、实际 payload、授权和 CA。保存／资源刷新只产生待应用候选，节点选择和分流更新继承 active。显式重连准备候选后切换，后续启动失败使用旧实际内容恢复，不重读已变化文件；普通 Stop 释放私密材料。共享入口见 [Invoke API](invoke-api.md) 与 [CLI](cli.md)。
