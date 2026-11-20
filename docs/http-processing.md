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

同一次候选编译中，原生 URL 选择器按完全相同的 pattern 字节共享不可变 Regex 与其搜索缓存池；本地与 provider 规则仍逐条校验、计费并保留原顺序和来源。共享表只存活于该次编译，规则持有各自引用，重新编译的候选不沿用旧表；不缓存匹配结果，也不改变捕获模板、原始 URL 视图、脚本选择器或正文搜索。缓存池仍按实际并发取得搜索状态，共享不构成进程内存上界或性能保证。

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

源码只接受本机主文档的内联字符串，不读取文件、URL 或 script provider；rewrite provider 仍只能携带原生 `payload`。禁用总开关仍检查全部脚本的 schema、选择器及源码 AST；静态校验不初始化脚本后端、不执行源码、不获取外部资源。实际准备遇到不支持的执行后端明确失败，不把脚本静默丢弃；当前后端可用性限于 Apple；每次实际执行分支是下述保守闭合子集的 Rust Plan，或独立 fresh JavaScriptCore。完整脚本改写吞吐须披露实际分支，Rust Plan 的结果不能称为 JSC 虚拟机吞吐。启用且声明非空脚本的实际资源准备，会在独立线程首次创建专用 JavaScriptCore context，解析受信 runtime，并仅执行固定、小常量的私有 guard／Finish 合成序列；不读取、扫描或执行配置中的用户 source，也不调用其 rewrite。该 context 使用仅限预热的固定 no-op 私有 callback，不占业务正文账本或计入用户求值计数。context、callback 和 owner 真正释放、线程及 TLS join 后才继续；进程只保留成功初始化标记，失败可重试。预热不保留 VM，不触发于静态验证或禁用/空声明；取消和 Stop 等待已经开始的初始化真实结束。每次选择 JSC 的用户调用仍创建独立 VM；静态计划不创建 VM，二者沿用相同的排队、期限与资源限制。

脚本声明最多 64 项，名称与选择器合计不超过 64 KiB，选择器沿用每项 2 KiB 和原生正则编译预算；内联源码计入已有的 1 MiB 文档/实际资源总上限。未知字段、空值冒充省略值、无效 AST 或超限均拒绝整个候选，不截断。实际 source、声明与编译结果随 HTTP 会话候选固定，资源刷新或后续编辑不改变正在运行的脚本。

源码必须定义唯一同步入口 `function rewrite(input) { ... }`。当前语法支持 let/const、if/else、return、普通 for/while/do-while、无标签 break/continue、普通对象和稠密数组、成员读取/简单赋值、局部变量自增减及赋值运算、条件/逻辑表达式与原始值的有限算术比较。对象不会被隐式转换成字符串或数字。静态 AST 检查遍历最多 16,384 项、递归深度 128；未知语法明确拒绝，不用字符串过滤代替语法解析。

AST 解析前另有保守的词法资源预检：括号嵌套、静态控制关键字、运算符字符及未分隔冒号链各限 128；最多 65,536 个词法状态、256 个 slash 歧义分支和 8 MiB 累计扫描。字符串与普通注释作为数据跳过，不从内容猜测语法；slash 同时考虑除法/正则词法目标，最终仍由 AST 拒绝正则。超出预检界限明确失败，不承诺支持所有合法 JavaScript。局部变量使用未转义的 ASCII 标识符，不接受字符串/注释以外的标识符转义。

工具调用只开放 `String/Number/Boolean` 的单参数原始值转换，`JSON.parse/stringify`，`Object.keys/values/entries`，`Array.isArray`，`Number.isFinite/isInteger`，`Math.abs/floor/ceil/round/trunc/min/max` 和 `Uint8Array.from`。字符串可用 slice/substring/charAt/at/includes/startsWith/endsWith/indexOf/lastIndexOf/trim/toLowerCase/toUpperCase/split/replace/replaceAll；replace 的搜索参数只接受字符串，保留 JavaScript 字符串替换模板语义。数组可用 push/pop/slice/concat/join/indexOf/includes/reverse/at，Uint8Array 另支持 subarray。工具拒绝用户回调和隐式对象转换，输出在分配或导出前受大小、结构和工作预算检查。

不支持 import/export、额外函数或闭包、递归、async/await/Promise、class/new、try/catch/throw、正则字面量、模板字面量、解构、spread、可选链、动态函数调用和属性自增/复合赋值。不能访问 eval、constructor、prototype、原型链修改入口或内部执行工具；不提供文件、网络、KV、通知、timer、DOM 或平台对象。普通 JS JSON Number 与重复键行为不等于原生无损 JSON Patch。

输入含 `phase`、只读原始 URL/方法、当前 request、response 阶段的当前 response，以及本次声明选择的 body。headers 是保留同名多值顺序的 `{name,value}` 序列，不承诺 H2 的原始完整线序。none 的 body 为 not-requested；text 是严格 UTF-8 字符串，bytes 是完整解码实体的 Uint8Array，空正文与未提供正文不同。输入修改不直接提交；不能无损构造字符串 header 快照时跳过调用，不丢字段或有损替换。

返回值必须是普通有限数据记录：`{type:"pass"}` 保留输入，modify 可包含 url/method/status/headers/body，respond 以 status、初始 headers 和正文生成完整本地响应，`{type:"abort"}` 关闭当前 H1 交换或 reset 当前 H2 流。modify 的 headers 只能是有序 set/add/remove 操作，set/add 的 values 是非空字符串数组；respond 的 headers 是初始 `{name,value}` 序列。响应阶段不能改 URL/方法，请求阶段不能改 status。未知字段、undefined/null/Promise、accessor、自定义 toJSON、非有限数、孤立 surrogate、共享/循环结果和非法字节载荷均使整次调用失败。

普通请求 method 可改合法 token，但不允许涉及 HEAD/CONNECT 的方法转换；OPTIONS `*` 的请求脚本只提供 none，modify 只改普通 headers。普通完整响应 status 可在 200..599 之间变更；204/205/304/206 或带 Content-Range 的响应不变更 status，普通响应也不能改成这些特殊状态。respond 不生成 1xx/101/206 或 Content-Range；HEAD、204/205/304 不允许非空实体。framing、Host、Content-Encoding 等协议字段仍由 Core 管理；JS 另不能写代理认证字段。每次结果最多 100 个 header 操作/初始字段、100 个 set/add 值，控制字段按现有开销算法累计最多 32 KiB。

混用顺序固定为原生 URL → 原生 request header/body → request JS → 最终目标规划与上游转发 → 原生 response header/body → response JS → Core 校验发送；全部选择器继续使用原始 URL。JS 按声明顺序串行累计，失败只回到该次输入，保留原生和前序脚本结果；跨 origin 先清继承的 Authorization/Cookie，回退不恢复前序已清理凭据。respond/abort 终止后续链，本地响应不再递归执行 response 脚本。

原生与 JS 共用 256 KiB 单份实体和 4 MiB 非等待正文账本，桥接实际副本与输出也计费；没有正文需求不缓冲全文。原生正文继续使用 UTF-8 资格与事务；bytes 模式不要求 UTF-8，但保留 HEAD/无体/部分响应、流式、trailer 和原始协商排除。JS text 变化输出 UTF-8 identity，bytes 变化输出 binary identity，不自动追加 UTF-8 charset；无变化保留该次输入表示。正文不可用时跳过要求正文的脚本，none 仍可执行。

原生 literal 替换在非空搜索串且替换字节数不增加时，输出缓冲容量按实际输入字节数预留；可能增长、空搜索或 regex 仍预留单实体上限。该容量在分配前计费，输出及其 Bytes 切片继续持有真实 owner，直到最后引用释放；不提前退款，也不改变整阶段失败回滚。

已编译 literal 的 search／replacement 若各恰一个 ASCII 字节，原生正文可在独立、按原容量先付费的输出内直接写入：All 对全部输入逐字节选择，First 复制输入后仅替换最左一次。UTF-8 多字节部分原样保留；NUL、`$`、相同字节及 no-match 仍保留 literal 语义和原准入。其他 literal 形状及全部 regex／模板继续走原 Search helper；headers 不使用此正文专用写入。输出初始化及实际 native 操作仍须完成后才返回，不新增 JS tick／期限，也不承诺 SIMD 或性能收益。仅该已证输出容量等于输入字节数的 byte-map 路径与闭合 Plan 共用 fixed-output 工厂：Unix 且启用 inbound-http 时，容量至少 64 KiB 使用原安全匿名映射，较小输出、非 Unix 或未启用该 feature 保持 Vec；映射失败在同一完整 reservation 下尝试原 Vec，不另争信用。其他原生 String／regex／模板及 JSC 保持原 Vec；collector 按下述独立与共享路径选择 backing，源与结果仍独立按原容量及实际 owner 大小计费，最后发送／slice owner 释放前不退款，不改变 no-op 表示保留或整阶段回滚。

有正文输入的调用借用当前 Entity 的不可变正文。输入视图由私有构造的账本见证绑定实际 Entity／Bytes owner，不能用任意切片与另一账本拼接；正文替换仅接受同账本的 BudgetedBytes，全部校验后才原子提交正文及元数据。JSC 分支一次取得独立 Rust 输出缓冲与 C API 桥接工作区。原 Entity 及其正文许可跨等待与实际求值线程的 context/TLS 释放和 join 保持；JSC 输入仍通过公开 API 创建独立字符串或 typed-array 副本，脚本修改输入不直接修改 Entity。整次结果校验后才替换当前 Entity，失败保留该次输入；不再分配或计费一份多余的 Rust 输入复制。静态前端仅在原已接受 AST 的全部返回路径均为新建结果记录、text 正文由只读原始 body.data／局部别名／不可增长 ASCII 单字符 replaceAll／字面字符串组成，且整程序效果审查排除未证明安全的相关写入和未知调用时生成保守 UTF-8 输出界限 O=min(256 KiB,max(实际输入字节数 I,最大已证明字面正文 UTF-8 长度))；分析不确定或达到自身上限时 O 仍为 256 KiB，不改变源码准入或生成 JS。Rust 输出预留 O；0<O<256 KiB 时另预付一个公开 UTF-8 API 的 NUL scratch 字节，逻辑正文仍严格限于 O。

输出界限证明还接受函数顶层唯一声明、初值已有字符串界限的 `let` 绑定，其全部写入只能是顶层独立的 `s = s.replaceAll(search, replacement)`；receiver 必须为同一绑定，两个参数均为单 ASCII 字节字面字符串且 replacement 不是 `$`。每个成功版本保留初值的同一 UTF-8 字节上界，不按最后一次赋值缩小界限；旧值别名、提前返回及初值的全部传递依赖继续参与证明。任何其它相关写入（包括条件、循环、嵌套表达式或不可达语句中的写入）、成员写入、shadow、未知效果或分析上限仍使该可选证明回到 256 KiB。检查复用同一有界 AST 遍历，不改写源码、生成 JS、静态执行计划的选择或既有正文／执行额度；得到较小输出界限仍可继续使用 JavaScriptCore。

设 M=256 KiB、Q=UTF-16 Vec bookkeeping，所有输入模式的独立预付视图 V=max(3O,min(7I+Q,3M))；text 输入另付 retained backing 2I 与 Q，二者不能借给视图。未知输出 O=M 时，原 bridge 总量保持 3M+(text?2I+Q:0)。UTF-16 构造临时部分最多 2I；ASCII 无 NUL 的 UTF-8 构造仅在 V>=3I+1 时使用，覆盖 CString I+1 与可能 decoder 2I 的峰值，retained backing 2I 独立计费。MAX 输入回 UTF-16 构造，避免末尾 +1 改变旧准入边界。bridge 整体许可跨实际 context 释放，Rust 输出 Vec 不能重复支付 API 字符副本；bytes 输入仍可返回 text，不能省略独立视图。

none 调用不提前占正文输入／输出或桥接槽。成功 Finish 后，私有可信 helper 对原始 String 读取 .length；原生端重新检查原始 String/Number、有限整数单元数 N、N<=O，再于任何 API 字符复制前非等待支付 3N 视图。复制后重验实际 API 长度，严格 UTF-8 字节长度不超过 O 后才准备／写入 Rust 输出；bytes 输出同样在复制前检查长度<=O。空 text 没有字符载荷，不占视图槽。API 视图和 Rust 输出同时存活时分别计费，所有退出先释放 API owner 再归还临时许可。预算耗尽仍允许没有正文结果的 pass/header-only 调用及空本地响应。该保守桥接载荷账本不覆盖所有 VM StringImpl/ArrayBuffer、GC 或框架分配器开销；这些仍进入进程内存验收。

Apple JSC 分支每次调用使用独立上下文；所有分支的单次期限均为 100 ms（包含排队）、最多 100,000 次受控 tick；请求/响应各自的 JS 阶段另有 1 秒总期限，不把它当作正文收集或 HTTP 传输总期限。循环与入口均插入检查，数据增长和工具调用也检查预算。系统内建函数的一次受限同步操作不能被抢占；其输入、控制流与结果有界，期限/取消必须等待实际调用结束才返回，不以换线程或提前完成 Future 冒充终止。2 MiB 累计 allocation-work 是当前执行器的工作准入计数，不能称为 JavaScript VM heap 或进程 RSS 上限，也不替代正文账本。未获下述完整证明的脚本仍依赖 Apple JavaScriptCore；非 Apple 平台可纯静态校验源码，但启用非空脚本列表时实际准备明确失败。`testHttp` 当前也明确拒绝启用的非空脚本列表，不能把原生离线演算当成已执行 JS。

受信任 prelude 对至少 4096 个 UTF-16 单元的非 quoted 字符串可调用私有 ASCII 判定，以公开 JSC API 读取有界字符视图。Execution 记录预付视图 V 及已借给累计保留输出 backing 的 B，另保留最终导出 floor F=3O，累计保留 backing 只能借 V-F；可用临时部分 A=V-B 始终至少为 F。判定与导出均按实际单元数 N 先支付 max(3N-A,0) 的同账本缺额，再创建 API 副本，先释放 API owner 再归还临时缺额。最终输出界限不能当成中间字符串界限。无法取得判定视图时回原正则判定，Unicode、短字符串和 quoted 路径保持原逻辑与 tick。helper 不暴露给用户源码，不允许字符串对象或用户转换回调，也不把 API 字符副本称为零复制。

受信任 prelude 在保留原字符串大小预检、allocation-work 计费和 tick 次数后，可为至少 4096 个 UTF-16 单元的 replaceAll 尝试私有原生 literal 工具。工具只处理整个输入均为 ASCII、search/replacement 各一个 ASCII 单元且 replacement 不是 `$`、命中数至少为输入单元数的 1/16（向上取整）的情形；其他语义、短／稀疏输入或准入失败继续使用原 JS intrinsic。工具不暴露给用户源码，不进行对象隐式转换，期限／取消仍在原检查点生效并等待实际同步调用返回。

原生 literal 工具按当前实际字符串 N 单元，在任何 API 字符复制前支付临时 T=5N+Q 与新输出 backing R=2N。从可用 A 超过最终导出 floor F=3O 的部分中先划分 b=min(R,max(A-F,0)) 给本次待保留 backing，临时视图只能使用 A-b；同一账本先分别预留 R-b 与 max(T-(A-b),0) 的缺额，任何一步失败回原 JS intrinsic。输入 retained backing 和 Rust export Vec 不能代替这些额度。生成 host UTF-16 输出 Vec 后先实际释放输入 API 视图，再创建输出 API／MakeString 副本，避免所有字符副本和 host Vec 额外并存。输出 API 创建前才提交 B+=b 并合并额外保留 reservation；之后即使 API 分配失败，也保守持有至实际 context 释放后。最终已准入正文的 3N<=3O<=A 导出不再争取全局额度；后续 native 缺额不足在工具入口回退。中途覆盖 JS 变量不会归还 B 或累计保留额度；创建输出 API 之前的语义回退则退款本次未使用保留计划。所有原始 tick、allocation-work、错误回退和 deadline 保持；该账本仍不是 VM heap／RSS 上限。


Apple 编译后的源码可携带一个可选静态执行计划。原 frontend 先完整检查源码并生成 JS，再在同一 AST 上证明完整闭合子集：String 局部别名／ASCII 字面常量、只读 `input.body.data`、非空单 ASCII 单元的 literal `replace`／`replaceAll`（replacement 不含 `$`），以及最终 fresh modify record 和可选静态 header 操作。已有 String 初值的顶层 `let` 还可执行独立的 `s = s.replaceAll(search, replacement)`，receiver 必须是同一 mutable binding，两个参数继续满足上述单 ASCII 限制；每次赋值生成新的不可变值，旧别名保留原版本，未使用的替换仍执行原 tick／work 动作。所有声明和表达式均参与证明；仅允许下述完整只读 header／body guard 前缀，其他分支、循环、赋值、动态 header、未知节点或分析上限一律不生成计划。完整源码合法性及 JSC 生成不变，不按脚本名、域名、变量名或具体替换字符识别。输入不是有效 UTF-8 text，或所需 metadata 无法完整分类时，在执行前选择 JSC；不按脚本种类推定 guard 为真，也不删除 guard。

可选只读 header guard 前缀必须整体符合：一个独立 `let flag=false`，一个从0遍历 `input.request.headers` 或 `input.response.headers` 全部行的 `for`（仅前缀／后缀 `++`），循环体只用严格 `===`／`!==` 的 name/value 字面字符串比较及 `&&`／`||` 设置 flag=true，随后 `if(!flag)` 仅返回 fresh pass 或 abort，再执行原 String tail。变量名和完整 Unicode 比较字面量通用；所有未知读写、额外语句、别名／shadow／其他控制流或分析上限都让整个调用在执行前选 JSC，不允许部分执行再回退。flag即使已为真也必须继续读取全部后续行，谓词按实际短路顺序求值。

可选只读 body guard 位于该 header guard 之后、String tail 之前，也可独立使用。它只有一个不带 else 的 `if`，条件成立时只返回 fresh pass 或 abort。条件限于 `input.body` 的 truthiness、`input.body.kind`／`typeof input.body.data` 与完整字符串字面量的严格 `===`／`!==` 比较、`input.body.data.length` 与有限数值字面量的严格比较，以及这些条件的 `!`、`&&`、`||`；比较允许字面量位于任一侧。它只借当前 Entity 的有效 UTF-8 text 和实际 metadata，不读取诊断 metadata 中会被真实后端覆盖的 data 值。kind 不是 text、正文缺失／非法 UTF-8 或 metadata shape 不受证明时仍在执行前选 JSC；业务原有的正文不可用 skip 不变。

body guard 按源码短路顺序执行各次 Get，不提前执行 tail，也不预先假定返回路径。body、kind／typeof-data、data-length 叶分别保留2、4、6个受控 tick；严格比较、否定和逻辑运算不额外增加 helper tick。长度按 JavaScript UTF-16 code units，只有 guard 实际读取 length 时才计数；Unicode 计数受原取消／期限检查，不复制正文。`!input.body || input.body.kind !== "text" || typeof input.body.data !== "string" || input.body.data.length !== N` 的完整检查保留16ticks，不把 UTF-8 字节数当作 length。早退沿原 pass／abort 的 record／Finish 费用执行，header 早退时不执行 body guard；整个函数仍只有一个入口 tick。guard 与 String 节点合计受原128节点上限约束，深度上限保持64。

执行前要求相应 headers 是真实数组，最多 `headers::MAX_FIELDS` 行，每行只有 name/value 两个字符串字段，按现有 `headers::MAX_BYTES` 统计完整边界。缺少 response、缺字段、非字符串、额外 shape 或超界选择 JSC；不能把缺失当空数组或先制造异常。只借当前 invocation 的 metadata，不复制／缓存头，不再大小写折叠字面量；生产 snapshot 本身已将 name 小写、value保留原值。原生和此前脚本修改后生成的新 snapshot 必须可见。正文不可用仍沿用业务前置 skip。

整个函数仅一个入口 tick。循环每次 test7ticks，进入1tick，每个实际比较叶8ticks，更新4ticks／16work，并包括最后失败 test；n行、M个实际叶的 guard 额外费用是 `12n+7+8M` ticks／`16n` work。Guard 不匹配时仅构造 pass／abort 与 Finish，跳过全部 tail 动作及正文写出；连同入口／循环，早退为 `14+12n+8M` ticks，work分别 `142+16n`／`144+16n`，结果正文长度0。原独立输出和有界 tail state 的真实预留仍先取得并持有至实际 owner 结束，不能提前退款。匹配时只跳过 tail 内原重复入口，其余动作、配额和 All recipe 原样。

闭合计划对有效 UTF-8 text 逐字节执行单 ASCII 搜索／替换：非 ASCII UTF-8 字节不可能匹配 ASCII 搜索，替换保持字节数与 Unicode scalar 的 UTF-16 起点。字符串大小 fuel 按原可信运行时的 UTF-16 循环起点计数，包含跨 256 单元边界的 surrogate pair 跳步；仅长全 ASCII 保留原有快速计数。正文上限、输出容量与替换 allocation-work 继续按 UTF-8 字节计，不改成 UTF-16 长度；中文、emoji、组合字符和 NUL 不因此回落到 JSC。

平台预热在完整源码静态编译之后判断。活动列表仅在每项都声明 `body: text`、完整 AST 得到闭合 UTF-8 计划，且可选 header guard 符合声明 phase 时，才省去 JavaScriptCore 的提前初始化。证明结合每项原有 phase 与 body 声明，不按脚本名、URL 或流量样本判断；bytes、none、省略 body、request 阶段读取 response headers 的 guard、其他有效语法或分析未完成的任一项均保留原预热与运行时回落。已有语法和平台 capability 检查、禁用声明校验及取消检查保持；非 Apple 平台的支持范围不扩大。无 guard 覆盖两阶段；读取 request headers 的 guard 覆盖两阶段，读取 response headers 的 guard 仅覆盖 response 阶段。Guard 的总覆盖仅适用于私有 Message 的业务 metadata：每次选择后端前重新校验当前 request／response headers，生成有界的 `{name,value}` 字符串行，重复值逐行保留，合法 Unicode 不有损替换。response 消息仍有必需的 request 快照；不存在的 response 不能当空数组。任意诊断 JSON 仍经过原 rows 检查，所需数组或行字段缺失、行含额外字段、错误类型或超限继续在执行前回落；不参与 guard 读取的外层字段沿用原行为，不据此扩展业务证明。该判定只避免本进程尚未发生的初始化，不能卸载已初始化的 JavaScriptCore 或降低历史 RSS 峰值。

计划选定后，Rust 只持有原 Entity 的有账本见证借用、结果精确字节界限的 BudgetedBytes 和预付的有限视图状态 Vec；没有 JSC 输入/API 临时或 retained 字符副本，因而不为这些不存在的副本预留 bridge。源正文与结果仍独立计费，Bytes 的最后发送／slice owner 释放前许可不退款。计划用同一受控动作序列保留入口、声明、调用、字符串与结果 Measure/Finish 的 tick 及 2 MiB 累计 allocation-work；不可变视图避免中间正文复制，但不取消对应语义 work 计数。预算、取消、期限或已选计划的任何失败均回滚该次调用，绝不再执行 JSC。最终 metadata／正文仍经公共事务校验，原生→脚本顺序、U0 匹配和阶段期限不变。

Plan 的调用只把实际输出 payload 分配移至同一执行 lane 取得之后。排队前仍从同一账本非等待支付原有输出 owner 的固定 bookkeeping Q；它是每次调用独立的有限准入，不能依赖输入 Bytes 是否共享。同一账本内的等待者数量因此仍有 floor((4 MiB−其它实际信用)/Q) 的绝对界限，不引入零付费执行队列、新 lane 或经验配额；较大正文的实际队列深度仍可能改变。取得 lane 后，非等待 reserve 输出界限 O，与 Q 合并为精确的 O+Q，再创建唯一真实输出 backing；不经会瞬时占两个 owner 的 prepare_output。Unix 的已选 Plan 在输出容量至少 64 KiB 时使用 safe memmap2 匿名映射，较小容量和非 Unix 保持 Vec；映射失败在同一 reservation 下尝试原 Vec，均失败仍在任何 action 前跳过本次调用。其他原生 String 转换及 JSC 输出保留原 Vec 路径；已知共享 collector 在下述 Apple 范围复用相同的有界字节 backing，Plan 与上述已证原生 ASCII byte-map 仍使用原初始化字节写出，不隐式转换成未付费 String 副本。输出按逻辑长度暴露字节，容量及实际 owner 本体大小仍完整计入原账本；backing enum 的实际大小变化也计入 Q，不硬编码旧值。lane 与首次取得时的绝对 deadline 同步持有至真实操作返回／展开，后端不能再排队或重给 100 ms。输出分配现也消耗该原有期限。payload 预算不足或分配失败在任何 Plan action 之前按本次 CallBuffers 失败跳过、保留输入，不重跑 JSC；取得 lane 不保证新 collector 未占用所需额度。JSC 分支保留原先完整输出／bridge 准入后才排队的顺序。

映射不缓存，也不改变输出最后 Bytes／slice owner 的释放边界：backing destructor 完成后才退款；安全依赖在析构中执行 unmap，不提供 OS 释放成功或 RSS 下降的回执。请求容量不是页粒度的物理内存上界，每份映射的末页 padding 小于系统一页，页表、Bytes owner 包装与 allocator 元数据另计；4 MiB 为正文逻辑账本，不据此宣称进程内存达标。

计划最终正文的完整祖先链仅含 Input／ASCII literal／replaceAll 时，可保存有限的静态写出步骤：以原有输入或 literal 节点为源，不复制源码常量；每个256字节输出块先执行原取消／期限检查，复制到独立、已付费输出，再按原先后顺序逐项单ASCII替换。仅有一个All步骤时，每块直接从不可变源逐字节选择replacement或原byte并无条件写入独立输出，省去先复制再原地条件写的两遍过程；判断只依配方长度，不按字符、名字或脚本特化。零步或多个All步骤保持原copy及有序逐步循环。含First replace的最终祖先链继续用原不可变DAG逐字节写出，不改变Plan或JSC准入。所有原actions（含未使用声明、First扫描、tick、allocation-work、Finish及header验证）仍先完整执行，不能因最终写出较快而省略或退款。写出不增加逐调用正文或状态分配；此实现只提供普通连续循环，不承诺向量化或吞吐收益。

多线程 Tokio runtime 在持有同一执行 lane 时，JSC 分支仍为每次求值创建有作用域的 OS 线程，全部 JSC 对象在该线程创建、使用和释放；线程/TLS 退出并真实 join 后才返回及归还 lane、借用缓冲和实际存在的桥接许可。纯 Rust 计划在多线程 runtime 配置的 worker 多于一个时沿调用者同步栈直接执行，配置单 worker 时仍经 `block_in_place`；不创建逐调用脚本 owner 线程、不请求 QoS，也不脱离父 Future；lane、输入和输出 owner 在实际操作返回或 panic 完成展开前保持。直接执行只由稳定公开的 runtime worker 数决定，不读取 CPU 数或覆盖 worker；同一执行 lane 仍限制真实后端并行，不保证其它 worker 当前空闲或全部任务及时进展。内存分配、触页、同步日志和系统调度可能停顿；BIP 路径仍可为调度移交复用或创建替代 worker，因此不承诺进程线程数或 RSS 不变。线程启动、调度和同步操作仍使用原绝对期限；JSC 线程创建失败按该次调用失败处理，panic 保持展开语义。单线程 runtime 保持原同步执行，不调用 `block_in_place`。不引入 VM/context 池或新的并行 lane。

直接执行条件成立的业务 Plan 在取得同一 lane 并实际 materialize 已付费输出后、同步求值前仅执行一次 `yield_now().await`；能力判定复用同步 helper 的同一公开 runtime 查询，不复制 CPU／worker 规则。lane、借用输入与实际输出 owner 在挂起期间仍由该 Future 持有，原 acquire 时确定的 100ms／phase 绝对期限不重新授予；恢复后仍由原 Plan／phase 检查处理取消或过期，丢弃 Future 则同步释放其输出与许可，不提交候选元数据／正文。current-thread、单 worker BIP 和 JSC 不新增此让出点。让出并不保证驱动 IO、先运行其它任务或在固定墙钟时间内恢复；不能把合作期限称为抢占上限。该让出发生在 lane queue 计时结束后、Plan helper 派发计时开始前，不能用两者之和宣称覆盖这段额外等待，也不将其标作 BIP 成本。

## 编译期诊断

Apple 多线程运行时的临时 JSC 执行线程请求公开 `USER_INITIATED` QoS；诊断套件中显式创建的 Plan 参考线程仍按其真实 scoped 路径记录。
脚本路径不再次修改准备阶段预热线程或 Tokio 父线程的 QoS，生产 Plan 内联执行也不逐调用设置。业务 runtime 自有线程另遵循启动时的 Apple 运行时 QoS 策略；脚本 scoped owner 的请求失败仍执行原调用，不改变结果、期限或回退。
可选诊断的 `scopedScriptOwner` 记录请求结果及可用的当前线程 CPU；getter 只反映请求类，
不证明有效优先级、CPU 核选择或频率。`timings.scopedOwner` 从用户 owner 创建前计至实际
线程/TLS 结束和 join 返回，含其中的求值，不含排队与 HTTP 流水开销；不得与嵌套计时相加。

非默认 Cargo feature `http-diagnostics` 提供隐藏的 Rust 观测入口 `http_processing::diagnostics::snapshot()`；默认构建不保留计数器或新增采样时钟。同时启用 `invoke` 时，可通过本地运行时级 [`getHttpDiagnostics`](invoke-api.md#gethttpdiagnostics仅-http-diagnostics-构建) 读取同一快照；默认构建仍按未知方法失败，不增加 Controller API。读取不要求或执行初始化，不创建实例、运行时、网络资源或 JS 执行环境，不改变脚本、排队、正文准入或错误回退。固定字段按进程寿命累计，不按 URL/脚本名扩张，不保存正文、头或私密材料，也不提供并发 reset。

TUN 入站另计已消费读前缀中的成功解帧包和 `InvalidPacket` 结果、MTU 丢弃、
netstack 实际接受与最终背压丢弃。成功解帧不代表完整 IP／TCP 校验通过；UDP／本地
ICMP 等旁路和停止阶段已读但未转交的前缀也不能误算为 netstack 丢包。
诊断构建还计完整 IPv4／IPv6 基本头声明长度大于实际读切片的次数，不使用缓冲容量，
不验证 options／jumbo／校验和，不据此单独认定传输丢包。所有观察均不改变现有转发条件。

同时启用 TUN 时，`http-diagnostics` 转发非默认的 `vole-netstack/diagnostics` feature，
仅为被动 TUN driver 安装整数回调。`tunNetstackDriverDrivePasses` 记录完成的 drive，
`TcpEntryVisits` 记录其中维护访问的 TCP entry 数；同前缀的 `AppRxBytes`／`AppTxBytes`
记录 socket 与应用队列间实际移动的 TCP payload，方向分别是 raw IP 到应用和应用到 raw IP。
`NoDataProgressPasses` 表示没有移动应用字节且没有输出包，协议状态仍可能前进。
`WaitIngress`／`WaitNotify`／`WaitTimer` 只记录实际选中的正常工作来源，
不计 Pending、EOF、取消或主动 client 命令，不能解释为等待时长，也不要求与 drive 数相等。
每轮先局部累计再提交固定计数；feature 关闭时移除这些观察，启用但未安装回调的 stack
仍有局部统计成本。字段按进程累计，区间包含 drain／Stop 时不得称为精确 active 窗口；
payload 字节不等于完整 HTTP 交付或实际 900Mbps 准入，缺失字段不作零值解释。

快照覆盖匹配/跳过原因、完整 CallBuffers 组合准入及 input/最大 output/bridgeWorkspace 请求量、独立桥接准入失败、ASCII 视图请求/准入/预算回退、排队和实际求值结果、正文收集/解码/原生转换失败点、context 生命周期，以及成功和失败的六段求值时间、最终 JSON 解析、context 释放、整体求值时间和 tick 汇总。各段是当前实现的实际边界：context 段含 callback 安装，invoke 段含结果整理；整体时间另含最终检查、解析及清理，阶段总和不保证等于整体时间。求值计时从后端进入开始，不含排队及 scoped 线程启动/join；调用者总耗时和吞吐须另行测量。计时单位为微秒，固定聚合只含次数/累计/最大值；不是分位延迟或逐请求追踪。

最终写出入口另计 `planFinalRecipeEntered`／`planFinalDagEntered`，单步配方入口另计子集 `planFinalSingleStepEntered`（含空结果，仍不表示成功）；在所有语义actions成功后、实际fill入口计数（含空结果）；它不代表本次完全未用DAG（未使用First声明仍可能扫描DAG），也不代表Plan成功、Message提交或完整交付。

只读前缀另计 `planHeaderGuardEntered`、`planHeaderGuardTail`、`planHeaderGuardPass`、`planHeaderGuardAbort`；后三者只记录对应路径成功到达，不覆盖中途取消／期限／预算失败，不能称为 JSC 求值或完整交付。

后端选择另计 `jscSelected`、`planSelected`、`planInputFallback`、`planAstFallback`；已选计划缓冲拒绝为 `planBuffersRejected`，实际开始及结果为 `planEntered/Succeeded/TimedOut/Cancelled/Failed`。Plan 不计入 JSC evaluation、context、tick 或六段 JSC 时间。scoped owner 的 started/joined 按 `jscOwner*`／`planOwner*` 分项，joined 只在真实线程退出（含 TLS）后记录；`scopedOwner` 总耗时及 `jscScopedOwner`／`planScopedOwner` 分项包含启动、调度和 join。单线程同步路径和生产内联 Plan 不伪造 scoped owner。多线程 Plan 的 `planInlineEntered/Returned/Panicked` 只计共同同步 helper 内的真实操作；Returned 包含正常返回的 Ok/Err，panic 记 Panicked 而非 Returned，静止后应满足 entered=returned+panicked。`planInlineWall`／可用的 `planInlineThreadCpu` 计该操作至其局部清理，`planInlineCpuUnavailable` 明确缺失 CPU 样本；独立 `planInlineDispatchWall` 包含所选直接执行或 BIP 策略的派发和返回，不单独代表 BIP 成本。它们与 scoped owner 时间范围不同，不相加；Returned 也不表示 caller 仍持有的结果或最后 Bytes owner 已释放。无诊断 feature 时这些采样不进入热路径。

Plan 延迟输出另计 `planOutputPendingAdmitted`（只有固定 Q 已付费，不能称完整 CallBuffers 已准入）、`planOutputQueueFailed`（lane acquire 明确返回错误）及 `planOutputPayloadBudgetRejected`（lane 内非等待 payload 预算失败）。`callBuffersRequested` 仍记录期望完整输出成本，`callBuffersAdmitted` 仅在 payload／实际 backing 成功后增长。父 Future 在排队中被丢弃时，Q 与原 QueueGuard 按实际 Drop 清理，但不伪造一次 acquire 返回错误，因此不能用上述三个字段强求覆盖所有丢弃路径的等式。它们不改变正文额度或错误回退。

平台初始化另计 `platformWarmupRequested/Started/Succeeded/Failed` 与 `platformWarmupContextCreated/Released`，不并入用户求值的 context、queue、tick 或六段计时。成功标记只在初始化线程 join 后发布；真实屏障后应满足 started = succeeded + failed、warmup context created = released。

各字段独立采样，活跃快照不保证跨字段一致；生命周期守恒应在真实 Stop 屏障后检查。`bodyWorkspace.current/peak` 是跨账本的影子 telemetry，分配/释放与采样存在窄排序窗口，peak 不等于单账本硬上限；`maxSingleBudget` 来自真实成功准入时的账本占用。额度仍由原账本控制并随最后 Bytes owner 释放，这些数值均不是 JS heap、RSS 或 Network Extension footprint。

同一诊断快照另含固定的 `tunWriteSingle*`／`tunWriteBatch*` 计数：`SendAttempts`
在实际调用平台 send 时增长，`AcceptedPackets` 仅计完整写入的包；后者不证明对端交付。
`EnobufsErrors` 记录 Apple 返回的 ENOBUFS，`Sleep1msRequests` 仅记录随后请求的退让，
不表示完成睡眠或实际等待时长；`WouldBlock` 记录 send 返回 WouldBlock 后的 readiness 分支。
重复错误不代表不同包，尝试／接受／错误的差不能当作丢包量。这些字段不改变重试策略，
默认构建不保留计数。按同进程前后快照作差仍须标明实际区间，包含 drain／stop 的区间
不能冒充精确的 active 窗口；未经过该平台路径的零值也不证明平台能力。

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

Apple 上，已知 wire 长度的共享 collector 在原容量为 64..256 KiB 时尝试安全匿名映射，映射失败在同一已付费 reservation 内回退 Vec；未知长度保留 MAX_BODY+1 的 Vec 哨兵，独立原生 collector 入口和小正文保留 Vec。原生正文与 metadata-only JS 并用时仍属于共享入口。逻辑长度从零开始，只按实际接收字节增长，容量不证明 EOF 或上传完成。映射不缓存，不改变读取、回放、解码、事务回退、最后 Bytes owner 和退款顺序；页粒度、页表和分配器开销仍须按真实进程 phys_footprint 单独验收。

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

下游 rustls 写侧缓冲使用统一 TLS 默认值 64 KiB；这是 HTTP 上下文的固定默认策略，不接收节点或低层调用者的容量覆盖。它与 TUN 发送缓冲、H2 窗口及 4 MiB 正文账本分别计量；正文许可继续持有至实际发送 owner 释放，TLS 局部容量不代表进程 physical footprint。

H1 上游协商 HTTP/1.1，H2 下游对接实际协商的 H2 或 H1。普通 H2 CONNECT 返回 405；WebSocket 使用 H1 Upgrade。叶证书最多 32 项、材料预算 256 KiB、空闲 10 分钟，有效期不超过 24 小时或 CA。

明文 H1 与成功终止 TLS 后的同 origin HTTPS H1，可在同一下游连接的固定 HTTP 上下文中保留至多一个上游。HTTP/1.1 的空正文或固定长度普通请求允许尝试复用；原始与最终方法均不能是 HEAD／CONNECT，且不接受 asterisk target、Expect 或 Upgrade。原生和 JS 请求正文处理保持；完成处理后再次确认最终 framing 与 keep-alive，只有真实上传成功完成并 flush、响应原始正文完整消费后才保留上游。每个请求仍先授权原始 authority、完成规则与脚本，再做一次实际选路。只有相同最终 scheme／host／port、路由与静态 connector 安全身份、固定资源代际一致时才可使用旧流；未提供可证明复用身份的出口保持单次连接。持久连接资格不取决于请求幂等性，已提交请求仍不自动重放。

H1 上传的最终响应优先于上传 Future 返回时，仅对真实原始定界和输出均为固定长度、未替换来源且已进入末次正文 flush 的路径，非阻塞补 poll 同一 Future 一次。实际 Ready(Ok) 才纳入上传完成；Pending 或错误保持原响应优先及关闭行为。已预收集／改写的输出仍须完成所有实际写入，原始来源完成或输出长度本身不能替代这个证明。操作不等待 Pending、不重新建立期限、不继续读取下一请求；路由身份、响应原始消费和缓存退役条件独立保持。

静态身份支持原有内置 DIRECT，以及物理路径可证明固定的 HTTP／HTTPS CONNECT、SOCKS5／TLS、无插件、simple-obfs HTTP/TLS 或固定 ShadowTLS v3 身份的 SS2022、VMess TCP／WebSocket／gRPC／单 URI legacy H2／固定明文 HTTP 首包伪装、Trojan TCP／WebSocket／gRPC、Hysteria2、TUIC、Mieru、WireGuard、MASQUE 和 VLESS 的实际静态流／XHTTP 腿。VMess 的明文与普通 TLS、Trojan 的普通 TLS 可参与；它们的 REALITY／JLS／ShadowTLS、VMess TLS HTTP 伪装／多 URI 或多头值候选 HTTP 伪装／多 URI legacy H2 和 AnyTLS 的擦除自定义连接器尚不提供此证明，保持单次业务 HTTP 路径。VLESS 的固定 REALITY／JLS 只由自身可信构造证明，不能据此扩大其它出站的共享安全能力。代理服务器的实际物理目标须为字面 IP，实际保留的预解析端点须精确匹配单一地址；静态代理链的每层均须明确提供相同证明，未知包装器和 `dialer-proxy` 策略组不参与复用。非默认地址族策略、protect／接口／源地址等原有受约束出口、非 macOS 的 `mptcp: true`、已停止的 Dialer、文件客户端身份和动态 ECH 保持单次路径，不为性能绕过保护。业务目标仍可为代理端解析的逻辑域名，不为制造复用 key 改成本地解析。路由层策略组仍逐请求确定实际叶节点与链，叶节点、规则、入口身份、最终目标或资源代际变化不能沿用旧流；此证明不更改代理协议本身的载体池或健康探测活动计时。

sing-mux 包装器仅在自身未取消且内层连接器的完整静态身份已获证明时，传递同一业务 HTTP 复用资格。路由、包装后的具体节点、资源代次、入口和最终 origin 仍由原有 key 校验，真实 request／response close、未完成正文和早响应仍沿原退役条件处理。保留的 HTTP 上游继续持有原 mux 逻辑流和 lease，直到该下游结束、退役或 Stop。

缓存中的空闲 HTTP 上游仍是活动逻辑流。Brutal 单物理会话与 yamux 累计 64 流退役同时适用时，旧 lease 的存活可延后新物理会话的建立；等待仍受新调用的原 setup 期限和 Stop 约束，缓存不重置期限或绕过池的退役规则。

Hysteria2 的业务 TCP 也可在固定 TLS 身份、字面 IP 的直接物理 UDP 路径上提供上述静态证明；其 QUIC/协议池、带宽、拥塞、定时器与所有者阈值保持。ports 跳跃和 Realm 发现、文件客户端身份、动态 ECH、代理/组 UDP 上游及已停止的节点或 Dialer 保持单次路径。此资格只用于保留已建的同 origin 业务 HTTP/TLS 流，不扩大业务 UDP 或外层池能力；缺少 inbound-http 或 outbound-hysteria2 时不增加能力。

TUIC 的业务 TCP 在固定 TLS 身份、字面物理 IP 和可证明固定的直接 UDP 上游上提供同一静态证明。
逻辑 server/SNI 为域名时，可由显式字面 ip 固定实际物理目标；未固定的物理域名、Proxy/Group UDP 上游、
文件客户端身份及已停止的节点或 Dialer 保持单次路径。native、quic 和 UoT 配置不改变普通业务 TCP 的
此项资格；UDP/UoT 本身不进入业务 HTTP 复用。已支持的外层静态 TCP 连接器可沿原证明链依赖此 TUIC 叶。
HTTP 父级仍逐请求授权与选路，校验 origin、路由/资源代际和完整上传/响应；实际保留的 TUIC Stream 继续
持有同一会话 lease，直到退役、下游结束或 Stop。QUIC/协议池、握手、半关闭、UNI、UDP、队列、预算和
期限不变；缺少 inbound-http 或 outbound-tuic 时不增加此资格。

Mieru 的业务 TCP 按实际载体提供静态证明：工厂须为单物理端口、固定凭据与编译后的不可变 traffic-pattern；TCP 载体要求完整静态 TCP 上游图，UDP 载体只接受固定直接物理 UDP 路径。端口范围、域名／动态组、未知依赖与已停止 client／Dialer 保持单次路径。multiplexing 和 STANDARD／NO_WAIT 只控制新逻辑流，不改变已保留流的目标、身份或取消所有者；NO_WAIT 首写仍先完成原 SOCKS 应答验证，不能跳过认证或提前发布失败连接。此资格不更改底层载体池、随机调度、可靠性、信用、计时器、缓冲或业务 UDP 能力；缺少 inbound-http 或 outbound-mieru 时不增加能力。

WireGuard 的业务 TCP 逐一证明完整私有配置中的所有实际 peer，而非代表性首端点：密钥、PSK、reserved、路由、本地地址、MTU 和私有 DNS 由已验证节点的不可变快照固定。每个 peer 均须为字面 IP，按驱动实际 `for_server` 派生初始及适用的 refresh 路径，并通过相同的直接物理 UDP 证明；域名 peer、上游代理／组、未知或受约束／已停止的 Dialer、已停止节点保持单次路径。初始 Direct 不属于该 peer 时，原驱动使用同一 Dialer 的 LazyDirect；匹配但非单一地址的 Direct 不参与。固定字面 refresh 沿同一不可变 IP4P 策略取得相同实际地址和端口，驱动保留原外层会话；不因此支持动态端点或认证漫游。结构资格不查询或初始化 engine，也不证明 channel 健康；真实业务 IO 仍绑定其 peer 取消所有者，失败沿原 H1/H2 退役路径传播。此资格不更改 Noise、栈、队列、正文预算、端点刷新、节点私有 DNS、业务 UDP 或 Stop；缺少 inbound-http 或 outbound-wireguard 时不增加能力。

HTTPS 的 URL 处理必须始终保持原 origin；原生或任一次已接受 JS 操作跨 origin／scheme，即使后续改回也保持单次连接。新上游仍按最终 host 进行真实 SNI／证书验证，实际 ALPN 仅接受 HTTP/1.1 或原策略允许的未协商值，握手成功后才可能保留流；不同上下文、安全配置、authority 不共享 TLS 连接。TLS ticket、客户端证书与验证策略不变，不新增全局池或跨 origin 证书合并。

MASQUE 仅在真实连接工厂固定已解析的服务端 SPKI、客户端 ECDSA 身份、URI 与全部物理路径时提供静态证明。H2 沿实际 TCP 上游图递归检查；H3 IP／L4 仅允许同一固定直接 UDP Dialer。动态服务器域名、上游策略组、未知连接器、受保护／绑定／非默认地址族或非 macOS 的 `mptcp: true` 等路径保持单次业务 HTTP；节点或依赖停止即撤销资格。资格查询不创建 engine、解析或 socket，也不证明连接仍健康。保留的业务 TCP 继续持有原 engine／L4 请求及取消 owner；私有 DNS 对新连接的解析、H1/H2 失活退役和真实 Stop／join 不变。

上游原始 HTTP/1.1 响应还须无 close／特殊状态／Content-Range／trailer，并有完整 Content-Length 消费和空的剩余读缓冲。EOF、无请求对应的额外字节、传输／定界错误、Upgrade 或请求／响应 close 退役该流；预发送健康检查不承诺消除随后断流，已发送请求失败不自动重放。保留的 TLS／物理流与正文 owner 沿原取消及 Stop 屏障真实释放，不新增后台 driver 或线程。

H2 每连接最多 8 个活动请求，下游请求的流／连接接收窗口为 64／64 KiB，上游响应的流／连接接收窗口为 64／64 KiB；头最多 32 KiB／100 字段，帧 16 KiB，关闭动态 HPACK 表。单个下游请求流可占用全部连接接收信用，同一连接的全部流仍共享 64 KiB 未归还 DATA 上限。接收信用限制尚未归还的 DATA，不限制已复制正文、TLS 或整进程内存。下游响应每流发送队列的 capacity 背压上限为 64 KiB，每次预留和 DATA 提交仍最多 16 KiB；只有对端流／连接信用允许时才能继续排队。该局部上限不预分配整份 payload，也不是 wire SETTINGS、接收窗口或连接总内存界。业务上游 H2 client 的发送缓冲仍为 16 KiB。上传使用 30 秒无进展期限；上传完成后响应头另有 30 秒等待期限，提前响应仍与上传并发。取消和 Stop 覆盖上下游、正文与驱动。

完整改写正文的队列切片共享已付费 Bytes backing，许可持有至最后实际发送／切片 owner 释放；流式未改写正文则可能因较多排队而保留更多传输帧。codec、TLS 与 TUN 缓冲仍分别计量，64 KiB 队列不代表零新增分配或进程 footprint 保证；共享 4 MiB 正文账本、实际背压、取消与 Stop 屏障保持各自约束。

H2 上游请求在实际正文源已到达结束、没有待转发前缀／正文／trailer／接收信用，且预期长度为未知或零时，直接以 HEADERS 的 END_STREAM 结束上传并启动原响应头等待期限；不另发空 DATA。资格不依赖方法、URL 或脚本名。其余请求保留原正文／trailer relay、长度校验、提前响应和取消语义；共享与单次 H2 交换使用同一路径，不改 H1 回落、窗口、发送队列、正文账本或任何期限。

VMess／Trojan 的证明还要求节点所有者未取消，普通 TLS 的实际客户端身份为内联且 ECH 非动态；VMess legacy H2 还须恰有一个固定完整 URI，多 URI 保持原逐流 authority 选择和单次业务 HTTP 路径。协议自有 gRPC 池、legacy H2 driver 及其逻辑流所有者保持原样，不创建额外载体或放宽信用。一个保留的业务连接继续拥有原逻辑流，不能在每个 HTTP 请求结束时提前归还载体；节点 Stop 仍撤销资格并按原屏障退出。VMess 记录计数沿既有 16 位回绕合同，不因 HTTP 持久连接增加自动重连／重放或新的 nonce 唯一性保证。

H2 下游对原始与最终均为空正文或有明确长度的普通请求、最终同 HTTPS origin 且无历史跨 origin／Expect 的请求，尝试同一下游固定 HTTP 上下文内的上游 H2 复用。原始与最终方法均排除 HEAD／CONNECT，asterisk target 保持单次路径；原生和 JS 请求正文处理不因此禁用复用。每请求仍先授权原始 authority、完成全部规则／脚本，再取得一次真实选路计划；只有相等的上述静态 connector opaque 身份、资源代际和最终 origin 可使用旧会话。不做跨 authority 证书合并；最终 host 的 SNI／证书验证和真实 H2 ALPN 通过后，driver 先登记到下游父级并确认所有权，才能发布 sender。协商 H1 或未协商 ALPN 时，将已连接的原 IO 交回原单次 H1 路径，不重拨；其它协议失败。

共享 H2 交换分别证明上传和完整响应完成。只有已成功提交 HEADERS 的 END_STREAM，或正文 relay 实际成功完成长度、trailer、信用及 END_STREAM 处理，才证明上传完成。有效最终响应先于上传结束、最终响应头后的上传错误、取消或展开均退役该会话的后续准入；不能将响应成功当作上传成功。提前最终响应和晚到上传错误仍沿原行为完成有效响应，不为缓存资格替换响应或重放请求；当前与兄弟在途租约继续持有原 driver／IO，直至各自完成或失败。此证明不增加后台任务、并行槽、队列、预算或期限。

每个下游只有一个可接新请求的会话入口；退役会话由已在途的局部租约持有至完整响应／失败结束，最后租约释放后父级真实丢弃其 driver／IO，不依赖对端自然关闭。所有 driver、注册消息和请求 future 均由原 serve_h2 父级内联轮询，包括空闲 PING／GOAWAY 和八槽占满期间；不增加后台任务、全局池或请求数量配额。进入可复用候选比较时，路由／origin 不匹配或已失效状态退役旧入口；GOAWAY／ready／传输错误被本次共享交换观察到时也停止旧入口接收新请求，已提交或失败的请求不自动重放。不符合资格或无可证明 key 的单次路径不等待复用锁，也不为了该次转发主动清除既有空闲入口；它可跨越无关的单次交换保留，后续使用仍须重新取得相等的当前路由 key 与精确 origin。初始化锁等待与 TCP／TLS 共用原 10 秒绝对 setup 期限，H2 handshake 及登记／首 ready 共用下一原 10 秒期限；命中会话的 ready 使用本请求的原 setup 期限，等待期间不重给期限。正文工作区与最后 Bytes owner 不变；取消、EOF 和 Stop 在返回前释放全部注册／request／driver IO。保留空闲 TLS／H2 状态可能增加实际进程内存，仍须独立满足整进程内存验收。

当前会话固定主设置、实际 payload、授权和 CA。保存／资源刷新只产生待应用候选，节点选择和分流更新继承 active。显式重连准备候选后切换，后续启动失败使用旧实际内容恢复，不重读已变化文件；普通 Stop 释放私密材料。共享入口见 [Invoke API](invoke-api.md) 与 [CLI](cli.md)。

VLESS 的业务 HTTP 复用身份逐一证明真实上传和显式下载腿：固定的明文／标准 TLS／REALITY／JLS 安全身份、字面服务器和完整静态路径，且节点及各 XHTTP owner 未取消。XHTTP H1/H2 载体使用 TCP 路径证明；XHTTP H3 按各实际 XHttpClient 版本使用直接 UDP 证明，不能按 VLESS 内部的 Tcp 占位传输推导。文件客户端身份、动态 ECH、未知依赖／上游组和 ShadowTLS 保持单次。此资格不按 Vision、XHTTP mode 或基准组合特化；REALITY／JLS 的允许只在 VLESS 可信构造接缝内，不扩大其它出站的共享安全能力。JLS 还要求该腿实际持有成功构造的不可变 Boring JLS 客户端，不能只凭配置模式取得资格；共享安全 helper 对 JLS 仍不提供证明。

Native／XorPublic／Random 外观的 VLESS Encryption 仅由实际构造的不可变 Client 提供上述静态证明；密钥链、外观、padding 与选定密码套件固定，Client 或节点停止即撤销资格。`1rtt`／`0rtt` 和票据更新只决定后续物理连接的握手，不重置已保留流的 AEAD／CTR／Vision 状态；票据过期不关闭该流。资格查询不查找或更新票据，不创建握手、任务或连接。它仍须通过原有每腿、物理路径、安全、依赖和 owner 检查，以及每请求的 authority／路由／资源代际确认；不增加全局池、不自动重放失败请求，也不改变载体池和任何预算。

Random 的记录头 CTR、AEAD 和 Vision direct 的持续解析状态均属于原逻辑流，不能按 HTTP 实体或 H2 stream 重置。关闭仍遵守其整流关闭语义，HTTP 实体完成不触发 shutdown；节点及依赖停止继续撤销复用资格并沿原 IO 取消路径释放连接。

macOS 的 `mptcp: true` 仍使用原普通 TCP socket 创建路径；该标记自身不禁止固定上游的业务 HTTP 复用，也不单独禁止 VLESS 私有 split-H2 两腿复用。共享静态证明的直接 UDP 载体调用同样不因该标记被拒绝；实际 UDP 路径不变。保护、DNS／源地址／接口绑定、地址族、安全身份、每腿端点和 Stop 检查保持。这不提供 macOS MPTCP 协商或多路径能力；其他平台仍按原 MPTCP 标记限制判断。

SS2022 的 simple-obfs HTTP/TLS 插件仅在实际固定 cover 与完整静态上游路径获证明、插件 owner 未停止时提供同 origin 业务 HTTP 复用资格；不将报文外观当作标准 TLS 身份。每条完整 SS／obfs 流绑定独立 child，包括 UoT；资格撤销后仍绑定已取消 child，避免建链完成与 Stop 交错时逃逸。原 HTTP 父级继续负责空闲连接退役与真实释放；同一流保持 SS AEAD、目标前导和部分 IO 状态，不按 HTTP 实体重新建立。其它插件的范围见下述限定；不新增载体池、任务、队列或期限。

SS2022 的 `v2ray-plugin` 仅在 `inbound-http` 下的无 TLS、`mux: true`、early-data 为 0、标准 WebSocket 固定传输提供同 origin 业务 HTTP 复用资格，仍须通过原有字面代理端点、完整静态上游和资源代际证明。完整 SS／单通道 mux／WS 流使用同一独立 child 与双向唤醒封装；固定类型决定绑定，Stop-before-bind 仍取得已取消 child，单流 Drop 不取消父或兄弟流。原 HTTP 父级负责缓存退役和真实释放；不按实体重发目标或 mux New，不增加通用 mux 池、任务或期限。WSS、early-data、无 mux、HTTPUpgrade／fast-open、Gost 和 JLS 保持单次路径。

SS2022 的首响应读取还单独适配官方 codec 的完整前缀合同，与 HTTP 复用许可无关：所有 feature 组合仅对实际 Obfs，以及无 TLS、early-data 为 0、标准 WebSocket、非 Gost 且启用 mux 的固定传输按 cipher 延迟聚合 59／91 字节密文。该前缀位于解 cover／mux 后，可跨合法 mux Data 与完整 WS Binary Message 边界；最多 91 字节内联存储，不超读正文，部分前缀 EOF 返回错误。该层不解密、不改变认证或写入、预算、期限、任务和取消路径，也不授予非 HTTP 构建复用资格。WSS、early-data、无 mux、HTTPUpgrade／fast-open、Gost、JLS、ShadowTLS 和裸 SS 保持原读取路径。

SS2022 的 ShadowTLS v3 插件仅在实际客户端持有固定 cover 策略及无客户端身份或内联身份时提供静态证明；文件轮换身份保持单次业务 HTTP 路径。共享安全 helper 的 ShadowTLS 资格不因此扩大。每条已建 SS／ShadowTLS 流持有插件 owner 的独立取消子令牌；丢弃单流不停止父节点或兄弟流，父停止撤销复用资格并唤醒等待读写，原 HTTP 父级继续负责取消、退役与真实释放。记录 HMAC、SS AEAD、目标前导及其部分 IO 状态由整条流持续持有，不按 HTTP 实体重建。

VMess HTTP 首包伪装的新增资格仅限启用 `inbound-http`、实际明文安全身份、单个固定 URI 和每个声明头单值（无头也固定）的完整工厂；保留原静态安全、字面代理端点、完整上游、路由／origin／资源代际和节点 Stop 门禁。完整 TCP 流在同一固定类型下持有原 child 与私有双向唤醒 owner，即使建链完成与 Stop 交错也不返回未绑定流；该 owner 只转发原读写／flush／shutdown 与错误，不改变请求／响应认证或整流关闭。HTTP 实体完成只归还既有业务 lease，不重发 cover、VMess 目标或重置 body codec；原 HTTP 父级负责退役及真实释放。TLS 和多选工厂仍为单次路径，UDP、共享 OwnedStream、传输、队列、预算及期限保持原样；缺少该 feature 不新增状态、资格或绑定。
