# HTTP 处理

HTTP 处理只作用于 TUN 和 mixed-port 的业务 TCP。Core 自己的 DNS、provider、GeoData、
节点握手及 Controller 请求不进入该路径。关闭时不创建 CA、证书缓存或后台任务。

## 独立输入

主配置仍使用 Mihomo YAML。`validateConfig`、`start` 和 `updateConfig` 可另外传入
`httpConfigYaml`；CLI 的 `-http-config PATH` 由 foreground 读取该文件，不自动搜索。
附加配置最多 1 MiB，和主配置一起验证、发布，失败保留当前运行代。
`updateConfig` 省略附加输入时继承当前值，显式空字符串关闭；provider 刷新继承同一策略。
Windows Session Host 从同一个不可变启动 Snapshot 读取附加输入，运行时更新不改变旧 token。

```yaml
http-ports: [80, 8080]
rewrite:
  - pattern: '^http://old\.example/(.*)$'
    action: replace
    replacement: 'https://new.example/$1'
  - pattern: '^https://private\.example/blocked$'
    action: reject
mitm:
  domains: ['private.example', '*.example.net']
  exclude-domains: ['excluded.example.net']
  ports: [443]
  certificate: | # 用户提供的 CA 证书 PEM
    ...
  private-key: | # 匹配的 CA 私钥 PEM
    ...
```

`mitm` 可省略；CA 私钥由 App/宿主管理安全存储与信任安装，Core 不生成或安装根证书。
附加输入包含私密材料，不应作为普通代理订阅分享。Controller 查询、日志和 Debug 不返回其原文。

## URL 动作

规则按顺序匹配完整规范化 URL，只执行第一条，不递归改写。动作包括 `replace`、
`redirect302`、`redirect307`、`reject`；前三者需要 replacement，reject 不接受 replacement。
支持 `$1`、`${name}` 与 `$$`。只接受 HTTP(S) URL，不接受 userinfo、fragment 或控制字符。
最多 64 条规则，每个 pattern 2 KiB，pattern/replacement 合计 64 KiB，单个结果 8 KiB；
每条正则的编译与搜索缓存有局部上限，替换先检查输出空间再扩容。

redirect/reject 本地响应后关闭连接，不先连接原目标，也不把未读正文当作下一请求。
转发复用既有 HTTP/1 定界和流式正文，支持持久连接、chunked、Expect、临时响应及 Upgrade。
同 origin 的 path/query 动作保留已选择的目标 IP；跨 origin 时重新解析、选路、重建 Host，
并移除旧站点的 Authorization/Cookie。入口认证身份和原始目标快照保持。

## 选择性 HTTPS

域名为精确匹配或 `*.example.net` 子域匹配，后者不包含域本身；排除项优先。
只有明确允许的 SNI/端口才终止 TLS。无 SNI、ECH（含 GREASE）、未命中域名和 UDP/QUIC
透明保留；不会用 ECH 的外层覆盖名假装获得目标授权。证书固定或客户端证书要求可能使
选定连接失败，失败不会回退为关闭上游证书校验。

每个原始 HTTP authority 独立检查域名与端口授权；H2 连接的第一个域名不会授权所有流。
与连接 SNI/端口不同的 authority 重新选择目标。上下游 TLS 独立；最终上游经过同一
Dispatcher 和受保护物理出口，按实际最终主机验证证书，H2/H1 使用真实协商结果。
H1 上游按 HTTP/1.1 协商；H2 下游可对接 H2 或 H1 上游。正文背压传递，不缓存全文。

每个 CA 身份归运行代所有，叶证书同时限制 32 项、材料计费 256 KiB、空闲 10 分钟，
有效期最多 24 小时且不超过 CA。计费含证书、私钥及配置的保守成本，不代表进程 RSS。
同一 CA 的发行串行，同域名复用缓存；没有可脱离 Stop 的发行队列或任务。
HTTP 会话固定使用进入时的策略和资源代，reload 只影响后续新会话；CA 轮换也遵循该规则。

H2 每连接最多 8 个活动请求；流/连接接收窗口分别 32/64 KiB，头最多 32 KiB/100 字段，
单帧 16 KiB，动态 HPACK 表关闭。H2 不支持 CONNECT 或扩展 CONNECT；普通 CONNECT 返回 405。
WebSocket 沿 H1 Upgrade 路径透明转发。上游连接不跨请求复用，不存在跨身份的闲置池。
上传活动按 30 秒无进展期限控制，持续上传不消耗响应头等待预算；上传完成后，
尚未收到的响应头有独立 30 秒等待期限。提前响应继续与上传并发，响应正文使用逐帧空闲期限。
取消和 Stop 同时覆盖下游、上游、正文及驱动；设备信任与原生 VPN 验收独立于编译和容器互通。
