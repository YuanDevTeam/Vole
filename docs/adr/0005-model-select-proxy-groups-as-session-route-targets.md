---
status: accepted
---

# ADR 0005：将 select 代理组建模为会话路由与上游目标

`select` 是普通规则、`MATCH`、DNS 与 `dialer-proxy` 共享的命名目标。组拥有一个有序、非空的直接成员列表，成员可以是代理节点、嵌套 `select` 组、`DIRECT` 或 `REJECT`；`default-selected` 精确匹配直接成员，省略、null、空串或未命中时选择第一项。节点上游和全部组成员边统一为无环图，包括未选成员；独立 `measureDelay` 仍只接受具体节点链。

`mode` 支持 rule、global、direct；rule 模式允许空规则和任意位置的 MATCH，未命中直连。global 使用 GLOBAL 组；未显式声明时自动生成，成员顺序为 DIRECT、REJECT、全部节点、全部声明组，默认 DIRECT。该组与普通 select 共用运行时选择和 Controller 接口。

组当前选择属于运行会话；profile.store-selected 开启时由 Core 保存 Controller 的显式选择，下次启动恢复有效缓存成员。新建底层 transport 时读取当前选择；同一次建链对每个上游组只读一次，SOCKS5 UDP 的控制连接和 relay 路径共享快照与绝对期限。不同组没有原子快照保证。在途握手、既有 TCP / UDP、DNS cache / singleflight / TCP pool 和旧 AnyTLS 会话不迁移；复用旧会话的新业务流仍保持原路径。被选成员失败时原样返回，不隐式 failover。

路由组保留 `Dispatcher` seam；组上游在 `OutboundConnector` seam 解析，共享同一个原子选择索引，但不重新执行业务规则，不丢弃 effective peer、UDP 预算或建链期限。协议配置保持不可变，组连接器只持有声明的依赖；依赖优先构造、逆序停止与释放，避免全局节点注册表形成 Arc 环或深图递归析构。

上游组的 DIRECT 连接当前节点服务器，不是业务目标；REJECT 直接使建链失败。节点的主端点与独立下载端点在实际建链时通过运行时节点 resolver 解析；准备阶段不预解析潜在首跳。未选成员的 DNS 故障不阻塞启动。仅经代理访问的节点保持逻辑域名。DNS 关闭时使用系统解析，开启时使用配置的节点 nameserver/policy，不因失败切换系统解析；所有路径共享建链期限、递归依赖检查和停止取消。独立 measureDelay 的节点准备仍使用受控引导 resolver。

Provider 成员通过完整资源候选生成。候选重新校验名称及节点/组依赖图后发布，新连接使用当前资源，既有 TCP/UDP 与在途 DNS 保留仍使用的旧资源；不再使用的资源按原停止屏障释放。失败候选不替换可用配置或 HTTP 缓存。动态组移除当前成员时回到有效默认项或首成员，空组按 empty-fallback 处理。下载使用已发布资源，不依赖候选发布完成。

url-test 与 fallback 复用同一组选择和依赖图。共享 HTTP(S) 健康探测分别执行延迟容差和按序恢复，检查遵循 lazy、超时、并发上限和停止取消。探测结果不声明 UDP 能力，也不迁移既有连接。

load-balance 与路由、dialer-proxy 共用健康状态与策略实例。一致性哈希、轮询和粘滞选择在新连接建链时执行；UDP 对含负载均衡组的目标分别保留 transport，过期或明确的新 QUIC 流才重新选择。动态资源代际仍固定在旧会话上。上游组以当前节点服务器为目标，单次建链的所有协议步骤共用同一选择。
