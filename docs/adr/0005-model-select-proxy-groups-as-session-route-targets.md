---
status: accepted
---

# ADR 0005：将 select 代理组建模为会话路由与上游目标

`select` 是普通规则、`MATCH`、DNS 与 `dialer-proxy` 共享的命名目标。组拥有一个有序、非空的直接成员列表，成员可以是代理节点、嵌套 `select` 组、`DIRECT` 或 `REJECT`；省略 `default-selected` 时选择第一项，显式值必须精确命中一个直接成员。节点上游和全部组成员边统一为无环图，包括未选成员；独立 `measureDelay` 仍只接受具体节点链。

`mode` 支持 rule、global、direct；rule 模式允许空规则和任意位置的 MATCH，未命中直连。global 使用 GLOBAL 组；未显式声明时自动生成，成员顺序为 DIRECT、REJECT、全部节点、全部声明组，默认 DIRECT。该组与普通 select 共用运行时选择和 Controller 接口。

组选择只属于当前 Vole 运行会话，由调用方在下一次配置中重新提供。新建底层 transport 时读取当前选择；同一次建链对每个上游组只读一次，SOCKS5 UDP 的控制连接和 relay 路径共享快照与绝对期限。不同组没有原子快照保证。在途握手、既有 TCP / UDP、DNS cache / singleflight / TCP pool 和旧 AnyTLS 会话不迁移；复用旧会话的新业务流仍保持原路径。被选成员失败时原样返回，不隐式 failover。

路由组保留 `Dispatcher` seam；组上游在 `OutboundConnector` seam 解析，共享同一个原子选择索引，但不重新执行业务规则，不丢弃 effective peer、UDP 预算或建链期限。协议配置保持不可变，组连接器只持有声明的依赖；依赖优先构造、逆序停止与释放，避免全局节点注册表形成 Arc 环或深图递归析构。

上游组的 DIRECT 连接当前节点服务器，不是业务目标；REJECT 直接使建链失败。节点无上游，或上游组经纯组链能到达 DIRECT 时，prepare 预解析其主端点及独立下载端点，包括未选路径；仅经代理访问的节点保持逻辑域名。潜在首跳解析失败时 prepare 失败，不在切组后临时借系统 DNS。
