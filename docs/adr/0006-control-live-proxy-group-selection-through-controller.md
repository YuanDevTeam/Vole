---
status: accepted
---

# ADR 0006：只通过 Controller 控制代理组的实时选择

Vole 首版只通过 Controller 暴露代理组的实时选择，不新增 Invoke 方法，也不扩展 Windows 控制管道。Controller 采用 mihomo `select` 的核心调用形状：`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`；PUT body 为 `{"name":"member"}`，成功返回空的 `204`。组状态只承诺 `name`、`type`、`all`、`now`，不宣称兼容完整 mihomo Dashboard API。

Windows WinRT VPN 的实际运行时位于独立 Session Host，桌面 Wintun、Apple 与 Android 的运行时位于 Invoke owner 背后；Controller 是现有平台中唯一能统一到达实际运行会话的 Adapter。Controller 也可用于合法 mixed-only 静态节点或纯 DIRECT 配置，无需额外开启 TUN 或显式代理组；组路由可以在无 TUN 的本地代理运行时中使用，`/traffic` 仍只在存在 TUN 统计时提供。

配置同时包含代理组和 Controller 时，必须为整个 Controller 配置 Bearer secret。请求使用精确名称和严格、有界的 JSON，任何失败都不得改变选择。没有 Controller 的代理组配置仍然有效，但本次会话中没有公开的实时切换入口；Core 按 `profile.store-selected`（默认 true）保存 Controller 的显式选择；下次启动优先恢复仍存在的缓存成员，否则使用配置默认或首成员。持久化失败不回滚已经成功的运行时选择。

Controller 同时展示动态 provider、自动组和节点健康状态；组选择与探测任务均位于实际运行会话。Controller 的节点/组 delay 与 Provider healthcheck 在当前资源代际中共用自动健康探测器、DNS、Dialer 和停止屏障；每节点手动历史有界，实际内存仅在请求时采集。独立 measureDelay 保持 node-only Invoke 接口，复用内部 HTTP/TLS 探测能力。
