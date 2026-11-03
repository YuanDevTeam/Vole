# Vole 文档

本文档只维护当前契约、有效约束和发布边界。历史方案、阶段报告与已取消能力留在 Git 历史，不另建归档副本。行为以当前源码、测试和契约为准，不一致时一起修正。

## 配置与接口

- [配置协议](config.yaml)：严格 YAML、节点、providers、动态与自动策略组、DNS 与规则。
- [Mihomo 兼容原则与范围](mihomo-compatibility.md)：互通要求、性能取舍、已实现能力及协议与平台边界。
- [Invoke API](invoke-api.md)：严格请求格式、核心软件版本与构建身份、生命周期、平台回调及内联配置。
- [Controller](controller-api.md)：认证、组与资源、连接管理、规则/配置/DNS 诊断和 TUN 流量。
- [混合入站](inbounds.md)：同端口 HTTP 转发/隧道、SOCKS5 TCP/授权 UDP、监听及认证。
- [出站](outbounds.md)：HTTP(S) CONNECT、SOCKS5、AnyTLS、Trojan、VMess AEAD、Hysteria2、TUIC v5、SS 2022、WireGuard、TrustTunnel、Mieru、MASQUE。
- [VLESS](vless.md)：传输、Vision、Encryption、REALITY、JLS、ECH。
- [XHTTP 与 sing-mux](xhttp.md)：双腿、H1/H2/H3、连接池及复用。
- [TLS 证书与指纹](tls-client-fingerprint.md)：证书 pin、ClientHello 模板、身份与缓存。
- [REALITY 线协议](reality-wire-protocol.md)：认证、密钥与失败边界。

## 运行与平台

- [DNS 与 ICMP](tun-icmp-dns.md)、[GeoData](geodata.md)。
- [资源策略](runtime-resource-policy.md)：局部预算、所有权、取消和观测。
- [TUN 平台](tun-platform.md)、[Windows VPN](windows-vpn.md)。
- [TLS 依赖与发布](tls-dependencies.md)：来源、provider、fork 与升级门禁。
- [Windows 最小集成示例](../example/windows-uwp/README.md)。

## 开发与验证

- [平台编译](../scripts/README.md)、[离线回归与独立容器入口](../tests/README.md)。
- [CLI 与 tag 发布](cli.md)：五个参数、配置路径、共用内核入口和 CLI / FFI 统一发布。
- [测试隔离](testing-isolation.md)：所有网络服务端必须容器化。
- [验收边界](acceptance.md)：本地、CI、设备和发布证据分别记录。
- [领域上下文](../CONTEXT.md)、[架构决策](adr/)。
- 工程 skills：[Issue 跟踪](agents/issue-tracker.md)、[分类标签](agents/triage-labels.md)、[领域流程](agents/domain.md)。

配置字段由 `config.yaml` 维护；协议文档补充语义与限制，不复制阶段计划。
技术标识符保留原文，说明使用中文。AGENTS.md 只放跨任务约束与读取入口。
