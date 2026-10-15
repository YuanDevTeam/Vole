# 核心协议回归输入

生产字段以 [config.yaml](../../docs/config.yaml) 和协议契约为准。本目录只保留
Vole 纯核心回归直接使用的独立输入，不包含容器 catalog、消费者或测试编排。

- `limits.json`：局部资源上限、实际常量引用和边界断言；
  `tests/limit_foundations.rs` 直接读取并核对。
- `encryption-crypto.json`：独立官方 Go 原语生成的 Encryption 密码向量；
  `src/outbound/vless/encryption/crypto.rs` 和 `records.rs` 的确定性回归直接使用。
  不能从待测实现重生成期望；历史生成来源可在 Git 中追溯。

核心离线回归见 [tests](../README.md)，平台编译见 [scripts](../../scripts/README.md)。
互通消费者、官方对端下载与编排由独立容器测试工具维护，公开结果见
[benchmark](../../docs/benchmark.md)，入口为
`container-benchmark interop --source vole=PATH`，默认使用 Mihomo、Xray-core、
Hysteria2、V2Ray 与 Caddy/Xray，以及 TrustTunnel、Mieru 和 MASQUE 的代表用例；Mihomo listener 的缺口保留原生
或明确分层验证。`--backend` / `--protocol` 可筛选，`--list` 离线列举。
原生 TUN 压力与两核性能比较使用该工程的 `stress` / `compare`；真实执行均显式
提供 Vole checkout，不推断工程路径。网络互通不混入离线检查或平台构建。
本目录独立输入的离线回归不代替实际网络互通。

输入文件属于受版本控制的测试源，不是每轮产生的测试数据。每轮容器实验仅保留
脱敏文字结论，清理规则见[测试隔离](../../docs/testing-isolation.md)；
行为、互通和设备的证据边界见[验收范围](../../docs/acceptance.md)。
