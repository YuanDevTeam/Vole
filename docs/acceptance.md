# 验收边界

只报告实际执行的检查。结果记录在对应 CI、PR 或 benchmark 运行中，本文维护验证范围。

兼容验收遵循 [Mihomo 兼容原则](mihomo-compatibility.md#兼容原则)：验证与 Mihomo listener 和官方协议 server 的互通，以 Vole Core 的内存优化和吞吐达标为第一目标。字段对照用于记录支持范围与差异，不要求逐字段行为相等。性能达标须依据当次明确的内存预算、目标负载及实测结果判断，不能仅凭连接成功或配置解析通过。

| 层次 | 验证内容 |
| --- | --- |
| 离线 / 纯内存 | 配置、协议编解码、取消、生命周期、内存与 FFI 所有权 |
| 平台编译 | 各目标构建、CLI 基本运行、库文件和发布归档 |
| 原生消费者 | C/Swift/JNI 等真实宿主的加载、调用与资源释放 |
| 容器互通 | Mihomo listener 与官方协议 server、真实双向流量、认证、支持模式的 UDP 与关闭行为 |
| 压力 | 实际吞吐、CPU、内存峰值、丢包、DNS 完成数及退出清理 |
| 设备 / 发布 | 真机 TUN、物理出口、权限、生命周期、签名安装及商店要求 |

编译不替代原生消费者或设备验证；模拟器、Wintun 与 UWP 分别验收。
Linux RSS 不等于 Apple Network Extension physical footprint。
性能结果须同时给出输入、目标负载和实际负载，保留失败与丢包情况。

核心测试入口见 [tests](../tests/README.md)，平台与发布入口见 [scripts](../scripts/README.md)。
网络互通和压力由 [container-benchmark](https://github.com/YuanDevTeam/container-benchmark)
执行，遵守 [测试隔离](testing-isolation.md)。设备要求见 [TUN 平台层](tun-platform.md)
与 [Windows VPN](windows-vpn.md)。
