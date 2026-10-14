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

## 性能采纳标准

Apple 的内存验收针对 iOS/tvOS **整个 Network Extension 进程的 physical footprint**，
硬上限为 **40 MiB（41,943,040 bytes）**，优化目标为 **35 MiB（36,700,160 bytes）**。
包含 Core、宿主桥接与扩展运行时；以真机目标负载下的进程观测验收，不能只计算 Rust heap。

Mac 普通 CLI 与模拟 TUN 用于优化筛选，分别报告 physical footprint、RSS 和 CPU。
采样到的最大当前 footprint 可能遗漏瞬时峰值，内核 lifetime 高水位与 `wait4` 可能包含
exec 前占用，应独立记录。Mac 小负载互通不替代压力验收，Mac CLI 结果不替代真实
Network Extension、iOS 或 tvOS 的设备内存验收。

Linux 压力保留以下 RSS 对照口径和指标，与 Apple footprint 分开判断：

使用相同输入、负载和重复次数的普通 Release 对照，分别比较吞吐/QPS中位数与最大CLI生命周期峰值RSS。Linux CLI的RSS观察覆盖exec至退出/reap，包括启动、负载、drain和Stop；heaptrack等仪器开销、tracked heap和wait4读数不能替代这一验收口径。

- CLI生命周期峰值RSS硬上限为 **40MiB（41,943,040 bytes）**；超过必须优化，不能用吞吐改善抵消。
- 满足硬上限后，吞吐提高且RSS降低可采纳。令R为候选/基线吞吐或QPS，M为候选/基线最大RSS，也允许`R > 1.02 && M < 1.01`或`M < 0.98 && R > 0.99`：一项改善严格大于2%，另一项回退严格小于1%。按未四舍五入数值判断，等于2%或1%不满足新增容忍分支。
- 定速压力在 **1Gbps** 下有效吞吐须 **≥990Mbps**，在 **2Gbps** 下须 **≥1980Mbps**；CLI生命周期峰值RSS优化目标仍为 **≤35MiB（36,700,160 bytes）**。保持既有负载及其有效性门槛；设置目标速率或较低负载下达到内存目标不能代替实际吞吐验收。
- UDP丢包率须 **≤0.5%**，以实际发送与接收的包数计算，按上下行发送包数加权汇总，同时保留两个方向的独立计数。丢包在固定收尾后统计；吞吐仅统计活动窗口，不把漏发算作丢包。

数据有效性、实际完成量、负载到达、CPU、UDP loss、DNS完成数、测量有效性及退出/join/资源清理分别记录。测量成功不等于业务成功，编译、配置解析或连接成功不代替压力验收；失败或无效样本保留原结果，不参与有效性能胜出比较。以上是验收条件，不新增运行时admission或按整进程RSS拒绝业务的机制，资源所有权与局部容量仍遵循[运行时资源策略](runtime-resource-policy.md)。

核心测试入口见 [tests](../tests/README.md)，平台与发布入口见 [scripts](../scripts/README.md)。
网络互通和压力由独立容器测试工具执行，公开结果见 [benchmark](benchmark.md)，
遵守 [测试隔离](testing-isolation.md)。设备要求见 [TUN 平台层](tun-platform.md)
与 [Windows VPN](windows-vpn.md)。
