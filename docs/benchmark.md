# Vole TUN benchmark

仅展示 **1 Gbps** 压力下的实测结果。Linux ARM64 普通 Release、真实 TUN、Controller 开启、完整 CN GeoData；每容器5 CPU / 8 GiB、NAT，64条混合TCP/UDP流、每UDP socket 64个目标、1000 DNS QPS，每轮60秒。

| 路径 | 内核 | 实际吞吐（Mbps） | CPU（%） | 峰值RSS（MiB） | UDP丢包率（%） |
| --- | --- | ---: | ---: | ---: | ---: |
| DIRECT | Mihomo `v1.19.32` | 997.80 | 115.67 | 107.25 | 0.060565 |
| DIRECT | Vole `1e12828` | 999.65 | 113.05 | 28.98 | 0.000085 |
| Mieru TCP | Vole `2d6ae1f` | 998.86 | 146.13 | 35.50 | 0.0304 |

DIRECT双方各三轮，吞吐和CPU取中位数，RSS取生命周期最大值，UDP丢包按实际发送包数加权。Mieru TCP为单轮，使用官方mita `3.38.1`、LOW复用、STANDARD握手；其普通CLI与受验源码 `1e12828` 的对应产物字节相同。

CPU 100%表示一个逻辑核；RSS覆盖启动、负载及Stop/reap。不同协议路径和重复次数分别记录，不作跨协议排名。Linux RSS不替代iOS/tvOS整个VPN扩展的physical footprint验收，见[验收边界](acceptance.md)。
