# Vole / Mihomo TUN benchmark

CPU 100% 表示一个逻辑核；UDP 丢包按实际上下行发送包数加权。

## Linux 原生 TUN

容器各 5 CPU、8 GiB；60 秒混合 TCP/UDP、64 条流、1000 DNS QPS，完整 `geosite:cn` / `geoip:cn`，DIRECT 出口，Controller 开启。内存为 CLI 生命周期观测峰值 RSS。

历史横向对照：Vole `96b665a`、Mihomo `v1.19.32`。本轮复核只运行 Vole `1d569ee`，运行时代码为 `7fbb5f4`，保留原 Linux 负载与观察器。

本轮两档均未通过压力验收：1 Gbps 的 UDP 流未完整完成，实际吞吐低于 990 Mbps；2 Gbps 实际吞吐低于 1980 Mbps。两档内存、UDP 丢包率、DNS 和正常退出检查满足本轮门槛。失败测量列入图中，不作为有效性能胜出样本。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 1200
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "实际吞吐"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo", "1G复核 Vole", "2G复核 Vole"]
    y-axis "Mbps" 0 --> 2100
    bar [999.05, 999.27, 1497.17, 1496.07, 1894.44, 1986.59, 1991.27, 1990.49, 976.83, 1908.47]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 1200
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "CPU"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo", "1G复核 Vole", "2G复核 Vole"]
    y-axis "%" 0 --> 200
    bar [113.85, 115.68, 139.62, 145.62, 180.88, 168.37, 180.10, 169.68, 93.78, 184.02]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 1200
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "内存"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo", "1G复核 Vole", "2G复核 Vole"]
    y-axis "RSS MiB" 0 --> 120
    bar [32.40, 93.57, 32.69, 97.43, 40.52, 109.11, 38.46, 105.04, 34.70, 36.77]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1200
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "UDP 丢包率"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo", "1G复核 Vole", "2G复核 Vole"]
    y-axis "%" 0 --> 1
    bar [0.0000, 0.0396, 0.0001, 0.1892, 0.5123, 0.6432, 0.1710, 0.4699, 0.0382, 0.3789]
```

## macOS 模拟 TUN（历史失败结果）

Vole `1d569ee`，运行时代码为 `7fbb5f4`；60 秒、32 条双向 TCP echo 与 32 条 UDP echo、1000 DNS QPS，完整 CN GeoData、DIRECT 和 Controller。原站位于同规格 Linux 容器，Mac 运行普通 CLI 与独立负载客户端。实际吞吐为活动窗口内经内容校验的 echo 有效载荷乘二；内存为每 20 ms 采样的最大当前 physical footprint，不与 Linux RSS 混合排名。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 600
    height: 300
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mac 实际吞吐"
    x-axis "负载" ["1 Gbps", "2 Gbps"]
    y-axis "Mbps" 0 --> 2100
    bar [978.00, 1864.62]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 600
    height: 300
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mac CPU"
    x-axis "负载" ["1 Gbps", "2 Gbps"]
    y-axis "%" 0 --> 320
    bar [135.90, 290.27]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 600
    height: 300
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mac 内存"
    x-axis "负载" ["1 Gbps", "2 Gbps"]
    y-axis "physical footprint MiB" 0 --> 50
    bar [36.25, 40.70]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 600
    height: 300
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mac UDP 丢包率"
    x-axis "负载" ["1 Gbps", "2 Gbps"]
    y-axis "%" 0 --> 0.001
    bar [0.0000, 0.0009]
```

两档均未通过压力验收：实际吞吐与 DNS 完成不足，1 Gbps 还存在 TCP 关闭未完整完成。Mac 模拟测试工具已删除，正式压力使用 Linux；这些采样结果不能证明 iOS/tvOS Network Extension 的真机内存达标。
