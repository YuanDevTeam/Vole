# Vole TUN benchmark

## Mieru TCP 载体

Vole 优化前 `e9d64b9`、优化后 `c84f2ba`，参考端 Mihomo `1.19.32`，均连接官方 mita `3.38.1`，使用 TCP 载体、LOW 复用和 STANDARD 握手。Linux ARM64 普通 Release CLI，真实 TUN、Controller 开启；每档各一次 60 秒，64 条混合 TCP/UDP 流、每个 UDP socket 64 个目标、1000 DNS QPS、完整 CN GeoData。规则、流量驱动、队列和采样口径固定。

**优化后 1 Gbps 样本通过压力硬门槛**：接收 996.45 Mbps、RSS 41.48 MiB、UDP 丢包 0.0476%，尚未达到 40 MiB 内存目标。32 条 UDP 流的接收超时仍保留，`driver_complete=false`，按既有丢包容限判定；数据有效、DNS、Stop 和清理通过。优化后 2 Gbps 仍未达标：接收 1234.81 Mbps、RSS 67.19 MiB、UDP 丢包 20.2409%。统一验收标准见[压力标准](acceptance.md)。

其余五个样本均未通过压力验收。Mihomo 两档均出现 `datagram-source-or-size`，接收提前终止；对应丢包包含接收终止后的未收到包，无法据此判断协议吞吐上限或作有效性能排名。优化前及优化后 2 Gbps 也保留未完成流和负载校验失败；图中仍如实列出活动窗口接收计数。

CPU 100% 表示一个逻辑核；内存取 CLI 从启动至 Stop 退出的最大 Linux RSS；UDP 丢包按实际上下行发送包数加权。以下为单轮 Linux 结果，不能替代重复统计或真机 Network Extension 内存验收。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mieru TCP 实际吞吐"
    x-axis "负载 / 版本" ["1G 前", "1G 后", "1G Mihomo", "2G 前", "2G 后", "2G Mihomo"]
    y-axis "Mbps" 0 --> 1400
    bar [277.12, 996.45, 565.98, 307.72, 1234.81, 1046.78]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mieru TCP CPU"
    x-axis "负载 / 版本" ["1G 前", "1G 后", "1G Mihomo", "2G 前", "2G 后", "2G Mihomo"]
    y-axis "%" 0 --> 300
    bar [248.58, 150.36, 173.47, 241.76, 196.74, 240.15]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mieru TCP 内存"
    x-axis "负载 / 版本" ["1G 前", "1G 后", "1G Mihomo", "2G 前", "2G 后", "2G Mihomo"]
    y-axis "RSS MiB" 0 --> 1800
    bar [128.08, 41.48, 349.77, 128.47, 67.19, 1630.70]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "Mieru TCP UDP 丢包率"
    x-axis "负载 / 版本" ["1G 前", "1G 后", "1G Mihomo", "2G 前", "2G 后", "2G Mihomo"]
    y-axis "%" 0 --> 100
    bar [52.7393, 0.0476, 43.3867, 70.2554, 20.2409, 45.4280]
```

## 历史 DIRECT 结果

Linux ARM64 普通 Release CLI，Vole `b58b82f` 的历史结果。A 为原默认构建，B 为原 `low-memory` 构建；源码、依赖、Ubuntu 镜像、原始 GeoData 和流量驱动一致。

每容器 5 CPU、8 GiB、NAT；每档 60 秒混合 TCP/UDP、64 条流、每个 UDP socket 64 个目标、1000 DNS QPS、完整 `geosite:cn` / `geoip:cn`，DIRECT 出口，Controller 开启且负载期间不轮询。TUN / eth0 队列均为 4096，原站队列保持默认。每档每种构建各运行三轮。

吞吐与 CPU 取三轮中位数，CPU 100% 表示一个逻辑核；内存取三轮 CLI 生命周期最大 RSS，覆盖启动、负载与 Stop 退出；UDP 丢包率合并三轮实际上下行发送包数后加权。Linux CLI RSS 用于内存优化筛选，不能替代真机 Network Extension physical footprint。

全部 12 个历史样本的 RSS 均低于 40 MiB。这些历史 DIRECT 结果不代表当前构建的 Mieru 性能。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 850
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐"
    x-axis "负载 / 历史构建" ["1G A", "1G B", "2G A", "2G B"]
    y-axis "Mbps" 0 --> 2100
    bar [999.81, 999.81, 1996.48, 1997.14]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 850
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "CPU"
    x-axis "负载 / 历史构建" ["1G A", "1G B", "2G A", "2G B"]
    y-axis "%" 0 --> 200
    bar [109.48, 113.15, 178.10, 181.66]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 850
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "内存"
    x-axis "负载 / 历史构建" ["1G A", "1G B", "2G A", "2G B"]
    y-axis "RSS MiB" 0 --> 50
    bar [32.82, 28.89, 39.13, 36.17]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 850
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "UDP 丢包率"
    x-axis "负载 / 历史构建" ["1G A", "1G B", "2G A", "2G B"]
    y-axis "%" 0 --> 0.5
    bar [0.0000, 0.0000, 0.0505, 0.0613]
```
