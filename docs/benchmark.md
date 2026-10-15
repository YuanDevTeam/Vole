# Vole TUN benchmark

## 当前 DIRECT 定速对照

A 为 Mihomo `v1.19.32`，B 为 Vole `1e12828`；Linux ARM64 普通 Release、真实 TUN、Controller、完整 CN GeoData。每档每端三轮、每轮60秒；吞吐和CPU取中位数，RSS取生命周期最大值，UDP丢包按三轮上下行实际发送包数加权。CPU 100%表示一个逻辑核。

Vole 九个窗口均通过现行硬门槛及40MiB目标。2/3Gbps存在超时和未完成流，吞吐为活动窗口已收有效载荷，不代表无错误容量；验收口径见[压力标准](acceptance.md)。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐"
    x-axis ["1G A", "1G B", "2G A", "2G B", "3G A", "3G B"]
    y-axis "Mbps" 0 --> 3100
    bar [997.80, 999.65, 1993.92, 1942.01, 2726.10, 2246.87]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "CPU"
    x-axis ["1G A", "1G B", "2G A", "2G B", "3G A", "3G B"]
    y-axis "%" 0 --> 241
    bar [115.67, 113.05, 168.08, 178.11, 214.45, 210.57]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "内存"
    x-axis ["1G A", "1G B", "2G A", "2G B", "3G A", "3G B"]
    y-axis "RSS MiB" 0 --> 178
    bar [107.25, 28.98, 100.80, 34.56, 158.18, 35.20]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "UDP 丢包率"
    x-axis ["1G A", "1G B", "2G A", "2G B", "3G A", "3G B"]
    y-axis "%" 0 --> 17
    bar [0.060565, 0.000085, 0.289467, 5.048557, 1.848385, 15.041642]
```

## 当前 H3 对照

A 为 Vole `c42eba7`，B 为 `1e12828`；真实 TUN，各三轮固定量负载。吞吐和传输窗口CPU取中位数，RSS取生命周期最大值；DoH单列QPS，UDP为端到端交付丢包率。

L4、IP/T、IP/U分别表示MASQUE L4、IP TCP、IP UDP；TT为TrustTunnel。

九项业务与清理通过，B全部达到40MiB目标；旧相对判据保留7 PASS、2 FAIL。MASQUE L4吞吐下降约3.10%、RSS从29.09降至26.50MiB（降低8.90%）；IP UDP吞吐下降约0.66%、RSS从23.31降至23.05MiB（降低1.11%）。

旧相对规则要求吞吐与内存同时改善，或一项改善超过2%、另一项退步小于1%。L4因吞吐退步超过1%、IP UDP因内存改善不足2%而保留原始`PERFORMANCE_FAIL`，不追溯改签。

按[现行内存优先标准](acceptance.md#性能采纳标准)，两项在已测固定量TUN场景下均达到40MiB目标，内存改善可渐进采纳；接受上述取舍，不再作为阶段14阻塞项，也不再专项优化。吞吐、CPU和丢包率保留实测结果。

固定量结果不代签MASQUE各模式的1Gbps定速吞吐及丢包门槛，也不代签2/3Gbps内存过载验收；Linux RSS不替代iOS/tvOS整个VPN扩展的physical footprint验收。

### 实际吞吐 TCP

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐 TCP"
    x-axis ["packet A", "packet B", "one A", "one B", "up A", "up B", "down A", "down B", "TT H3 A", "TT H3 B", "L4 A", "L4 B", "IP/T A", "IP/T B"]
    y-axis "Mbps" 0 --> 1288
    bar [115.58, 130.06, 869.64, 1039.90, 882.19, 1149.17, 921.19, 1138.30, 637.25, 661.67, 710.03, 688.05, 245.05, 251.86]
```

### 实际吞吐 UDP

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐 UDP"
    x-axis ["IP/U A", "IP/U B"]
    y-axis "Mbps" 0 --> 173
    bar [154.06, 153.04]
```

### 实际吞吐 DoH

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐 DoH"
    x-axis ["DoH A", "DoH B"]
    y-axis "QPS" 0 --> 19539
    bar [17444.73, 17444.89]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "CPU"
    x-axis ["packet A", "packet B", "one A", "one B", "up A", "up B", "down A", "down B", "DoH A", "DoH B", "TT H3 A", "TT H3 B", "L4 A", "L4 B", "IP/U A", "IP/U B", "IP/T A", "IP/T B"]
    y-axis "%" 0 --> 289
    bar [59.94, 70.38, 208.53, 238.25, 209.37, 251.91, 209.03, 257.48, 174.62, 160.25, 165.43, 168.59, 182.39, 179.02, 69.54, 72.00, 71.69, 76.98]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "内存"
    x-axis ["packet A", "packet B", "one A", "one B", "up A", "up B", "down A", "down B", "DoH A", "DoH B", "TT H3 A", "TT H3 B", "L4 A", "L4 B", "IP/U A", "IP/U B", "IP/T A", "IP/T B"]
    y-axis "RSS MiB" 0 --> 46
    bar [32.92, 28.72, 34.93, 25.64, 37.71, 26.13, 35.42, 26.91, 28.01, 24.05, 40.36, 28.34, 29.09, 26.50, 23.31, 23.05, 26.20, 24.54]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "UDP 丢包率"
    x-axis ["IP/U A", "IP/U B"]
    y-axis "%" 0 --> 1
    bar [0.000000, 0.000000]
```

## 当前其他协议对照

A 为 Mihomo `v1.19.32`，B 为 Vole `1e12828`；真实 TUN，各三轮固定量负载。Mieru U/T、U/U分别为UDP载体承载TCP、UDP；TT2/T、TT2/U、TT3/U分别为TrustTunnel H2 TCP、H2 UDP、H3 UDP；M2IP/T、M2IP/U为MASQUE H2 IP TCP、UDP。双方42个业务样本与清理通过，Vole全部达到40MiB目标。吞吐和传输窗口CPU取中位数，RSS取生命周期最大值；UDP按实际发送包数汇总端到端丢包。

### 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "实际吞吐"
    x-axis ["TT2/T A", "TT2/T B", "TT2/U A", "TT2/U B", "TT3/U A", "TT3/U B", "Mieru U/T A", "Mieru U/T B", "Mieru U/U A", "Mieru U/U B", "M2IP/T A", "M2IP/T B", "M2IP/U A", "M2IP/U B"]
    y-axis "Mbps" 0 --> 661
    bar [566.83, 589.96, 124.78, 131.36, 83.94, 88.56, 184.14, 324.23, 135.15, 144.66, 395.43, 364.50, 132.55, 132.01]
```

### CPU

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "CPU"
    x-axis ["TT2/T A", "TT2/T B", "TT2/U A", "TT2/U B", "TT3/U A", "TT3/U B", "Mieru U/T A", "Mieru U/T B", "Mieru U/U A", "Mieru U/U B", "M2IP/T A", "M2IP/T B", "M2IP/U A", "M2IP/U B"]
    y-axis "%" 0 --> 209
    bar [133.14, 143.54, 83.10, 69.32, 82.87, 63.34, 85.64, 144.98, 110.84, 82.62, 161.39, 185.87, 84.50, 72.02]
```

### 内存

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "内存"
    x-axis ["TT2/T A", "TT2/T B", "TT2/U A", "TT2/U B", "TT3/U A", "TT3/U B", "Mieru U/T A", "Mieru U/T B", "Mieru U/U A", "Mieru U/U B", "M2IP/T A", "M2IP/T B", "M2IP/U A", "M2IP/U B"]
    y-axis "RSS MiB" 0 --> 305
    bar [105.18, 22.93, 80.39, 22.35, 81.27, 22.87, 272.13, 22.29, 89.87, 21.29, 120.53, 24.55, 79.56, 23.29]
```

### UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1100
    height: 350
    showDataLabel: true
    showDataLabelOutsideBar: true
---
xychart
    title "UDP 丢包率"
    x-axis ["TT2/U A", "TT2/U B", "TT3/U A", "TT3/U B", "Mieru U/U A", "Mieru U/U B", "M2IP/U A", "M2IP/U B"]
    y-axis "%" 0 --> 1
    bar [0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000]
```

## Mieru TCP 载体定速结果

Vole `2d6ae1f` 的普通 CLI 与受验源码 `1e12828` 的对应产物字节相同，复用本组最终结果。官方 mita `3.38.1`、TCP/LOW/STANDARD，Linux ARM64 普通 Release CLI、真实 TUN、Controller 开启。每档一次60秒；每容器5 CPU / 8 GiB、NAT，64条混合流、每UDP socket 64个目标、1000 DNS QPS、完整CN GeoData。TUN/eth0队列均为4096。

**1/2/3 Gbps 均通过当前硬门槛**。1 Gbps 同时达到吞吐、丢包及 40 MiB 内存目标；2/3 Gbps 峰值分别为 **41.36 / 42.05 MiB**，通过 45 MiB 硬上限，尚未达到 40 MiB 优化目标；本项不再专项优化。2/3 Gbps 的吞吐和丢包只记录，未完成交付保留原始状态，不作为无错误容量排名。

各组已接收内容、来源、完整 TUN 压力窗口、进程观测和 Stop/清理有效。CPU 100% 表示一个逻辑核，内存为启动至 Stop/reap 的最大 Linux RSS，UDP 丢包按实际发送包数加权。单轮 Linux 筛选不替代重复统计或真机 Network Extension 内存验收。验收口径见[压力标准](acceptance.md)。

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
    title "Mieru TCP 实际吞吐"
    x-axis ["1G", "2G", "3G"]
    y-axis "Mbps" 0 --> 3100
    bar [998.86, 1397.28, 1369.54]
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
    title "Mieru TCP CPU"
    x-axis ["1G", "2G", "3G"]
    y-axis "%" 0 --> 300
    bar [146.13, 201.41, 209.1]
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
    title "Mieru TCP 内存"
    x-axis ["1G", "2G", "3G"]
    y-axis "RSS MiB" 0 --> 55
    bar [35.5, 41.36, 42.05]
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
    title "Mieru TCP UDP 丢包率"
    x-axis ["1G", "2G", "3G"]
    y-axis "%" 0 --> 55
    bar [0.0304, 23.2549, 48.3889]
```
