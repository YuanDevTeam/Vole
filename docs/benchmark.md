# Vole / Mihomo TUN benchmark

测试版本：Vole `96b665a`、Mihomo `v1.19.32`，两端均开启 Controller。
Linux 容器各 5 CPU、8 GiB；60 秒混合 TCP/UDP、64 条流、1000 DNS QPS，完整 `geosite:cn` / `geoip:cn`，DIRECT 出口。
CPU 100% 表示一个逻辑核；内存为 CLI 生命周期峰值 RSS，UDP 丢包按实际发送包数加权。

## 实际吞吐

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "实际吞吐"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo"]
    y-axis "Mbps" 0 --> 2100
    bar [999.05, 999.27, 1497.17, 1496.07, 1894.44, 1986.59, 1991.27, 1990.49]
```

## CPU

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "CPU"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo"]
    y-axis "%" 0 --> 200
    bar [113.85, 115.68, 139.62, 145.62, 180.88, 168.37, 180.10, 169.68]
```

## 内存

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "内存"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo"]
    y-axis "RSS MiB" 0 --> 120
    bar [32.40, 93.57, 32.69, 97.43, 40.52, 109.11, 38.46, 105.04]
```

## UDP 丢包率

```mermaid
---
config:
  xyChart:
    width: 1000
    height: 400
    showDataLabel: true
    showDataLabelOutsideBar: true
    xAxis:
      labelFontSize: 12
---
xychart
    title "UDP 丢包率"
    x-axis "负载 / 内核" ["1G Vole", "1G Mihomo", "1.5G Vole", "1.5G Mihomo", "2G Vole", "2G Mihomo", "2G复测 Vole", "2G复测 Mihomo"]
    y-axis "%" 0 --> 1
    bar [0.0000, 0.0396, 0.0001, 0.1892, 0.5123, 0.6432, 0.1710, 0.4699]
```
