# Vole TUN benchmark

**1 Gbps**、真实 TUN、Controller 开启、完整 CN GeoData；Linux ARM64 Release，每容器 5 CPU / 8 GiB。64 条业务流，每个 UDP socket 轮换 64 个目标；各口径单轮 60 秒。

Vole `5054c29`，Mihomo `v1.19.32`。图中 VLESS 为 **VLESS + XHTTP（H2、stream-one）+ REALITY**，AnyTLS 为独立出站。

每图依次列出实际吞吐、CPU、峰值 RSS 和丢失率；标签保留实测值，各指标只在同一单位内比较。CPU 100% 表示一个逻辑核；RSS 覆盖启动至 Stop/reap。

```mermaid
xychart-beta horizontal
    title "纯 TCP"
    x-axis ["Vole VLESS 996.69 Mbps", "Mihomo VLESS 999.92 Mbps", "Vole AnyTLS 999.85 Mbps", "Mihomo AnyTLS 999.92 Mbps", "Vole VLESS CPU 129.50%", "Mihomo VLESS CPU 43.30%", "Vole AnyTLS CPU 54.47%", "Mihomo AnyTLS CPU 41.63%", "Vole VLESS RSS 36.35 MiB", "Mihomo VLESS RSS 117.12 MiB", "Vole AnyTLS RSS 33.82 MiB", "Mihomo AnyTLS RSS 107.09 MiB", "Vole VLESS 业务丢失 0%", "Mihomo VLESS 业务丢失 0%", "Vole AnyTLS 业务丢失 0%", "Mihomo AnyTLS 业务丢失 0%"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [996.69, 999.92, 999.85, 999.92, 129.5, 43.3, 54.47, 41.63, 36.35, 117.12, 33.82, 107.09, 0.0, 0.0, 0.0, 0.0]
```

```mermaid
xychart-beta horizontal
    title "纯 UDP"
    x-axis ["Vole VLESS 999.13 Mbps", "Mihomo VLESS 998.67 Mbps", "Vole AnyTLS 999.28 Mbps", "Mihomo AnyTLS 999.90 Mbps", "Vole VLESS CPU 205.38%", "Mihomo VLESS CPU 222.76%", "Vole AnyTLS CPU 215.93%", "Mihomo AnyTLS CPU 218.39%", "Vole VLESS RSS 35.67 MiB", "Mihomo VLESS RSS 107.20 MiB", "Vole AnyTLS RSS 31.75 MiB", "Mihomo AnyTLS RSS 93.81 MiB", "Vole VLESS UDP 丢包 0.080176%", "Mihomo VLESS UDP 丢包 0.125488%", "Vole AnyTLS UDP 丢包 0.067472%", "Mihomo AnyTLS UDP 丢包 0.006256%"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [999.13, 998.67, 999.28, 999.9, 205.38, 222.76, 215.93, 218.39, 35.67, 107.2, 31.75, 93.81, 0.080176, 0.125488, 0.067472, 0.006256]
```

```mermaid
xychart-beta horizontal
    title "混合 TCP / UDP"
    x-axis ["Vole VLESS 999.36 Mbps", "Mihomo VLESS 999.27 Mbps", "Vole AnyTLS 999.94 Mbps", "Mihomo AnyTLS 999.75 Mbps", "Vole VLESS CPU 196.47%", "Mihomo VLESS CPU 200.23%", "Vole AnyTLS CPU 184.04%", "Mihomo AnyTLS CPU 178.93%", "Vole VLESS RSS 34.37 MiB", "Mihomo VLESS RSS 115.74 MiB", "Vole AnyTLS RSS 32.39 MiB", "Mihomo AnyTLS RSS 102.19 MiB", "Vole VLESS UDP 丢包 0.113408%", "Mihomo VLESS UDP 丢包 0.132928%", "Vole AnyTLS UDP 丢包 0.000000%", "Mihomo AnyTLS UDP 丢包 0.037088%"]
    y-axis "实际值（单位见标签）" 0 --> 1100
    bar [999.36, 999.27, 999.94, 999.75, 196.47, 200.23, 184.04, 178.93, 34.37, 115.74, 32.39, 102.19, 0.113408, 0.132928, 0.0, 0.037088]
```

纯 TCP 的业务丢失率按实际发送/接收字节计算，双方所有流字节、校验和及结束状态均完整；TCP 重传另记，不作为业务丢失。纯 UDP 与混合流显示按实际发送包数加权的 UDP 丢包率。

以上为单轮 Linux 实测，不代替 iOS/tvOS 整个 VPN 扩展的 physical footprint 验收，见[验收边界](acceptance.md)。
