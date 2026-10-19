# Vole

<p align="center">
  <a href="../README.md">English</a> · 简体中文 · <a href="./README.ru.md">Русский</a>
</p>

Vole 是用于 VPN 客户端和本地代理的 Rust 代理内核，提供原生库和前台 CLI。它通过直连、代理节点、代理组和代理链转发 TCP/UDP 流量，并集成 DNS、GeoData 和跨平台 TUN 数据面。

配置采用 **Mihomo 风格的 YAML，范围限于 Vole 已支持的功能**。Vole 以内存优化和吞吐达标为第一目标；兼容要求是与 Mihomo listener 和官方协议 server 端互通，不寻求逐字段行为完全一致，见 [兼容原则](../docs/mihomo-compatibility.md#兼容原则)。

## 内核能做什么

- **接入应用与 VPN 流量：**HTTP 转发、CONNECT 和 Upgrade；SOCKS5 CONNECT 和 UDP ASSOCIATE；宿主提供的 IPv4/IPv6 TUN 数据包。
- **路由流量：**支持 rule/global/direct 模式，域名、来源/目标 IP 与端口、TCP/UDP、GeoSite/GeoIP、规则集合及逻辑规则；在支持的平台使用进程/UID 规则，提供具名 direct/dns/reject 出站与内置路由动作。
- **选择和串联代理：**嵌套 select/url-test/fallback/load-balance 组、健康检查与选择持久化；`dialer-proxy` 可引用节点或组。既有连接保留原路径。
- **处理 DNS：**hosts、独立 bootstrap/节点/直连解析角色，UDP/TCP/DoH/DoT/DoQ、域名/GeoSite/rule-set policy、fallback、有界缓存、redir-host 和持久 fake-IP；按配置接管 TUN DNS。
- **识别流量用于路由：**TUN/mixed TCP 的 HTTP1/HTTP2/TLS 嗅探与 TUN、SOCKS5 UDP 关联的 QUIC v1/v2 嗅探，支持强制/排除条件和目标覆盖开关；本地应答 ICMPv4/ICMPv6 Echo。
- **管理路由数据：**HTTP/file/inline 节点与规则 providers、URI/Base64/AGE 订阅、动态组、筛选和覆盖；YAML/Text 及 domain/ipcidr MRS。GeoData 完整加载引用类别，支持指定出口下载和周期更新，坏更新保留旧状态。详见 [GeoData 边界](../docs/geodata.md#内存与安全边界)。
- **提供客户端控制：**组与资源状态、连接快照与关闭、规则命中、有效配置、有界 WebSocket 推送和 DNS 诊断；支持范围内的配置更新、TUN 流量与隔离的节点/代理链延迟测量。更新边界见 [Controller 契约](../docs/controller-api.md)。
- **处理选定的业务 HTTP：**URL 改写和重定向，可使用宿主提供的 CA 对明确授权的 HTTPS 域名进行选择性解密，并以有界 H1/H2 流式转发。使用[独立 HTTP 配置](../docs/http-processing.md)。

## 代理协议

默认构建启用下列协议。UDP 支持以协议模式和节点配置为准。

| 协议 | 能力 |
| --- | --- |
| [VLESS](../docs/vless.md) | TCP、WebSocket / HTTPUpgrade、gRPC、HTTP 首包伪装、传统 H2、[XHTTP H1/H2/H3](../docs/xhttp.md)；在支持的组合中提供 Vision、Encryption、REALITY、JLS、ECH 和 sing-mux |
| [VMess AEAD](../docs/outbounds.md#vmess-aead) | TCP、WebSocket / HTTPUpgrade、gRPC、HTTP 首包伪装和传统 H2；TCP/UDP，明文或支持的 TLS 模式 |
| [Trojan](../docs/outbounds.md#trojan) | 通过 TLS TCP、WebSocket / HTTPUpgrade 或 gRPC 传输 TCP/UDP |
| [Shadowsocks 2022](../docs/outbounds.md#shadowsocks-2022) | TCP/UDP；三种 2022 算法与 AES 身份链；可选 obfs、WebSocket、JLS 或 strict ShadowTLS v3 插件；UoT v2 |
| [AnyTLS](../docs/outbounds.md#anytls) | TLS 会话与 UDP over TCP v2 |
| [HTTP / HTTPS CONNECT](../docs/outbounds.md#http--https-connect) | TCP CONNECT、可选代理认证与 TLS |
| [SOCKS5](../docs/outbounds.md#socks5) | CONNECT 和 UDP ASSOCIATE，可选用户名/密码认证 |
| [Hysteria2](../docs/outbounds.md#hysteria2) | QUIC TCP/UDP、带宽控制、Salamander/Gecko、端口跳跃或 Realm/STUN，以及 mTLS |
| [TUIC v5](../docs/outbounds.md#tuic-v5) | QUIC TCP/UDP、native/quic UDP 转发、UoT v2、拥塞控制选择；`disable-sni` 仍保留证书验证 |
| [WireGuard](../docs/outbounds.md#wireguard) | 标准 WireGuard TCP/UDP、多 peer 与节点 DNS，使用用户态 IP 栈 |
| [TrustTunnel](../docs/outbounds.md#trusttunnel) | H2/H3 CONNECT 承载 TCP/UDP，支持认证、健康检查、mTLS 和 ECH |
| [Mieru](../docs/outbounds.md#mieru) | TCP/UDP 载体承载 TCP/UDP，支持复用、STANDARD/NO-WAIT 握手与 traffic-pattern |
| [MASQUE](../docs/outbounds.md#masque) | H2/H3 CONNECT-IP 承载 TCP/UDP；H3 L4 模式仅支持 TCP |

VMess、VLESS、Trojan 与 AnyTLS 可在各自支持的 TCP 载体上使用 ShadowTLS v3 或 JLS；VMess 与 Trojan 还支持 REALITY。传输限制与身份互斥遵循[共享流式安全约束](../docs/outbounds.md#流式安全身份)。

标准 TLS 连接支持证书验证与 SHA-256 证书固定。适用的 TCP TLS 路径可使用 Chrome、Firefox、Safari 或 iOS ClientHello 模板；`client-fingerprint` 与证书 `fingerprint` 相互独立。准确的名称和支持组合见 [TLS 配置与证书策略](../docs/tls-client-fingerprint.md)。这些功能不保证与浏览器不可区分，也不支持任意协议组合。

SS2022 复用未经修改的官方 Rust 加密与编解码，由 Vole 初始化 padding 并处理 server-first，详见 [Shadowsocks 契约](../docs/outbounds.md#shadowsocks-2022)。

## Mihomo 风格配置

使用熟悉的 `proxies`、`proxy-groups`、`rules`、`dns`、`mixed-port` 和 `tun` 结构。例如：

```yaml
mixed-port: 1080
allow-lan: false

proxies:
  - name: edge
    type: anytls
    server: proxy.example.com
    port: 443
    password: replace-with-your-password
    client-fingerprint: chrome
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies: [edge, DIRECT]

dns:
  enable: true
  nameserver:
    - "udp://223.5.5.5:53#DIRECT"

rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,Proxy
```

请替换示例中的服务器地址与凭据。GeoSite/GeoIP 使用 `<dataDir>/geodata` 下的数据文件；缺失的必需资产通过配置出口下载，加载成功前对应规则不可用。详见[配置参考](../docs/config.yaml)与 [GeoData 行为](../docs/geodata.md)。

`mixed-port` 在同一 TCP 端口接入 HTTP 与 SOCKS5，并在同端口启用 SOCKS5 UDP。`allow-lan` 控制绑定地址，与 `authentication` 独立：`authentication` 省略或为 `[]` 时，回环与通配绑定均免认证；配置凭据后 HTTP 与 SOCKS5 均校验。顶层 `port`、`socks-port`、`udp` 和 `listeners` 都会拒绝；代理节点的 `port` 与 `udp` 保留出站含义。

兼容范围限于文档列出的 Mihomo 配置子集。未知字段与不支持的组合明确拒绝；当前平台和协议边界见 [Mihomo 兼容范围](../docs/mihomo-compatibility.md)与各项契约。

库接口由宿主使用内联 `configYaml` 启动实例；TUN 设备、描述符、MTU、DNS 拦截和 UDP 超时归属于 `tun` 配置，平台回调仍在运行时本地注册。CLI 通过同一 Invoke API 传递参数，由其前台操作读取 `-f` 指定的配置。Linux 自建 TUN 可配置自动路由与 systemd-resolved DNS；借用 fd 和 App 平台的网络仍由宿主管理。

## CLI

通过 `uv run --project scripts --locked vole-scripts build cli` 构建前台程序。Windows CLI 固定使用 Wintun；FFI 使用 `build windows --backend wintun|uwp` 选择后端，默认 UWP。tag Release 同时发布 CLI 和 FFI，Windows CLI 仅 Wintun，FFI 提供两种后端。目标与包内容见[编译脚本](../scripts/README.md)。

```sh
vole -f /path/to/config.yaml
vole -d /path/to/data -f ./config.yaml
vole -t -f ./config.yaml
```

`-d` 设置配置及数据目录，`-f` 独立指定配置文件；相对路径均从启动工作目录解析。省略 `-f` 时读取 `<数据目录>/config.yaml`，目录默认用户的 `.config/vole`，按 Mihomo 规则回落到 `XDG_CONFIG_HOME`。`-f -` 从标准输入读取。`VOLE_HOME_DIR` / `VOLE_CONFIG_FILE` 提供环境默认值，显式参数优先。`-t` 只校验配置，`-v` 显示版本与构建身份，`-h` 显示帮助。详见 [CLI 与 tag 发布](../docs/cli.md)。

## 平台与集成

| 平台 | TUN 集成 |
| --- | --- |
| iOS / macOS | 宿主提供 utun 文件描述符；macOS 也可打开或创建原生 utun |
| tvOS 17+ | 宿主提供 utun 文件描述符；支持 ARM64 真机和模拟器目标 |
| Android | `VpnService` 文件描述符与出站 socket 保护 |
| Linux | 借用 fd 或由内核打开设备的真实单队列 raw-IP TUN；Linux 自建设备支持自动路由与系统 DNS |
| Windows | 编译时互斥的 `windows-wintun` 桌面后端与 `windows-uwp` 安装包 Provider/Session Host；共用内核 |

Vole 提供原生库和前台 CLI。Apple、Android、Windows 的系统网络与 App 生命周期由宿主负责；Linux 自建 TUN 另外支持自动路由和系统 DNS。Unix 宿主持有原始 TUN 描述符；Vole 使用并关闭自己复制的描述符。Apple 公开的 packetFlow API 不保证可获取 raw fd，因此实际 Network Extension 集成和设备验证仍由宿主负责。详见 [TUN 集成](../docs/tun-platform.md)与[平台验收边界](../docs/acceptance.md)。

桌面 Wintun 从进程可执行文件所在目录加载宿主提供的 `wintun.dll`。接口地址、DNS、路由与物理出口由宿主配置；Wintun 与安装包 UWP 分别进行设备验收。命令行使用与交付见 [CLI 与 tag 发布](../docs/cli.md)。

跨平台 C ABI 通过 Invoke API 接受 JSON 请求：

```c
char *VoleInvoke(const char *request_json);
void VoleFree(char *response);
```

单个公共实例遵循 `initialize → createInstance → start(configYaml) → stop → destroyInstance` 生命周期，准备过程由 `start` 内部完成；`validateConfig` 不要求初始化。CLI 通过显式的前台 Invoke 操作处理文件、环境默认值、信号与清理。API 还提供状态查询、GeoData 状态与延迟测量。详见 [Invoke API](../docs/invoke-api.md)、[Controller API](../docs/controller-api.md)与 [Windows 集成示例](../example/windows-uwp/README.md)。

## 文档

- [文档索引](../docs/README.md)
- [配置参考](../docs/config.yaml)
- [Mihomo 兼容范围](../docs/mihomo-compatibility.md)
- [核心与平台构建](../scripts/README.md)
- [CLI 与 tag 发布](../docs/cli.md)
- [核心回归测试](../tests/README.md)
- [资源策略](../docs/runtime-resource-policy.md)
- [验收与已知限制](../docs/acceptance.md)

## Credits

Vole 使用并参考以下公开依赖、协议实现和平台资料：

- TUN 依赖：自有 [`vole-netstack`](../crates/vole-netstack/README.md) 使用 [smoltcp](https://github.com/smoltcp-rs/smoltcp)，Unix 与 Windows Wintun 包 I/O 使用 [tun-rs](https://github.com/tun-rs/tun-rs)（Apache-2.0）。
- WireGuard：[boringtun](https://github.com/cloudflare/boringtun)（BSD-3-Clause），不启用 host-device、FFI 或 JNI。
- [Wintun](https://www.wintun.net/)：运行时 DLL 由宿主提供，不随 Vole 捆绑。tun-rs 中的上游 [API 头文件](https://github.com/tun-rs/tun-rs/blob/2.8.11/src/platform/windows/tun/wintun.h) 版权为 2018–2021 WireGuard LLC，许可证为 `GPL-2.0 OR MIT`；分发链接的 API bindings 时须保留其版权和 MIT 可选许可证声明。
- 网络与路由参考：[clash-rs](https://github.com/Watfaq/clash-rs)、[netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp)、[Mihomo](https://github.com/MetaCubeX/mihomo)、[Xray-core](https://github.com/XTLS/Xray-core) 和 [Leaf](https://github.com/eycorsican/leaf)。这些参考项目并非 netstack 依赖。
- TLS 与 Shadowsocks：[rustls](https://github.com/rustls/rustls)、[boring](https://github.com/cloudflare/boring)、[BoringSSL](https://boringssl.googlesource.com/boringssl/) 和 [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)。衍生的重放窗口代码保留了 [MIT 声明](../src/outbound/shadowsocks/packet_window.rs)。
- Windows 集成：[windows-rs](https://github.com/microsoft/windows-rs)、[UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample)、[wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs)、[Maple](https://github.com/YtFlow/Maple) 和 [YtFlowCore](https://github.com/YtFlow/YtFlowCore)。

## License

[MIT](../LICENSE)。
