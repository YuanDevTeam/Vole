# Windows VPN 平台边界

本文维护 MSIX 安装包中的官方 `Windows.Networking.Vpn` / `windows-rs` 路径。完整代理运行时位于每会话 Session Host；AppContainer Provider 只负责 Windows VPN 平台资源和失败关闭。普通桌面进程的 Wintun 适配见 [TUN 平台层](tun-platform.md#windows-wintun)，两条路径共用内核且不互相降级。

Windows 包构建显式启用 `ffi,windows-uwp`。`invoke` 提供共用业务 dispatcher，`ffi`
仅包装 C ABI/JNI；`windows-uwp` 单独启用 WinRT VPN 功能、Provider/Session Host 与包集成。
普通 CLI 使用 `cli,windows-wintun`，两种后端在 Windows 编译时互斥，UWP 不拉入
tun-rs 的 Wintun 后端，也不依赖外置 `wintun.dll`。Wintun 的 interruptible I/O
会间接使用 Windows Win32 bindings；这不启用 `Networking_Vpn` 等 WinRT 包功能。

## 安装包边界

- 最低目标系统：Windows 10 20H2 build 19042。
- 目标架构：ARM64 和 x64。
- 分发形式：具有 package identity 的 MSIX。
- 前台：调用 Windows 桥接接口的完全信任宿主。
- Provider：同 package family 的 AppContainer 应用。
- Session Host：同一主 Application 的完全信任 extension，每个 VPN 会话一个独立进程，可选拥有同包 session backend。
- Windows 依赖：`windows = 0.62.2`。
- Manifest：包含 `networkingVpnProvider` 和 `runFullTrust`，不配置产品级 loopback exemption。

未安装的普通桌面进程没有 package identity，Windows VPN 桥接会失败关闭。

### COM / WinRT 生命周期

`VoleWindowsVpnInvoke` 在调用线程上配对执行 `RoInitialize(MTA)` / `RoUninitialize`。
调用线程可以尚未显式初始化 COM，或已经是 MTA；STA/ASTA 调用失败，不改变调用方的 apartment。

桥接首次成功进入 MTA 时，通过 `CoIncrementMTAUsage` 保留一份进程寿命的 MTA 引用，
与 `windows-rs` 的静态 agile factory 缓存同寿命。即使调用线程退出、调用方释放自己的
MTA，或两次请求之间没有显式 MTA 线程，缓存也不会跨越 MTA 拆卸后被再次使用。
这是一份固定引用，不随请求增长；不在逐次返回或 DLL/process teardown 时释放，
也不在 loader lock 内执行 COM 清理。获取失败仍配对释放本次初始化，并返回失败。

宿主无需额外持有 MTA，可以从不同的短生命周期工作线程串行调用。返回后，原本未显式
初始化的线程可能属于进程的 implicit MTA；桥接不会遗留该线程的显式初始化计数。
命令仍不允许重叠，不增加工作队列，也不改变包身份、profile 或会话生命周期。

## `IVpnPlugIn` 回调

Provider 实现：

- `Connect`：选择物理网络、建立包通道、等待 Session Host 就绪，再调用 `StartWithMainTransport`；
- `Encapsulate`：复制 Windows 交付的 L3 包、归还系统缓冲区，并非阻塞地提交到有界入站队列；
- `Decapsulate`：排空已就绪的出站包，填充 `VpnPacketBuffer` 并 flush；
- `Disconnect`：停止包通道、等待有界确认、清理传输并调用 channel Stop；
- `GetKeepAlivePayload`：不承载业务数据。

所有回调都按可并发处理。Provider 只保留回调安全状态和一个会话所有者；panic 不能越过 COM 边界。

### 缓冲区所有权

- 回调内把 `IBuffer` 内容复制到 Vole 持有的内存；
- 不在回调之后保存裸 slice、`VpnPacketBuffer` 或系统列表；
- 每个系统缓冲区只归还一次；成功取得缓冲区后，任何后续本地错误都必须先归还缓冲区再传播；归还 API 自身失败时传播平台错误并失败关闭；
- 队列满时只丢当前包并计数，不能阻塞 Windows 回调。

## 原始 IP 数据面

```text
Windows route
  -> VpnChannel callback
  -> Provider 有界入站队列
  -> 命名管道数据通道
  -> Session Host WindowsTunIo
  -> vole-netstack
  -> DNS / 规则 / 出站图
  -> 命名管道数据通道
  -> Provider 有界出站队列
  -> Decapsulate
```

数据帧：

```text
u16 大端序包长
1..=1500 字节原始 IP 包
```

- 每个方向只有一个写端；
- EOF、零长度、超限、截断和帧格式错误会停止当前会话；
- 合法帧中的非法 IP 包由原始包解析器局部丢弃，不破坏帧同步；
- 写端等待首包后，最多合并另外 7 个已经就绪的包，不等待计时器或未来数据；
- 读端使用 64 KiB 缓冲区，但仍逐帧校验；
- Provider 两侧包队列容量均为 256；从空变为非空时只发一次唤醒；
- `Decapsulate` 每次排空当前已就绪队列，队列满按包计数。

`tun.mtu` 同时用于 Provider 的 `StartWithMainTransport`、Session Host netstack 和包校验，最大 frame 为 MTU 加 12。WinRT 接口 MTU 上限为 1400；配置必须显式填写受支持值，例如 `mtu: 1400`。内核通用默认 9000 在此路径会报错，不会被静默截断。TUN/XUDP 与 DNS UDP 响应负载保守限制为 MTU 减 48；MTU 1400 时为 1352 字节。packet channel 的 1500 上限仍是帧解析的结构边界，不是 Windows L3 接口宣告值。

`tun.file-descriptor` 必须省略或为 0。`startVpn` 在发布 Session Snapshot 前拒绝非零值；
Provider 和 Session Host 读取配置时执行相同的平台校验。通用配置校验仍允许 Unix fd。

控制消息使用独立管道，避免包背压阻塞启动和停止。

## 回包唤醒

`VpnChannel` 要求 Provider 关联受管理传输。Provider 在同一 AppContainer 内建立一对绑定当前物理地址的本地 `DatagramSocket`，并把主 socket 交给 `AssociateTransport` 和 `StartWithMainTransport`：

1. 出站队列从空变为非空时，配对 socket 向主 socket 发送一个哑数据报；
2. Windows 触发 `Decapsulate`；
3. 回调消费哑数据报并排空已就绪的原始包；
4. 队列持续非空时不重复唤醒。

哑数据报只用于调度，不承载业务包。主 socket 不能绑定回环地址；Windows 必须从它识别物理接口，才能把 local/CIDR exclusion route 落到物理出口。

## 路由与 DNS

每个地址族使用两条 `/1` inclusion route：

```text
IPv4: 0.0.0.0/1, 128.0.0.0/1
IPv6: ::/1, 8000::/1
```

顶层 `ipv6` 默认为 `true`。设为 `false` 时，Provider 只安装 IPv4 `/1` 路由，只分配 IPv4 TUN 地址，并且只向 Windows 注册 IPv4 DNS；不会安装或分配任何 IPv6 项。传给 `StartWithMainTransport` 的 IPv6 client-address 参数必须是 null，而不是空集合；Windows 11 ARM64 对空集合返回 `0x8007000E`。

Windows profile 固定覆盖所有应用，不使用 AppTriggers、traffic filters 或流量身份。每次会话还应用完整 policy：

- `allowLocalNetwork: true` 设置 `VpnRouteAssignment.SetExcludeLocalSubnets(true)`；
- `allowLocalNetwork: false` 清除该标志，并为物理适配器的每个去重 on-link prefix（包括 link-local）生成更具体的 inclusion routes，避免 `/1` inclusion route 因优先级较低而旁路 VPN；
- `excludedCidrs` 按地址族加入 exclusion routes，不修改两条 `/1` inclusion routes；生成本地 inclusion routes 前先减去全部显式排除范围，确保排除项不会被更具体的本地 inclusion 覆盖；
- `alwaysOn` 写入 profile capability；实际自动连接仍由 Windows 用户设置和 active profile 决定。

排除项最多 64 条，必须是规范 network/prefix；重复、host bits、`/0`、禁用 IPv6 时的 IPv6 项和包含 VPN DNS 的项都会在接触 WinRT 前失败关闭。

不能把 IPv4 两条 `/1` 合并为 `/0`。Windows 包环境中的验证表明，VPN `/0` 会使按产品要求绑定物理源地址和接口索引的外层 socket 返回 `WSAENETUNREACH`，而两条 `/1` 可以保持物理出口。

前台宿主在 `startVpn` payload 中提供当前会话的 TUN IPv4/IPv6、DNS IPv4/IPv6 和 policy。四个地址与三个 policy 字段始终严格必填并经过验证；即使顶层 `ipv6: false`，两个 IPv6 地址仍保留在桥接契约中，但 Provider 不使用。桥接把地址、顶层 IPv6 开关、policy 与 Session token 写入 profile custom configuration，Provider 再按开关传给 `StartWithMainTransport`。这些字段不写入用户 RAW YAML。

Provider 为后缀 `.` 安装外部 DNS 地址：

- `dns.enable: true`：目标端口 53 由 Vole 运行时 DNS 处理；
- `dns.enable: false`：TCP/UDP 53 保留原 DNS 目标，作为普通业务流量执行规则。

Windows DNS assignment 本身不提供解析器或 NAT。

## 物理出口防递归

Provider 在安装路由前选择不可变的：

- 适配器 GUID；
- 网络 profile 和 network identity；
- 每个可用地址族从非 link-local 地址中选定的一个源 IP 和对应非零接口索引；
- 独立于源地址选择保留的、物理适配器上全部去重的 on-link prefixes，包括 link-local。

Session Host 的每个非回环出站 socket 必须同时应用：

```text
源地址 bind + IP_UNICAST_IF / IPV6_UNICAST_IF
```

只绑定其中一项不满足契约。只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过；物理代理服务器的域名在准备阶段解析到任何回环地址都会失败关闭。局域网和私有地址不属于例外。缺少地址族、源地址绑定或接口设置失败时，当前连接失败关闭。

全局/节点 `interface-name` 和普通 DNS `#接口` 只允许选择同一个 Provider 物理适配器。
友好名、系统接口名和 GUID 由 Windows SDK 转换为实际接口身份；不匹配时当前连接失败，
不改变绑定源地址、接口索引或会话快照。非零 `routing-mark` 在 Windows 上不可用。
桌面 Wintun 的显式接口选择仅设置普通出站 socket，不取得 Provider 绑定或代替宿主路由配置。

`AssociateTransport` 只用于 Provider 的受管理唤醒传输，不用于普通代理流。Session Host 不持有 `VpnChannel`，不能给逐流 socket 获取同类豁免。

显式 `system` DNS 仅由实际 Session Host 在显式查询按需读取既有物理适配器 GUID 的 DNS 数据（metadata 缓存 20 秒），继续执行同一 `(源 IP, 接口索引)` 绑定；不读取前台 Invoke registry，也不改变控制协议。`GetInterfaceDnsSettings` v3 不可用或存在无法满足的加密要求时来源不可用。原生 IPv6 DNS 的加密策略无法通过该只读查询确认，也保持不可用。无法确认 DHCP option 6 来源时 `dhcp://<接口>` 不可用。系统 DNS 发现不配置或恢复系统网络，App 仍负责原有网络设置和生命周期。

## 网络变化

Provider 是物理网络状态的唯一权威，并订阅 `NetworkStatusChanged`。事件到达后等待 2 秒，再复验适配器 GUID、选定源地址、全部去重 on-link prefixes 和 network identity；任一项变化就停止当前 VPN。

当前实现不迁移现有 socket、不重选接口，也不回退到未绑定 socket。Session Host 不自行更新物理绑定。

## AppContainer 与 Session Host

- Provider 创建 AppContainer 本地控制管道和数据管道；
- `GetAppContainerNamedObjectPath` 提供限定对象路径；
- Provider 通过无参数 `FullTrustProcessLauncher` 激活同一 Application 的 Session Host；
- Session Host 使用当前 Windows session ID 构造限定路径并连接；
- 前台宿主退出不停止 Provider 或 Session Host，重新启动后从系统 profile 恢复状态。

会合记录只包含协议版本、Session token、相对对象路径和固定管道名称，不包含 YAML、backend 描述、参数、secret、PID、物理绑定或任意文件路径。Provider 是唯一发布者和清理者。

## 安装包与 profile

安装包必须包含：

```text
HostApplication.exe
vole.dll
vole-windows-vpn-host.exe
vole-windows-session-host.exe
```

- manifest 只有一个主 Application，三个可执行参与者相互独立；产物架构一致，Rust 使用静态 CRT；
- Session Host 是 `windows.fullTrustProcess` extension，不显示在应用列表，也不注册 StartupTask 或 URI；
- Provider 的 `windows.backgroundTasks` extension 显式使用 `windowsApp + appContainer`；
- Provider activation class 来自 `vole.dll`；
- 宿主为同一 package 使用一个稳定的 VPN profile 名称；`startVpn`、`getVpnStatus`、`stopVpn` 的可选 `profileName` 缺省为 `Vole`，匹配和改名边界见 [Invoke API](invoke-api.md#vpn-profile-名称)。同包仍只允许一个活动会话；
- custom configuration 是最大 4 KiB 的严格 JSON，只含修订版 4、Session token、顶层 IPv6 开关、四个网络地址和完整 policy；
- Session Snapshot 是 `LocalState/vole/windows/sessions/<sha256>.json`，revision 2 覆盖完整 YAML、可选进程顺序、路径和参数；读取验证大小、普通文件、reparse point、规范 JSON、摘要和每个 executable。参数引用的文件由宿主保持存在且不可变，Vole 不读取其内容；
- 活动 Session token、IPv6 开关、网络地址或 policy 不同时必须先显式 Stop，不能热切换；
- 安装包更新只能在 VPN 已断开时进行，并要求版本递增。

## 失败关闭

| 事件 | 结果 |
| --- | --- |
| 前台宿主退出 | VPN 和 Session Host 继续运行 |
| Provider 退出 | Windows 清理 VPN，Session Host 因 EOF 退出 |
| Session Host 退出 | Job 清理受管进程，Provider 触发 channel Stop |
| 控制或数据管道非法/EOF | 停止当前会话 |
| 物理网络变化 | 消抖后停止当前会话 |
| 受管进程退出 | 清理同 Job 进程并停止当前 VPN |
| 本地 SOCKS 流失败且服务进程仍存活 | 只失败当前流 |
| 显式 Stop | 有界确认后清理路由、记录、Controller 和会话进程 |
| 启动失败 | Provider Connect 失败；未完成握手的 Session Host 最多等待 15 秒后退出 |

当前实测范围和未完成平台门禁见 [验收矩阵](acceptance.md)。

## 参与者与所有权

```text
前台宿主（完全信任）
  ├─ VoleInvoke
  └─ VoleWindowsVpnInvoke
       ├─ Session Snapshot / profile
       └─ ConnectProfileAsync
              │ Windows 激活
              ▼
vole-windows-vpn-host.exe + vole.dll（AppContainer）
  ├─ VpnChannel / 路由 / DNS / 物理网络
  ├─ VpnPacketBuffer / 有界回调队列 / 失败关闭
  └─ FullTrustProcessLauncher
              │ 无参数激活
              ▼
vole-windows-session-host.exe
  ├─ 校验不可变 Session Snapshot
  ├─ 可选 Windows session backend / Job Object
  ├─ PreparedCore / RunningCore
  ├─ DNS / 规则 / GeoData / 嗅探器 / select 代理组
  ├─ 统一出站图
  └─ 运行时 Controller（TUN 流量 / 代理组选择）
              ▲
              └─ 同包控制管道 + 数据管道
```

| 参与者 | 拥有 | 不拥有 |
| --- | --- | --- |
| 前台宿主 | 用户命令、会话记录、UI 状态 | TUN 运行时、包通道、Provider 状态 |
| Windows 桥接 | Session Snapshot、profile、连接/断开命令 | 数据包、代理流、Session Host 进程 |
| Session Host | 单次 Vole 运行时、可选 session backend、Controller、GeoData、包客户端 | `VpnChannel`、路由、进程业务配置 |
| Provider | `VpnChannel`、WinRT 缓冲区、路由、物理绑定、管道服务端、网络监控、Session Host 激活 | YAML、代理图、Controller、GeoData、backend 描述 |
| SOCKS 服务 | 自身监听器、外层 socket 和绕过策略 | Vole 代理图和 Windows profile |

Session Host 每次连接新建一个进程，不常驻、不复用运行时，也不处理 URI 或 StartupTask。


## 启动顺序

1. 前台宿主调用 `startVpn(configYaml, networkSettings, policy, sessionBackend?, profileName?)`，后续查询和停止使用同一 profile 名称。
2. 桥接验证配置、四个地址、policy 和进程描述，发布不可变 Session Snapshot，并把解析后的顶层 IPv6 开关和 policy 写入 profile configuration。
3. 桥接按当前 package family 和请求的名称查找并写入 VPN profile，再调用 `ConnectProfileAsync`；它不接管其它 profile，也不启动或持有 Session Host。
4. Windows 激活 AppContainer Provider。
5. Provider 从 profile configuration 取得权威 token，选择物理网络绑定并准备基础资源。
6. Provider 清理陈旧会合记录，通过无参数 `FullTrustProcessLauncher` 激活 Session Host。
7. Session Host 不读取动态命令行参数，等待 Provider 会合记录。
8. Provider 创建控制/数据管道服务端并原子发布会合记录。
9. Session Host 严格解析会合记录，把其中的 token 作为候选值，构造限定对象路径并连接两条管道。
10. Session Host 发送 `SessionHello`；Provider 把候选 token 与 profile token 精确比较后返回 `ProviderHello` 和不可变物理绑定。
11. Session Host 验证 `ProviderHello` 回传同一 token，之后才读取 Snapshot；若存在 backend，则用一个 kill-on-close Job Object 按顺序启动全部进程。
12. Session Host 准备并启动完整 Vole 运行时、静态代理组状态和 Controller。
13. Session Host 确认受管进程尚未退出后返回 `RuntimeReady`。
14. Provider 调用 `StartWithMainTransport` 并启动失败关闭监视器。
15. 连接成功后，桥接向前台宿主返回当前系统 VPN 状态。

任一步失败都必须关闭包通道并收敛为 Disconnected，只返回有界脱敏错误；未完成握手的 Session Host 最多等待 15 秒后退出。

Session Host 的路径读取和启动失败日志必须在同一次 WinRT 初始化周期内完成；`RoUninitialize` 后不能再次查询缓存的 `ApplicationData` factory。没有 package identity 的裸启动快速、安全退出，不进入握手、不启动 backend，也不回退到普通用户数据目录。


## 会合记录

`LocalState/vole/windows/rendezvous.json` 最大 4 KiB：

```json
{
  "protocolVersion": 1,
  "snapshotToken": "vole-session-v2:...",
  "objectPath": "AppContainerNamedObjects\\S-1-15-2-...",
  "controlLeaf": "Vole.Vpn.Control.v1",
  "dataLeaf": "Vole.Vpn.Data.v1"
}
```

- Provider 是唯一发布者和清理者；
- 使用同目录暂存文件和原子重命名；
- 只接受规范 token、AppContainer 相对路径和固定 leaf；
- 非普通文件、reparse point、超限或未知字段都会失败关闭；候选 token 与 profile token 的绑定只在双向握手中完成；
- 握手完成后删除，新连接前清理断开状态下的陈旧记录。


## 控制协议

```text
u32 大端序 JSON 长度
严格 UTF-8 JSON
```

- 单帧最大 16 KiB；
- DTO 拒绝未知字段、错误版本和错误顺序；
- 错误码最大 128 字节，脱敏信息最大 4 KiB；
- 不传 YAML、Controller secret、SOCKS 凭据、日志或 Invoke 请求。

版本 1 消息：

```text
SessionHello { version, snapshotToken }
ProviderHello { version, snapshotToken, physicalBinding }
RuntimeReady { version }
RuntimeFailed { version, code, redactedMessage }
Stop { version, packetCounters }
Stopped { version, packetCounters }
```

启动超时 15 秒，有序停止确认超时 10 秒。活动包流没有空闲超时或 heartbeat。


## Windows session backend

`sessionBackend` 可以省略；存在时包含 `1..=8` 个进程。每个进程只声明：

```json
{
  "executableRelativePath": "bin\\proxy-core.exe",
  "arguments": ["run", "--mode", "vpn"]
}
```

- executable 必须是 package installed location 内不经过 reparse point 的规范 `.exe` 相对路径；
- argv 项数、单项大小、总大小和最终 UTF-16 command line 均有界；
- 不经过 shell，不展开环境变量，工作目录固定为 package installed location；
- Session Host 使用 `CreateProcessW(CREATE_SUSPENDED)`，先加入设置了 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 的 Job，再恢复主线程；
- 所有进程都是关键进程；任一退出都会停止 Vole、终止同 Job 中的其余进程并使 Provider 失败关闭；
- Stop 先停止 Vole，再终止 Job，确认活动进程归零后才返回 `Stopped`；
- 第一版不提供 port、UDP、readiness、heartbeat、restart、environment、working directory 或单进程控制；
- `RuntimeReady` 只表示进程仍存活且 Vole 已启动，不表示进程内部协议已就绪。


## Controller 与本地 SOCKS

- Controller 由 Session Host 按 YAML 的 `external-controller` 地址监听；
- `RuntimeReady` 前必须完成绑定，失败则连接失败；
- 前台宿主持有配置中的端口和 secret，并调用 `GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 或 `PUT /proxies/{name}`；
- `secret` 可省略或为空；配置非空 `secret` 时保护全部路由，与是否配置代理组无关；
- 代理组选择属于 Session Host 中实际 Running Session 的内存状态，不经过 Windows bridge、Provider 控制管道或 Session Snapshot 写回；
- 成功切换只影响之后新建的物理 TCP、UDP 和 DNS transport，不迁移既有连接、UDP association、DNS 状态或 TCP pool，也不执行自动 failover；
- 宿主如需跨 VPN session 保留选择，必须自行持久化，并在下次 `startVpn` 的 YAML 中注入对应 `default-selected`；
- 前台宿主退出后 Controller 和运行时继续，重新启动后恢复查询；
- Stop 关闭 Controller，销毁本次代理组选择；下一会话重新采用 YAML 初始选择并从零计数；
- 回环 SOCKS5 是普通 Vole 出站；其服务可以由外部宿主管理，也可以恰好运行在 session backend 中，但 Vole 不从 backend 描述推断端口或 readiness；
- 单个 SOCKS 流失败不停止 VPN。


## 官方 API

- [`IVpnPlugIn`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.ivpnplugin)
- [`VpnChannel`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel)
- [`VpnChannel.StartWithMainTransport`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel.startwithmaintransport)
- [`VpnChannel.AssociateTransport`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnchannel.associatetransport)
- [`VpnPacketBuffer`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnpacketbuffer)
- [`VpnManagementAgent`](https://learn.microsoft.com/uwp/api/windows.networking.vpn.vpnmanagementagent)
- [`FullTrustProcessLauncher`](https://learn.microsoft.com/uwp/api/windows.applicationmodel.fulltrustprocesslauncher)
- [Package identity](https://learn.microsoft.com/windows/apps/desktop/modernize/package-identity-overview)
- [`RoInitialize`](https://learn.microsoft.com/windows/win32/api/roapi/nf-roapi-roinitialize)
- [`CoIncrementMTAUsage`](https://learn.microsoft.com/windows/win32/api/combaseapi/nf-combaseapi-coincrementmtausage)


`startVpn` 可选 `httpConfigYaml` 接收[独立 HTTP 规则](http-processing.md)，不放入 Mihomo YAML。规则进入已校验的 Session Snapshot canonical 内容并参与 digest；实际 Session Host 读取并构造规则，前台 registry 不替代业务消费者。未携带该字段的快照序列化保持原形式，快照和 bridge 的既有总体字节预算继续生效。
