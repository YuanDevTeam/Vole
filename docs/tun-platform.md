# TUN 平台层

Vole 的 netstack、DNS、规则和出站只处理完整的原始 IPv4/IPv6 数据包。平台差异集中在 `platform::TunIo`；Windows 通过互斥的 `windows-wintun` / `windows-uwp` feature 选择桌面 Wintun 或安装包 WinRT VPN，两者共用其后的运行时和代理图。

## Unix 借用 fd

```text
TunRuntime -> TunRsIo -> 宿主持有的 TUN fd 副本
```

- iOS/tvOS/macOS：宿主提供 utun 文件描述符，适配器处理四字节 packet-information 头。
- Android：`VpnService` 提供 raw-IP 文件描述符。
- Linux：真实单队列 TUN，使用 `IFF_TUN | IFF_NO_PI`、无 VNET header；接口实际 MTU
  必须与 `tun.mtu` 一致。借用 fd 的地址、网络命名空间和路由由宿主负责。

`tun.file-descriptor` 缺省或 0 时，Linux / macOS 由 core 打开本机 TUN，Android / iOS /
tvOS 仍需宿主提供 fd。`tun.device` 控制原生打开的接口名：空值在 Linux 使用 `Vole`，
macOS 自动选择 utun。macOS 只设置自有接口的 MTU 和 nonblocking，网络配置仍由宿主负责。
Linux 自建接口的自动网络配置见下节；关闭自动路由时只设置 MTU/nonblocking。
Stop 关闭自有句柄，不承诺删除宿主已有接口。创建失败没有备用数据面。
正数 file-descriptor 选择下述借用路径；fd 数字必须对当前进程有效，CLI 不增加专用 fd 参数。

宿主始终拥有原始文件描述符。Vole 启动时：

1. 验证文件描述符有效且已设置 `O_NONBLOCK`；
2. 通过 `F_DUPFD_CLOEXEC` 创建 Vole 持有的副本；
3. 把副本交给 `tun-rs::SyncDevice::from_fd`，并用 Tokio `AsyncFd` 驱动；
4. 停止时只关闭副本。

借用路径不调用会修改共享 open-file-description 标志的异步构造器，也不重配置接口。
帧格式是平台内部固定约定：Apple 使用 utun packet-information，Android 和 Linux 使用
raw IP；YAML 和 Invoke 不提供 framing 参数。借用 fd 时以真实接口身份为准，`device`
不重命名已有接口。配置校验不取得 fd 或创建接口；资源检查发生在核心启动阶段。

Linux 启动前查询真实 TUN 及其所属网络命名空间，验证内核链接参数、实际 MTU 和
raw-IP 格式；普通 socket/pipe、TAP、PI、VNET header 或多队列设备失败关闭。
需要可读 procfs 和 TUN 所属 user namespace 的 `CAP_NET_ADMIN`，即使 fd 与
Vole 在同一网络 namespace，也必须能执行 `TUNGETDEVNETNS`；借用一个有效 fd
不能绕过此权限检查。
跨命名空间检查仅在专属短线程切换 namespace，完成并 join 后再启动运行时，
不改变 Invoke 或业务工作线程的 namespace；宿主还需提供 `CAP_SYS_ADMIN` 等
相应 `setns` 权限。同 namespace 不执行 `setns`。
宿主原 fd 保持有效、非阻塞，运行期间不得改变接口格式或 MTU。

Linux 压测可以把 TUN 创建在客户端 namespace，再把借用 fd 交给正常出口 namespace
中的 Vole：客户端业务经 TUN，Vole 的普通 TCP/UDP socket 经正常物理出口。
接口创建、路由隔离和清理由宿主完成；Vole 不隐式设置 default route 或保护标记。
首轮验证为 GNU/glibc 原生构建与容器真实 TUN；musl、其他架构、安装交付和设备验收
不由一次 Linux 容器压测推导。Linux RSS/VmHWM 与 Apple physical footprint 分开报告。

tvOS 首版为 17.0+、ARM64 真机和 Apple Silicon 模拟器，共用原有 TunIo、netstack 和
Dialer；不新增低内存数量上限，不改变其他平台默认行为。iOS/tvOS 的 TUN 生命周期接入
Apple Unified Logging、TASK_VM_INFO 当前/进程峰值观察及停止后的 allocator pressure relief。
既有 35/40/45 MiB 阈值仅发出诊断，不是系统限额或业务准入条件；macOS 不启用这组
移动扩展周期采样。tvOS 事件使用 tvos_memory_*，iOS 保留 ios_memory_*。

Apple 公开 NEPacketTunnelFlow API 是 packetFlow 的包读写，不承诺可取得 raw fd。
Vole 的借用 fd 契约不能证明宿主 KVC 提取 fd 是稳定公开方案。模拟器 socketpair 只验证
合成 utun 数据面；真实宿主的 fd 获取/桥接、签名与 entitlement、系统路由、设备生命周期
及物理内存须独立验收。当前没有新增 packetFlow 回调 ABI，也不暗中回退其他接入路径。

包 I/O 规则：

- `recv == 0` 表示设备关闭；
- 首个半字节必须表示 IPv4 或 IPv6；
- 单次读取缓冲区按配置 MTU 复用，缺省或零值为 9,000 字节；
- 写入必须一次完成整个包，部分写入立即失败；
- Apple 写入的瞬时 `ENOBUFS` 不终止整个运行时：只保留当前尚未接受的包，异步退让
  1 ms 后重试，Stop/取消仍直接释放该 future；不新建后台重试任务、不扩大宿主 socket
  缓冲，也不重发已经成功写出的包。其他错误和部分写入仍失败关闭；
- Apple PI 头不进入 netstack，也不计入流量。

所有平台的公共 TUN 循环按最多 8 包的有界批次推进：等到首包后只收取已经就绪的包，
不等待计时器或未来数据。Unix 在同一次 readiness guard 下逐包读写；每次系统调用仍
对应一个独立 IP 包，不使用 `readv/writev` 拼接多个包。Windows 的包适配器在同一队列临界区内
批量交接，保留非阻塞丢当前包与空到非空唤醒语义；Wintun reader 保留逐包边界。

Unix 读缓冲区和公共批次容器复用；非法包只丢该槽位，不丢合法邻包。批次中途发生错误或
取消时保留已经完成的逐包结果，流量只统计有效的已完成前缀，未完成包不得重放已完成
前缀。批次预算和协作调度保证停止与其他任务可推进，不改变 fd 标志、线程策略
或宿主 API；不新增 Apple packetFlow 接入或私有系统调用。

公共 reader 在进入 netstack 前同步分流 UDP，直接非阻塞提交到按源地址拥有的
关联队列；DNS 劫持提交受跟踪的查询任务。普通 UDP 不进入 TCP Driver，也没有
共享 UDP 入站中转队列。TCP/ICMP 使用独立有界 ingress；满时丢当前完整 IP 包并
计数，TCP 可重传，不等待容量而阻塞其他来源的 UDP/DNS。

唯一 writer 公平轮转 TCP/ICMP raw、普通 UDP 响应和 DNS 响应三个独立通道。
UDP 直接在复用的 MTU frame 中构包，不再经过 response writer 和 raw output
的二次交接；每批最多处理 8 个已就绪项目，非法响应也消耗工作预算。DNS permit
保留到对应包被平台接受、最终丢弃或取消，ENOBUFS 待重试时不释放；Windows
WinRT Adapter 成功处理仍不承诺 Windows 框架最终交付。

平台无关的 netstack 驱动同样最多连续消费 8 个已就绪入站包，再执行全量 TCP
socket / 应用缓冲维护及 egress polling。TCP 协议 ingress 仍逐包推进，保证相邻
SYN 的连接归属，不让未推进的 TCP 包误抑制相邻 ICMP；不把 ingress 延迟到凑满批次。
TCP egress 可延后到批次后的维护，不承诺 TCP 与即时 ICMP 响应之间的输出顺序不变。
每次取下一包前检查取消与输出容量，输出满时后缀留在原 raw 入站队列；
不预取额外后缀、不新建积压队列，输入关闭时已消费前缀仍经过维护后退出。
合作调度预算按实际消费包数记账，避免 `try_recv()` 绕过逐包扣账；最多先处理
当前 8 包，再按已消费数量扣账和退让。

Device 仅保留一个尚未消费的 ingress 包，不再保留 RX/TX 双 deque。smoltcp
TxToken 在消费 RX 前预留现有 raw egress 的槽位，生成包后直接提交；未使用的
token 归还容量。满输出保留尚未处理的 TCP 包和协议状态，低优先级 ICMP 仍可
丢当前请求。writer 消费包会显式唤醒 Driver；满输出不以零延迟 timer 忙重试，
输出端关闭则停止 Driver、释放 socket 并唤醒全部等待者。

netstack 的 TCP 接收与发送缓冲可独立配置，各方向的容量包含 smoltcp 与应用
缓冲，两层各占一半。生产 TUN 仍从现有资源策略取得每方向 32 KiB，合计每流
64 KiB 数据缓冲；不扩大默认容量、不新增用户 YAML 参数，也不改变其他协议
的缓冲策略。该容量不包含代理 relay、包队列或 allocator 的内存。

Linux 目前不启用 GRO/GSO：`tun-rs` 的 Linux offload 示例通过 builder 创建并
配置带 VNET header 的设备，而 Vole 的原生和借用路径均不启用该模式。对现有 raw-IP
设备调用 `recv_multiple` 不会自动合并读取或启用 offload。Vole 保留宿主
MTU/格式与 fd 标志，原生 builder 只打开 raw-IP TUN，不暗中启用 offload 或改变借用接口。

## Linux 自建 TUN 的系统网络

`tun.file-descriptor: 0` 的 Linux 路径支持 `auto-route` 和 `auto-detect-interface`，
两者缺省 true。其他平台缺省 false；借用 fd 路径不修改宿主网络，无论这两个字段的值。

- `auto-detect-interface` 从主路由表检测每个地址族的默认物理出口，最多缓存一秒。
  新建 TCP/UDP socket 绑定该接口，所有协议、DNS、资源下载共用 Dialer；没有出口时失败。
  已有 socket 不迁移，下一次建链重新检测。回环目标保持本机访问。
- `auto-route` 独占创建配置命名的 raw-IP TUN，已有同名接口失败。IPv4 使用
  `dns.fake-ip-range` 的原始 IPv4 地址（默认 `198.18.0.1`），前缀固定 /30；启用 IPv6 时使用 `fdfe:dcba:9876::1/126`。
  内部路由表 2022、规则优先级 9000/9001 必须空闲；保留主表的非默认路由，
  本机未标记流量经 TUN，转发流量不在本功能范围。Core socket 使用内部 mark 绕过捕获，
  不依靠 source IP 避免递归。配置接口与路由直接通过内核接口完成，不调用 ip 子进程。
- 自动路由启用，且 `dns.enable: true`、`dns-hijack` 匹配接口 IPv4 下一地址的 53 端口时，
  通过 systemd-resolved 给新接口设置 DNS（默认 `198.18.0.2`）、路由域 `~.` 和 default-route。
  系统须使用 systemd-resolved；调用 `/usr/bin/resolvectl --no-ask-password`，
  每次最多五秒并收回子进程。未启用 DNS 或关闭匹配劫持时保留系统 DNS 行为。
  不覆盖 `/etc/resolv.conf` 或其他接口设置，也不新增 DNS 配置字段。
- 启动失败逆序撤销已应用的操作；正常 Stop 先停止业务，再恢复 DNS、规则与路由，
  最后释放自建接口。清理期间额外持有接口 fd，避免接口索引被提前复用。
  已被外部移除的自有路由视为完成，其他清理错误作为停止错误返回。

安装包负责权限：`packaging/linux/post-install` 为 `/usr/bin/vole` 设置
`CAP_NET_ADMIN`，并把执行权限限制给 `vole` 组。安装器为获授权用户添加组成员关系，
将 `50-vole-resolved.rules` 安装到 `/usr/share/polkit-1/rules.d/`，并依赖 systemd-resolved、
polkit 与提供 setcap 的包。deb postinst / rpm %post 每次更新二进制后执行该脚本。
运行时不弹出提权请求，不使用 sudo，也不把 capability 传给 resolvectl 子进程；
后者使用已安装的 [resolve1 授权](https://github.com/systemd/systemd/blob/main/src/resolve/org.freedesktop.resolve1.policy)。
CLI 的进程启动、后台管理及用户授权仍由调用方负责。

## Windows Wintun

桌面 Wintun 使用宿主提供的动态库与原始 IP 适配器，通过同一 `TunIo` 边界进入
TunRuntime、netstack、DNS、规则和出站图。启用 TUN 的普通 Windows 业务运行时
走这条路径，不要求 MSIX 包身份，也不借用 WinRT Provider 或 packet channel。
实际启动调用见 [Invoke API](invoke-api.md#start)。

宿主提供与程序架构一致的官方 `wintun.dll`。加载路径固定为进程可执行文件所在目录下的
`wintun.dll`；适配器名由 `tun.device` 控制，空值为 `Vole`，启动可打开已有同名适配器或创建新适配器。
Vole 不下载或打包该动态库，不搜索 PATH 或启动工作目录。
系统接口地址、DNS、路由与防递归出口配置由宿主完成；YAML 不提供 DLL 路径或路由字段。
Wintun 使用配置的 MTU，共享原始包校验、IPv6 政策、局部队列预算和同步停止屏障。
UWP 的 1400 MTU 上限只适用于该安装包路径；超过上限明确拒绝，不静默截断。
Windows 不接受 Unix file-descriptor 借用路径。

平台 I/O 使用 `tun-rs` 的可中断 `SyncDevice`。唯一 reader 线程逐包收取 Wintun ring，
非阻塞地提交到既有 `WindowsPacketAdapter` 的 256 包入站队列；队列满只丢当前包。
写端直接提交到 2 MiB Wintun ring，ring 暂满时只保留当前尚未接受的包，异步退让
1 ms 后重试；取消会释放待写包，不创建后台写任务或重放已成功提交的包。
Stop 唤醒阻塞 reader 并等待线程结束，设备所有者随后关闭 Vole 持有的 session 和原生句柄。
这不承诺移除宿主已有的接口，也不卸载系统驱动。

驱动加载、权限、真实接口收发、物理出口与 Stop 后的设备资源释放须在 Windows 上
独立验证；非 Windows 编译和内存回归不能作为 Wintun 设备通过证据。

## Windows WinRT VPN

```text
VpnChannel callback
  -> WindowsPacketAdapter
  -> 有界队列
  -> 同包 packet channel
  -> WindowsTunIo
  -> TunRuntime
```

WinRT VPN 使用 `Windows.Networking.Vpn` 回调，不使用文件描述符或 Wintun ring：

- Provider 在回调内复制 `VpnPacketBuffer` 字节，不保存系统缓冲区的借用；
- 顶层 `ipv6: false` 时，Provider 向 `StartWithMainTransport` 传 null IPv6 client-address 参数，不分配 IPv6 TUN 地址，也不安装 IPv6 路由或 DNS；`startVpn` 的 IPv6 地址字段仍严格必填并经过验证；
- Windows profile 固定覆盖所有应用；Provider 按 policy 设置本地子网旁路，并把最多 64 条规范目标 CIDR 加入 exclusion routes；
- 系统和 Provider 创建的缓冲区都按 WinRT 所有权规则归还；
- 回调不等待管道 I/O，入站和出站队列保持有界；
- 空到非空的回环唤醒只通知 `Decapsulate` 排空响应队列；
- Provider 与完全信任的 Session Host 通过安装包命名空间中的控制管道和数据管道交换原始 IP 包；
- 数据帧为 `u16` 长度加 `1..=1500` 字节数据。写端最多合并 8 个已经就绪的帧，读端使用 64 KiB 缓冲区并逐帧校验；
- EOF、截断、超限、任务异常和进程退出都会停止当前会话。

完整契约见 [Windows VPN 平台边界](windows-vpn.md) 和 [Windows 会话运行时](windows-vpn.md)。

## MTU 与结构上限

`tun.mtu` 缺省或零值为 9000，接受 1280–65535，贯通平台 I/O、netstack 及 UDP 回包预算。
借用 fd 的实际接口 MTU 由宿主预先设置并保持一致，Linux 启动时验证真实值。
UWP 因 `StartWithMainTransport` 平台上限要求配置不超过 1400；packet channel 保留
1500 字节 wire 结构上限，包适配器同时执行更小的配置 MTU。

```text
原始 TUN 包                   配置 MTU（默认 9,000）
最终代理 UDP 负载             配置 MTU - 48（默认 8,952；UWP 1400 时 1,352）
包队列                        256
普通事件 / TCP accept         128
每关联 UDP 入站               64
普通 UDP 响应                 4,096
DNS 响应                      128
```

TCP 会话、普通 UDP 关联、半开连接和出站握手不设固定业务数量上限。结构安全由有界队列、每流缓冲区、解析大小、超时、空闲清理和缓存提供。

每关联入站、普通响应和 DNS 响应是独立内部队列预算，不扩大 TCP accept。
满时只丢当前数据报；容量不构成公开配置或活动业务数量上限。TUN 使用 TCP-only
netstack 端点及纯 UDP codec，独立 crate 的通用 UDP endpoint 不在生产 TUN 路径上。
写回受阻时 reader 仍可处理新请求。停止会取消并等待唯一 writer、reader 所有的
关联/DNS 任务和 netstack，不依赖输出队列腾出容量。

规则/建链在 TCP 握手完成前拒绝连接时，netstack 保留已 abort 的 socket，直到 smoltcp
将 RST 交给现有有界发送队列，再回收逐流状态；不因直接移除 socket 而吞掉关闭报文。
发送队列暂满仍等待原有驱动推进，Stop 可同步释放全部状态，不另建重试任务。

## 物理出口

- Linux：自建接口使用上述自动出口与内部路由隔离；借用 fd 继续由宿主负责命名空间
  或等效路由隔离。仅绑定 source IP 不能作为绕路保证。
- Android：每个出站 TCP/UDP socket 在 connect 前调用宿主 protect；失败则当前连接失败关闭。
- Windows WinRT：Provider 为当前会话选择不可变的物理网络绑定；每个地址族只从非 link-local 地址中选择一个源 IP 和接口索引交给 Session Host，同时独立保留物理适配器全部去重的 on-link prefixes（包括 link-local）用于 VPN 路由。普通出站 socket 必须同时绑定源地址和 WinSock 接口索引。
- Windows WinRT 只有配置中显式使用 `127.0.0.0/8` 范围内的 IPv4 字面量或 `::1` 的本地出站可以跳过物理绑定；物理代理服务器的域名解析到任何回环地址都会失败关闭。
- Windows Wintun：普通出站复用默认 Dialer，不获取 Provider 的物理绑定或网络变化监控。宿主必须配置物理出口和路由隔离，确保 Vole 出站不重新进入 Wintun；Vole 不自动修改地址、DNS 或路由。
- WinRT 物理适配器、选定源地址、全部 on-link prefixes 或网络身份变化后，Provider 等待 2 秒消抖并停止会话，不迁移 socket 或自动回退。

主机测试只能证明帧、所有权、队列和生命周期逻辑；平台实测范围见 [验收矩阵](acceptance.md)。
