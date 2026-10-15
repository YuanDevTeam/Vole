# Vole Invoke API

业务实例通过内联的 `configYaml` 启动，测速通过 `configYamls` 传入节点配置；前台 `foreground` 操作负责从文件或标准输入加载同一配置。每份已加载的 Vole 运行时最多拥有一个公共实例。业务代理入口仅通过 `mixed-port` 配置，HTTP/SOCKS5 TCP 与 SOCKS5 UDP 共用端口；顶层 `port`、`socks-port`、`udp` 和 `listeners` 都会失败。代理组实时选择沿用 Controller。ECH 使用节点内联静态配置或运行时节点 DNS 角色；measureDelay 的动态 ECH 使用原 Dialer 的 system-source 原始 HTTPS 记录叶服务，平台物理来源不可用时失败，不增加 DNS 或宿主元数据入参。

共享请求处理位于 `src/invoke/`。Rust 调用方使用 `vole::invoke::invoke_bytes(&[u8]) -> Vec<u8>`；CLI 和 C ABI 都调用该入口。`invoke` feature 提供共享操作，`cli` 和 `ffi` 分别添加命令行与原生传输适配。

## C ABI

公共接口由 `vole.h` 声明：

```c
char *VoleInvoke(const char *request_json);
void VoleFree(char *response);
```

- 请求必须是以 NUL 结尾的 UTF-8 JSON。
- 非空响应由 Vole 分配，调用方必须使用同一库中的 `VoleFree` 释放。
- 非法输入、未知方法、状态错误和 panic 返回合法失败 JSON；只有灾难性分配失败可以返回 `NULL`。
- 业务运行时线程不能重入 Invoke；Debug 和 Release 构建都立即返回失败 JSON，包括 `version` 等只读请求。
- 请求正文、响应正文、完整配置、UUID、密钥、short ID 和凭据不得写入日志。
- UWP 宿主包含 `vole_windows_uwp.h`（同时引入 `vole.h`），其中声明 `VoleWindowsVpnInvoke`。该头文件和独立的 Windows 安装包桥接接口仅由 `windows-uwp` 构建提供。
- `VoleWindowsVpnInvoke` 接受未显式初始化 COM 或已是 MTA 的调用线程；STA/ASTA 调用失败且不改变其 apartment。库配对管理每次调用的初始化，并为静态 WinRT factory 缓存保留一份进程寿命的 MTA 引用；宿主无需额外持有 MTA，短生命周期工作线程可串行重复调用。返回后未显式初始化的线程可能处于 implicit MTA，不遗留逐次显式初始化计数；完整边界见 [COM / WinRT 生命周期](windows-vpn.md#com--winrt-生命周期)。

## 请求与响应

请求：

```json
{
  "method": "getState",
  "instanceId": "1",
  "payload": {}
}
```

成功响应：

```json
{"success":true,"data":{},"error":""}
```

失败响应：

```json
{"success":false,"data":null,"error":"invalid configuration"}
```

约束：

- 请求 envelope 只接受 `method`、`instanceId` 和 `payload`。
- `method` 必须来自本文列出的白名单。
- `payload` 必须是对象；无参数时传 `{}`。
- 运行时级方法必须省略 `instanceId`；实例级方法必须携带 Vole 返回的非空 ID。
- 未知或已移除的 envelope 字段和 payload 字段都会失败，不静默忽略。
- 无业务数据的方法成功时返回空对象，不返回 `null`。
- Invoke envelope 上限为 240 MiB + 64 KiB（五份 YAML 的 JSON 最坏转义及 envelope），单份 YAML 最大 8 MiB。

## 初始化与生命周期

宿主管理业务实例时，先调用：

```json
{
  "method": "initialize",
  "payload": {"dataDir": "/absolute/path"}
}
```

`dataDir` 必须是可写绝对路径。Vole 固定使用：

```text
<dataDir>/configs   # 宿主可选持久化目录，不是 Invoke 输入
<dataDir>/geodata   # Vole 管理的 GeoData 目录
```

同一路径重复初始化幂等，切换路径失败。`version`、`validateConfig` 和前台帮助不要求初始化；`foreground` 的运行模式自行初始化并管理实例。

公共实例状态：

```text
stopped -> preparing -> prepared -> starting -> running
   ^                                      |
   +------------- stopping <-------------+

关键数据面提前退出 -> failed
```

- `instanceId` 是当前运行时内不可复用的代次令牌，不代表支持并行公共实例。
- 同一实例一次只执行一个生命周期命令，重叠命令立即失败。
- `validateConfig` 是可并发的纯校验方法，不要求或执行 `initialize`。
- `measureDelay` 使用独立批次和私有工作器，不进入公共实例表。
- 公开生命周期为 `initialize -> createInstance -> start(configYaml) -> stop -> destroyInstance`。`preparing`、`prepared` 和 `starting` 是 `start` 内部阶段，没有公共 `prepare` 方法。
- 不支持配置整体热重载；切换配置需要 `stop -> start(新 configYaml)`。运行期间可更新 providers、自动选择健康成员或通过 Controller 切组；这些操作不修改启动 YAML，既有连接保留原资源和路径。
- `stop` 在 stopped 状态幂等；`destroyInstance` 是最终同步清理屏障。

## 方法

### `version`

运行时级方法：

```json
{"method":"version","payload":{}}
```

返回：

```json
{
  "buildIdentity": "Vole;engine=rust;coreVersion=0.1.0",
  "engine": "rust",
  "version": "0.1.0"
}
```

`version` 和 `buildIdentity` 中的 `coreVersion` 取自 Cargo package version。源码 commit、lockfile 和产物 hash 由发布系统记录。

### `initialize`

参数和幂等语义见“初始化与生命周期”。成功时返回规范化后的 `dataDir`。

### `updateDnsNetwork`

初始化后的运行时级方法，不带 `instanceId`。宿主提供完整、只读的物理网络 DNS 快照；不改变 `start(configYaml)`，不配置接口、路由、DNS 或 App 生命周期。

```json
{
  "method": "updateDnsNetwork",
  "payload": {
    "generation": 1,
    "system": [
      {"address": "192.0.2.53", "interface": "en0", "scopeId": 0, "requiresEncryption": false}
    ],
    "dhcp": [
      {"interface": "en0", "servers": [{"address": "192.0.2.54", "scopeId": 0}], "requiresEncryption": false}
    ]
  }
}
```

`generation` 必须是正整数并单调增加；相同代次的相同内容幂等，不同内容或较旧代次失败。system/dhcp 必填，空数组撤销来源；一个 DHCP 接口只能出现一次。所有层级拒绝未知字段，metadata 原始 JSON（含内部空白）及规范化快照各限 64 KiB；在完整 JSON Value 解析前通过借用 RawValue 准入，额外 envelope 字节（含外部空白）独立限 64 KiB。这与其他方法沿用的全 envelope 上限不同。地址只接受非回环的单播字面 IP；IPv6 link-local 必须提供匹配物理接口的非零 scopeId，IPv4 scopeId 必须为 0。interface 是 1–256 字节的精确名称或 UWP 的绑定 GUID，不允许控制字符、路径分隔符或首尾空白。scopeId 默认 0，requiresEncryption 默认 false，宿主必须如实标记加密要求，不能将无法确认的数据描述为明文来源。

成功返回 `{}`。快照在同一运行时内共享，优先于 OS 发现，并与全部仍活跃资源代次的 DNS cache/hints 清理共用 epoch 屏障；旧查询不能回填，fake-IP 和活跃流保留。Windows 前台进程和 Session Host 的 runtime registry 各自独立，本方法不提供 IPC。平台可用性和物理绑定见 [DNS 来源](tun-icmp-dns.md#显式系统与-dhcp-来源)。

### `getGeoDataState`

运行时级只读方法，要求已经初始化：

```json
{"method":"getGeoDataState","payload":{}}
```

返回 `geosite`、`geoip` 和 `asn` 三项；三种资产分别报告需求与可用性：

```json
{
  "geosite": {
    "required": true,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  },
  "geoip": {
    "required": false,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  },
  "asn": {
    "required": false,
    "available": false,
    "updating": false,
    "lastSuccess": null,
    "nextCheck": null,
    "lastError": null,
    "etag": null,
    "hash": null
  }
}
```

`asn` 使用相同的 `required`、`available`、`updating`、`lastSuccess`、`nextCheck`、
`lastError`、`etag` 和 `hash` 字段。
时间使用 Unix 秒，hash 为小写 SHA-256。调用不会创建实例、联网或改变更新调度。

### `createInstance`

```json
{"method":"createInstance","payload":{}}
```

返回：

```json
{"instanceId":"1"}
```

该方法只创建 stopped 状态记录。实例销毁前再次创建失败。

### `destroyInstance`

实例级方法：

```json
{"method":"destroyInstance","instanceId":"1","payload":{}}
```

实例仍处于 prepared、running 或 failed 时，先执行与 `stop` 等价的清理。取得命令锁后，无论清理成功、失败或 panic，ID 都会永久失效；只有因 busy 在取得命令锁前被拒绝时，实例才保留。

### `validateConfig`

运行时级方法：

```json
{
  "method": "validateConfig",
  "payload": {"configYaml": "proxies:\n  - name: edge\n    ...\n"}
}
```

无需 `initialize`，完成大小、YAML、结构、共享 route-target 命名空间、引用和字段组合校验。节点的 `dialer-proxy` 可指定 DIRECT 或引用节点、组；全部上游和组成员边（包括未选成员）统一做无环校验。不创建实例、不解析远端域名、不联网，也不读取 GeoData。资产缺失不影响纯配置校验。显式引用的客户端证书与密钥文件在校验时读取；相对路径使用已初始化的 dataDir，未初始化时使用当前工作目录。

### `start`

实例级方法，只允许 stopped 状态。唯一 payload 字段是内联配置：

```json
{
  "method": "start",
  "instanceId": "1",
  "payload": {"configYaml": "tun:\n  enable: true\n  mtu: 1500\n  file-descriptor: 23\nproxies:\n  ...\n"}
}
```

`prepare` 方法、`tunFd` 与 `tunFraming` payload 已删除，提交这些旧输入会失败。
TUN 资源参数来自 YAML 的 `tun`，平台包格式由内核选择。

同一命令内先准备配置，再获取平台资源并启动：

- 读取当时可用的本地 GeoData，不启动或等待下载。
- 准备阶段只构建并校验代理图；实际建立物理首跳时，通过运行时节点 resolver 解析服务器及独立 VLESS 下载端点。未选中的备用节点不会因 DNS 故障阻塞启动。仅经代理访问的域名交给下一跳；系统解析仅用于 DNS 关闭的配置。
- 按当前资源构建代理组。`profile.store-selected` 开启时优先恢复仍有效的缓存选择，否则使用有效的 `default-selected` 或首成员；动态空组使用 `empty-fallback`。自动组随后依据健康探测选择成员。
- 含 TUN 的配置从内部 preparing 阶段起持有运行时本地的 TUN/protect 租约，直到停止或销毁。Android 必须在 `start` 前注册 protect controller。
- 所有监听器和关键数据面成功后才进入 running。准备、资源获取或启动失败均清理本次临时资源并回到 stopped；重试需要再次提交完整 `configYaml`。
- GeoData 更新只在启动后按需后台运行，不属于启动关键路径。

`tun.file-descriptor > 0` 时，Unix 宿主借用已经 nonblocking 的 TUN fd。
Vole 校验后建立带 `CLOEXEC` 的副本，只关闭副本，不更改原始 fd 的所有权或标志。
Apple 使用 utun 包头，Android 与 Linux 使用 raw-IP。Linux 要求真实单队列 TUN、关闭
PI/VNET header，并验证实际 MTU 与 `tun.mtu` 相同；跨网络命名空间的校验需要宿主提供权限。

`tun.file-descriptor` 省略或为 0 时，Linux 与 macOS 根据 `tun.device` 创建或打开原生
TUN；移动平台仍需要宿主描述符。Linux 自建 TUN 支持 `auto-route`、
`auto-detect-interface` 与 systemd-resolved 接管；其他平台和借用 fd 的系统网络由宿主配置。
`tun.mtu` 省略或为 0 使用 9000；字段契约及借用 fd 边界见
[配置参考](config.yaml)与 [TUN 平台层](tun-platform.md)。

Windows 编译时选择互斥的 `windows-wintun` 或 `windows-uwp`：

- Wintun 构建中，业务 `start(configYaml)` 在 `tun.enable: true` 时自动打开或创建
  Wintun。设备名取 `tun.device`，空值使用 `Vole`；MTU 使用 `tun.mtu`。仅加载进程
  可执行文件所在目录的外置 `wintun.dll`，宿主提供匹配架构的官方 DLL，并负责系统网络
  配置与物理出口防环。该入口不要求包身份，且不下载或打包 DLL。
- UWP 构建的系统 VPN 通过独立安装包桥接与 Session Host 启动，保留物理绑定和网络监控。
  其配置 MTU 必须在 1280–1400 范围内；默认 9000 不适用，需要显式配置。普通业务
  `start` 不替代 Provider 的 packet channel。两种构建都不接受 Windows 文件描述符。

Stop 关闭本次持有的 fd、session 和原生句柄；Wintun 不承诺移除宿主已有的同名接口
或卸载驱动。平台启动失败不切换另一种 Windows 后端。

### `foreground`

运行时级前台操作，省略 `instanceId`：

```json
{
  "method": "foreground",
  "payload": {
    "action": "run",
    "dataDir": "./state",
    "configPath": "./config.yaml"
  }
}
```

`action` 必填，只接受 `run`、`validate` 或 `help`；`dataDir`、`configPath` 为可选
路径元数据，不是 YAML 内容。成功数据为 `{"output":"...","diagnostics":"..."}`：

| action | 行为 | 成功输出 |
| --- | --- | --- |
| `help` | 返回静态帮助，不读取环境、工作目录、文件或标准输入。 | `output` 为空，`diagnostics` 为帮助文本。 |
| `validate` | 有界读取配置后执行纯配置校验，不初始化数据目录、创建实例、解析远端或检查 TUN 设备。 | `output` 为 `configuration valid\n`，`diagnostics` 为空。 |
| `run` | 初始化数据目录，创建一个公共实例，执行同一内部 `start(configYaml)`，等待退出并停止、销毁实例。 | 停止与清理成功后两项均为空。 |

省略路径时，分别使用 `VOLE_HOME_DIR` 和 `VOLE_CONFIG_FILE`；显式空字符串绕过
对应环境值并恢复默认。默认数据目录为 Unix `HOME` / Windows `USERPROFILE` 下的
`.config/vole`，用户目录缺失时从启动工作目录计算。该默认目录元数据读取失败时，
若定义 `XDG_CONFIG_HOME`，使用 `<XDG_CONFIG_HOME>/vole`。相对数据目录和显式
配置路径分别从启动工作目录解析并折叠 `.`/`..`，绝对路径原样保留；
配置默认 `<dataDir>/config.yaml`。
`configPath: "-"` 从标准输入读取。文件必须是普通文件，文件和标准输入均最多 8 MiB；
证书/密钥相对路径从选定 dataDir 解析，validate 也读取身份文件但不初始化目录。
不会下载、创建模板或改写配置。详细命令行映射见 [CLI](cli.md)。

普通 Unicode 路径使用 JSON 字符串。需要保留平台原生编码时，Unix 可使用
`{"unixBytes":[47,116,109,112,255]}`，Windows 可使用
`{"windowsWide":[67,58,92,55360]}`。对象只接受对应平台的一个字段，整数元素分别为
字节或 UTF-16 code unit；不会通过有损字符串转换。编码保留不替代文件系统对路径的合法性检查。

`run` 同步占用当前调用直到会话结束；同一运行时只允许一个前台运行操作。它消费进程的
标准输入和退出信号，并安装有界 stderr 诊断，适用于前台进程宿主。嵌入式、服务或 VPN
宿主继续用普通业务生命周期方法和自身的退出机制。
解析后的配置直接交给同一启动路径，不重复读取或解析。
CLI 与普通 `start` 共用统一的 TUN allocator 策略、内存诊断和 Stop 后回收；
无 TUN 的会话不修改 allocator。
GNU/Linux 的设置是进程级、一次性的，显式 allocator 环境覆盖仍优先，
完整语义见[运行时资源策略](runtime-resource-policy.md#统一内存策略)。
Unix 等待 SIGINT/SIGTERM，Windows 等待 Ctrl+C/Ctrl+Break；标准输入先读取，之后在
内部准备和启动前注册信号。启动中收到信号仍等待启动工作器结束，再停止和销毁；运行期
通过引擎完成通知等待结束，随后 join 确认结果，不持有命令锁等待信号。启动、关键数据面、
信号或清理失败返回失败响应，错误保留有界摘要；操作返回前完成本次清理。

### `stop`

```json
{"method":"stop","instanceId":"1","payload":{}}
```

同步取消并等待监听器、Controller、TUN、netstack、DNS、会话、出站和更新任务，关闭 Vole 持有的文件描述符副本并释放平台回调租约；Wintun 还唤醒并等待 reader 线程退出、释放设备资源。返回后不得继续产生数据包或调用 protect callback；本次 session 的代理组选择随之销毁。

### `getState`

```json
{"method":"getState","instanceId":"1","payload":{}}
```

返回：

```json
{"state":"running","lastError":""}
```

异步数据面失败时状态为 `failed`，`lastError` 只包含有界且脱敏的摘要。

### `measureDelay`

运行时级方法：

```json
{
  "method": "measureDelay",
  "payload": {
    "configYamls": ["proxies:\n  - name: edge\n    ...\n"],
    "timeout": 5,
    "url": "https://cp.cloudflare.com/"
  }
}
```

返回顺序与输入一致：

```json
{
  "results": [
    {"success":true,"delay":123,"error":""},
    {"success":false,"error":"measureDelay probe failed"}
  ]
}
```

- `configYamls` 接受 1–5 份非空节点配置，`timeout` 为 1–30 秒。
- 同一运行时一次只允许一个测速批次，最多并发五个私有工作器。
- 节点配置顶层只允许 `proxies` 和客户端信任 `tls.custom-certifactes`，不接受服务端 TLS 字段或 `proxy-groups`；`dialer-proxy` 可指定 DIRECT 或引用具体节点。Vole 推导唯一链头，且该链必须覆盖全部节点。
- 工作器只准备出站图并执行 TCP、可选 TLS 和 HTTP/1.1 HEAD；不创建公共实例、监听器、TUN、DNS、规则、嗅探器或 GeoData。
- 宿主测量组成员时，按当前选择快照展开具体链后提交；上游选到 DIRECT 时移除相应 `dialer-proxy`，选到 REJECT 时不发起该项测量。该快照不改变运行中的组选择。
- URL 必须是无 userinfo 和 fragment 的绝对 HTTP/HTTPS URL；HTTPS 与本次节点握手共享内置、可读系统及配置自定义信任根；各测量工作器的信任互相隔离。
- 任意合法 HTTP 状态都表示探测成功；不跟随重定向、不读取正文。
- 单项失败不取消其他项；方法返回前释放全部私有任务。

## Android protect

Android JNI 类固定为 `io.github.yuandevteam.vole.NativeVole`，与宿主应用的包名独立。
宿主提供如下 Java 声明（或等价的 Kotlin/JVM 声明），并打包匹配 ABI 的原生库：

```java
package io.github.yuandevteam.vole;

public final class NativeVole {
    static {
        System.loadLibrary("vole");
    }

    private NativeVole() {}

    public static native byte[] nativeInvoke(byte[] request);
    public static native boolean nativeRegisterProtectController(Object controller);
    public static native boolean nativeUnregisterProtectController();
}
```

仅导出该命名空间下的三个 JNI 方法，不提供其它包名别名。宿主声明必须与原生库一致；
代码压缩和混淆必须保留该类、这些 native 方法以及 controller 的 `boolean protect(int)`
方法名。`nativeInvoke` 的请求与响应均为标准 UTF-8 JSON `byte[]`，由 JVM 管理，
不使用 C ABI 的 `VoleFree` 释放。

Android TUN 通过 Invoke 之外的运行时本地回调注册：

```text
ProtectFd(fd) -> bool
```

- 含 TUN 的实例必须在 `start` 前注册；非 TUN 和 `measureDelay` 不需要。
- 每个出站 TCP/UDP socket 在 connect 前同步调用 protect。
- socket 初始化和 protect 可以在受跟踪的 Tokio 阻塞线程执行；不保证回调来自某个
  固定业务线程。取消不能中断已经开始的同步回调，Stop 返回前必须等待其完成。
- TCP/UDP 共用每初始化作用域 4 个未完成提交的内部许可；提交前异步等待并继承
  调用方取消/期限，不因繁忙拒绝业务连接。许可直到阻塞任务实际结束才释放。
- 返回 false、抛出异常或 controller 失效都会使当前连接失败关闭。
- 回调必须快速、同步、非阻塞，且不能重入 Invoke 或注册接口。
- TUN 租约存活期间不能替换或注销 controller；`stop`/`destroyInstance` 是释放屏障。
- Android binding 使用 UTF-8 `byte[]`，不依赖 Modified UTF-8。

## Controller

配置 `external-controller` 后，运行时可提供 HTTP `GET /traffic`、`GET /group`、`GET /group/{name}`、`GET /proxies/{name}` 和 `PUT /proxies/{name}`。代理组 Controller 可以在非 TUN 的 `mixed-port` 配置中运行；此时 `/traffic` 不存在。`secret` 省略或空串时免认证；非空时保护全部路由，监听地址由配置决定。

静态成员来自配置，动态成员随 provider 成功更新；显式选择按 `profile.store-selected` 保存。成功切换只影响之后新建的物理 TCP、UDP 和 DNS transport，不迁移既有连接、UDP association、DNS 状态或 TCP pool。自动组根据健康状态处理后续连接的选择与恢复；select 的连接失败按原样返回。已认证 Hysteria2 会话的后续逻辑流和跳端口 socket 保留初始上游选择；新的认证会话才读取新选择。Controller 查询不携带 `instanceId`，不进入 Invoke 命令锁；完整语义见 [Controller API](controller-api.md)。

## Windows 安装包桥接

`VoleWindowsVpnInvoke` 使用独立的桥接修订版 3：

```json
{"bridgeVersion":3,"method":"getVpnStatus","payload":{}}
```

只接受六个方法：

- `getEnvironment`
- `getVpnStatus`
- `startVpn`
- `stopVpn`
- `getStartupTaskStatus`
- `setStartupTaskEnabled`

### VPN profile 名称

`startVpn`、`getVpnStatus` 和 `stopVpn` 的 payload 都接受可选的 `profileName`。
省略时使用 `Vole`；使用自定义名称的宿主必须在这三个方法中始终传入同一个值，包括
前台重启后的查询。名称不属于业务 YAML、Session Snapshot 或 profile custom configuration，
不改变 Session token 的计算。

```json
{"bridgeVersion":3,"method":"getVpnStatus","payload":{"profileName":"Example VPN"}}
```

- 名称必须是 1–256 UTF-8 字节的字符串，不能有首尾 Unicode 空白或控制字符（含 NUL）。
  `null`、空串和其它 JSON 类型都拒绝，不 trim、不补默认值；其它系统名称限制仍由 Windows 返回错误。
- 仅匹配当前 package family 内同名的 VPN profile，区分大小写且不做 Unicode normalization。
  其它 package 的 profile 不会被接管或修改；Windows 名称冲突不会触发删除、重命名或回退。
- 同包存在其它名称的活动 profile 时，三个方法均失败，而不是报告已断开或操作那个 profile；
  多个同名匹配同样失败。同包不同名且已断开的 profile 不参与本次操作。
- 宿主应使用稳定名称。这不是多 profile 管理接口，不支持多会话并行、自动迁移、重命名或删除。
  更换名称前必须用旧名称显式 `stopVpn` 并确认断开；使用新名称启动不会复用或删除旧名称的 profile。
  名称选择不会转换旧 Session token 或解除现有 profile 配置校验。
- `getEnvironment`、`getStartupTaskStatus` 和 `setStartupTaskEnabled` 不接受 `profileName`。
  StartupTask ID 仍固定为 `VoleStartup`，与 VPN profile 名称无关。

### 启动 payload

`startVpn` 的 payload 为：

```json
{
  "profileName": "Example VPN",
  "configYaml": "tun:\n  enable: true\n  mtu: 1400\n...",
  "networkSettings": {
    "ipv4Address": "192.168.3.1",
    "ipv6Address": "fd00::2",
    "dnsIpv4Address": "8.8.8.8",
    "dnsIpv6Address": "2001:4860:4860::8888"
  },
  "policy": {
    "alwaysOn": false,
    "allowLocalNetwork": true,
    "excludedCidrs": []
  },
  "sessionBackend": {
    "processes": [
      {
        "executableRelativePath": "bin\\proxy-core.exe",
        "arguments": ["run", "--mode", "vpn"]
      }
    ]
  }
}
```

`policy` 始终必填。Windows VPN 固定覆盖所有应用；`alwaysOn` 控制 profile capability，实际自动连接仍取决于 Windows 用户设置和 active profile；`allowLocalNetwork` 控制本地子网是否绕过；`excludedCidrs` 是最多 64 个规范 IPv4/IPv6 目标网段。拒绝重复项、host bits、`/0`、禁用 IPv6 时的 IPv6 项，以及包含当前 VPN DNS 地址的项。

`sessionBackend` 可以省略。存在时包含 `1..=8` 个有序关键进程；每项只有 package installed location 内的规范 `.exe` 相对路径和有界 argv 数组。同一可执行文件可出现多次。第一版不接受 port、UDP、readiness、restart、environment、working directory 或 raw command line；任一进程退出都会使当前 VPN 会话失败关闭。

桥接把 YAML、进程顺序、路径和参数发布为 `vole-session-v2:<sha256>` Session Snapshot。参数引用的文件由调用方保持存在且不可变，Vole 不读取或摘要其内容。`getVpnStatus.data.snapshotToken` 返回该完整 Session token。

桥接请求最大 1 MiB。它负责安装包身份、按名称选择的 VPN profile、不可变 Session Snapshot、连接/断开命令和系统 VPN 状态；Provider 负责激活 Session Host。桥接不公开 profile CRUD、内部文件路径、backend 描述、参数、PID、管道名称或 Snapshot 维护。数据包、Controller 流量查询、代理组查询/切换和业务生命周期不经过该 JSON 桥接。

## 编码与安全边界

- 所有 JSON DTO 拒绝未知字段。
- 配置、错误和日志按 UTF-8 字节计数并受固定上限约束。
- TUN 原始数据包按 `tun.mtu` 限制；最终代理 UDP 响应最多为该 MTU 减去 48 字节。默认 9000 对应 8952 字节；显式 1500 对应 1452 字节，Windows UWP 的最高 1400 对应 1352 字节。
- 嵌套 UDP 协议可以增加有界帧头，但解封装后的最终负载仍受该平台响应上限限制。
- 节点和代理组定义名共享大小写敏感的严格 UTF-8 命名空间；内置动作名称保留，具体名称与编码规则见 [Controller](controller-api.md#名称与路径)。
- Secret、password、UUID、REALITY key、short ID、目标地址和完整配置不得进入日志。
- Apple Unified Logging 的 subsystem 固定为 `io.github.yuandevteam.vole`，category 为
  `vole`，不继承宿主应用的 bundle identifier；Console 或 `log stream` 应按该标识筛选。
