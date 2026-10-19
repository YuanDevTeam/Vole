# CLI

`vole` 是前台入口。CLI 解析参数并调用 Invoke；配置读取、初始化、信号与清理由
Invoke 的 `foreground` 操作处理，运行时复用同一个内核。

GNU/Linux 的 TUN 会话在 Core 工作线程启动前，将 glibc 的 arena 默认设为 1，
mmap 阈值设为 32 KiB，降低包处理时的堆保留。显式 `MALLOC_ARENA_MAX`、
`MALLOC_MMAP_THRESHOLD_` 或 `GLIBC_TUNABLES` 环境设置优先。
前台入口和普通业务 `start` 共用该策略，会影响同一进程内的宿主分配器；无 TUN 会话保留宿主策略。
帮助和配置校验保持纯查询行为。

```sh
vole -f /path/to/config.yaml
vole -d /path/to/data -f ./config.yaml
vole -t -f ./config.yaml
cat config.yaml | vole -f -
```

| 参数 | 作用 |
| --- | --- |
| `-d <dir>` | 配置及数据目录，默认用户目录下的 `.config/vole` |
| `-f <file>` | 配置路径；默认 `<data-dir>/config.yaml`，`-f -` 从标准输入读取 |
| `-http-config <file>` | 显式的独立 HTTP 附加配置，交给 Invoke 读取与验证 |
| `-http-ca <file>` | 独立私密 CA JSON 路径，交给 Invoke 读取；`-t` 不读取它 |
| `-t` | 校验配置后退出，不初始化数据、联网或启动 TUN |
| `-v` | 输出内核版本及构建身份 |
| `-h` | 输出帮助 |

语法与 Mihomo 的 Go flag 一致：支持 `-f file`、`-f=file`、`--f=file` 和 `-t=true`；
遇到位置参数或 `--` 停止解析。`-h`/`--help` 立即输出帮助，`-v` 优先于 `-t`。
参数错误返回 2，配置、启动或运行失败返回 1。

`-d` 与 `-f` 独立。与 Mihomo 一致，相对路径从启动工作目录解析并折叠 `.`/`..`；
绝对路径原样交给文件系统，保留符号链接后的 `..` 语义。路径支持空格及平台原生字符。
`VOLE_HOME_DIR`、`VOLE_CONFIG_FILE` 提供环境默认值，显式参数优先。
Unix 用户目录取 `HOME`，Windows 取 `USERPROFILE`，缺失时使用工作目录。
默认 `.config/vole` 不存在或不可访问时，若设置 `XDG_CONFIG_HOME`，使用其中的 `vole` 目录。
配置文件必须是普通文件，文件和标准输入上限均为 8 MiB，CLI 不写回配置。
独立 HTTP 配置上限 1 MiB，使用 `-http-config <file>` 或 `--http-config=<file>`。省略不探测文件；空路径与 `-` 失败，空文件关闭处理。相对 provider 文件从 HTTP 文件目录解析，缓存从数据目录解析。`-t` 只校验主文档／inline 内容，不读取外部 provider、下载或私密 CA；`-v/-h` 不读取附加文件。详细输入见 [HTTP 处理](http-processing.md)。

开启选择性 HTTPS 时，额外传 `-http-ca /private/ca.json`，格式为 `{"certificate":"...PEM...","privateKey":"...PEM..."}`。Unix 文件必须属于当前用户、关闭 group／other 权限（如 0600），且不能是符号链接。私钥不进入共享规则、命令行正文、普通快照或日志；宿主管理证书生成与客户端信任。
客户端 certificate/private-key 可引用 PEM 文件，相对路径从 -d 的数据目录解析；-t 同样读取并校验身份，仍不初始化目录。

正常运行执行 `initialize → createInstance → start(configYaml)`，等待退出后
`stop → destroyInstance`。Unix 支持 SIGINT/SIGTERM，Windows 支持 Ctrl+C/Ctrl+Break；
退出等待内核清理完成。诊断写入有界 stderr，遵循配置的 `log-level`，不包含配置正文或凭据。
具体请求格式见 [Invoke API](invoke-api.md)。

## TUN 与发布

TUN 完全由 YAML 配置。Unix 的 `tun.file-descriptor > 0` 借用宿主 fd，内核只关闭自己的副本；
省略或为 0 时 Linux/macOS 可根据 `tun.device` 创建或打开原生 TUN。
Windows CLI 固定使用 Wintun，DLL 由宿主提供；Windows FFI 编译时可选择 Wintun 或 UWP。
Linux 自建 TUN 的自动路由与 DNS 接管由 Core 执行，CLI 直接把配置交给内核。
其他平台和借用 fd 的接口地址、DNS、系统路由及物理出口隔离仍由宿主管理。
平台接入见 [TUN](tun-platform.md) 和 [Windows VPN](windows-vpn.md)。

构建命令、tag 发布矩阵和归档内容统一见 [编译与发布](../scripts/README.md)。
