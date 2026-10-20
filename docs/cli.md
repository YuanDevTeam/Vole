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
vole -t -config "$(base64 < config.yaml)"
```

| 参数 | 作用 |
| --- | --- |
| `-d <dir>` | 配置及数据目录，默认用户目录下的 `.config/vole` |
| `-f <file>` | 配置路径；默认 `<data-dir>/config.yaml`，`-f -` 从标准输入读取 |
| `-config <base64>` | 标准 Base64 编码的主配置，非空时优先于 `-f` |
| `-age-secret-key <key>` | 解密 AGE armor 主配置的身份，可含多行身份 |
| `-ext-ctl <address>` | 非空时覆盖 HTTP Controller 地址 |
| `-ext-ctl-tls <address>` | 非空时覆盖 TLS Controller 地址 |
| `-ext-ctl-unix <path>` | 非空时覆盖 Linux 本地 Controller 路径 |
| `-secret <token>` | 非空时覆盖 Controller 认证密钥 |
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
`VOLE_HOME_DIR`、`VOLE_CONFIG_FILE`、`VOLE_CONFIG_STRING` 和 `VOLE_AGE_SECRET_KEY`
提供环境默认值，分别对应 `-d/-f/-config/-age-secret-key`；显式参数优先，显式空值清除相应环境默认。
非空 Base64 主配置优先，其次是配置路径 `-` 明确选择的标准输入，最后为配置文件；不会探测标准输入。
`VOLE_CONFIG_FILE=-` 同样明确选择标准输入。Base64 使用带 padding 的标准字母表，允许 CR/LF，
不接受 URL-safe 字母表；编码文本最多 11,184,812 字节，解码后最多 8 MiB。
解码后的输入和文件／标准输入均可为标准 AGE armor，复用 provider 的 X25519／hybrid 身份与认证解密；
身份文本最多 16 KiB，解密后的 YAML 最多 8 MiB。编码、密文、明文按阶段释放，不在运行会话中保留编码副本；
临时身份与请求缓冲清零，错误不包含正文或密钥。帮助和版本不读取这些环境值或配置来源。
Unix 用户目录取 `HOME`，Windows 取 `USERPROFILE`，缺失时使用工作目录。
默认 `.config/vole` 不存在或不可访问时，若设置 `XDG_CONFIG_HOME`，使用其中的 `vole` 目录。
配置文件必须是普通文件，文件和标准输入上限均为 8 MiB，CLI 不写回配置。
正常运行时，`VOLE_OVERRIDE_EXTERNAL_CONTROLLER`、`VOLE_OVERRIDE_EXTERNAL_CONTROLLER_TLS`、
`VOLE_OVERRIDE_EXTERNAL_CONTROLLER_UNIX`、`VOLE_OVERRIDE_SECRET` 提供 Controller 覆盖的环境默认。显式参数优先，显式空值清除该环境默认，
且不覆盖 YAML 原值；只更改具体的 Controller 配置，不提供通用字段覆盖。
地址沿用 YAML 的 IP／localhost／空 host 与数字端口规则，不查询域名；密钥不会输出到日志或错误。
`-t` 与 Mihomo 一致，只校验输入配置，不应用或解析这些运行期覆盖；`-h/-v` 不读取其环境值。

独立 HTTP 配置上限 1 MiB，使用 `-http-config <file>` 或 `--http-config=<file>`。省略不探测文件；空路径与 `-` 失败，空文件关闭处理。相对 provider 文件从 HTTP 文件目录解析，缓存从数据目录解析。`-t` 只校验主文档／inline 内容，不读取外部 provider、下载或私密 CA；`-v/-h` 不读取附加文件。详细输入见 [HTTP 处理](http-processing.md)。

开启选择性 HTTPS 时，额外传 `-http-ca /private/ca.json`，格式为 `{"certificate":"...PEM...","privateKey":"...PEM..."}`。Unix 文件必须属于当前用户、关闭 group／other 权限（如 0600），且不能是符号链接。私钥不进入共享规则、命令行正文、普通快照或日志；宿主管理证书生成与客户端信任。
客户端 certificate/private-key 可引用 PEM 文件，相对路径从 -d 的数据目录解析；-t 同样读取并校验身份，仍不初始化目录。

`VOLE_SAFE_PATHS` 可为主配置的 file provider 读取和 HTTP provider 缓存增加授权目录。
使用系统路径列表分隔符（Unix 为 `:`、Windows 为 `;`），保留原生路径编码；相对目录从启动工作目录解析，
空项不授权当前目录。授权目录必须已经存在，初始化后固定，并由 provider 候选与恢复快照继承。
文件读取不创建目录；只有 HTTP provider 缓存可在授权根内新建目录及写入正文／sidecar。
路径中的 `..`、祖先或目标符号链接逃逸被拒绝。默认仍限 dataDir；file provider 在额外目录内不会回写 bundle 回退。
本次主配置／独立 HTTP 文件保留为不可被缓存覆盖的输入，显式私密 CA 路径不授予 provider 读写。
该环境只进入 provider 资源上下文，不改变主配置、客户端身份／私密 CA、独立 HTTP 设置或 Controller socket 的文件合同；
不修改全进程环境，也不提供任意目录写入授权。`-t/-h/-v` 不读取此环境值。

正常运行执行 `initialize → createInstance → start(configYaml)`，等待退出后
`stop → destroyInstance`。Unix 支持 SIGINT/SIGTERM，Windows 支持 Ctrl+C/Ctrl+Break；
退出等待内核清理完成。诊断写入有界 stderr，遵循配置的 `log-level`，不包含配置正文或凭据。
Unix 的 SIGHUP 通过同一候选工作器重载主配置：文件源重读该文件，Base64／标准输入源复用首次
解密后的有效 YAML，不重读标准输入、环境默认、独立 HTTP 文件或私密 CA。文件 AGE 保留已解析身份，
不保留原始密钥文本。Controller 覆盖继续应用于候选；规则、节点与普通 provider 候选沿原热更新流程。
坏候选、繁忙或超时保留当前会话；启动资源变化报告 reconnect required，SIGHUP 不自动停止或重连，
需宿主协调或重启前台进程。活动 HTTP payload／CA 继续固定，HTTP provider 待应用内容不会由 SIGHUP 应用。
退出或引擎停止会取消并等待已开始的重载工作；宿主原 TUN fd 不被替换或关闭。
具体请求格式见 [Invoke API](invoke-api.md)。

## TUN 与发布

TUN 完全由 YAML 配置。Unix 的 `tun.file-descriptor > 0` 借用宿主 fd，内核只关闭自己的副本；
省略或为 0 时 Linux/macOS 可根据 `tun.device` 创建或打开原生 TUN。
Windows CLI 固定使用 Wintun，DLL 由宿主提供；Windows FFI 编译时可选择 Wintun 或 UWP。
Linux 自建 TUN 的自动路由与 DNS 接管由 Core 执行，CLI 直接把配置交给内核。
其他平台和借用 fd 的接口地址、DNS、系统路由及物理出口隔离仍由宿主管理。
平台接入见 [TUN](tun-platform.md) 和 [Windows VPN](windows-vpn.md)。

构建命令、tag 发布矩阵和归档内容统一见 [编译与发布](../scripts/README.md)。
