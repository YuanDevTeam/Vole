# 测试

核心配置、内存 I/O 和生命周期回归留在本仓库。网络互通与压力测试由
[container-benchmark](https://github.com/YuanDevTeam/container-benchmark) 管理。

## 本地检查

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --locked --all-features --all-targets --no-run
cargo test --locked --no-default-features --features cli --bin vole cli::tests::
cargo test --locked --no-default-features --features cli --lib invoke::foreground::tests::
cargo test --locked --lib config::tests::
cargo test --locked --lib geodata::tests::
cargo test --locked --all-features --lib resource::http::tests::
cargo test --locked --all-features --lib outbound::http::tests::
cargo test --locked --all-features --lib platform::linux_network::tests::
cargo test --locked --all-features --lib connections::tests::
cargo test --locked --all-features --lib routing::diagnostics::tests::
cargo test --locked --all-features --lib managed_udp_connections_
cargo test --locked --all-features --lib routing::balance::tests::
cargo test --locked --all-features --lib load_balance_routes_
cargo test --locked --all-features --lib dialer::connections::tests::
cargo test --locked --all-features --lib fake_ip_
cargo test --locked --all-features --lib sniffing::tests::
cargo test --locked --all-features --lib tcp_sniffer::tests::
cargo test --locked --all-features --lib dns::fallback::tests::
cargo test --locked --all-features --lib dns::runtime::tests::dns_fallback_
cargo test --manifest-path crates/vole-netstack/Cargo.toml --all-targets
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

Windows UWP bridge 的名称准入与匹配使用独立过滤器；下列测试仅处理 JSON、匹配策略
和未注册的内存 `VpnPlugInProfile` 对象，不创建系统 VPN profile 或启动连接：

```sh
cargo test --locked --no-default-features --features ffi,windows-uwp --lib windows::host::tests::
```

构建 UWP DLL 后，可在未打包的 Windows 进程中执行真实 C ABI 的 COM 生命周期回归：

```sh
python scripts/check_windows_com.py --dll dist/windows/arm64/uwp/vole.dll
```

此命令只在原生 Windows ARM64 执行。原生 x64 主机使用本机的 Python 和
`dist/windows/x64/uwp/vole.dll`。宿主、Python 和 DLL 必须同架构；不得通过模拟运行跨架构验证。
该脚本只需 Python 标准库。CI 的各个 Windows job 通过 `actions/setup-python` 安装本架构的
Python，直接运行此检查，仅验证各自构建的产物。
四个独立子进程覆盖未初始化线程连续查询、调用方 MTA 的保留与释放、短线程退出/切换和 STA 拒绝，
同时检查显式初始化计数与 `VoleFree` 响应所有权。测试先用 Win32 确认没有包身份，
仅查询环境/状态并断言包身份错误，不读取 VPN profile、启动连接或访问网络。
父进程为每个用例设置超时。UWP 发布构建在上传归档前执行这些检查；通过不代表包内验收。

在 Windows 上，`windows-uwp` 与 `windows-wintun` 互斥，编译与 Clippy 应明确选择
所测后端而非 `--all-features`。名称选择仍需已安装包验证，不以对象级测试代替。

宿主只执行明确的纯内存过滤器；全目标使用 `--no-run`。
`invoke::tests::` 含监听器用例，不可整体在宿主执行；可执行过滤器以
[Tests workflow](../.github/workflows/test.yml) 为准。
协议独立向量见 [protocols](protocols/README.md)，ClientHello 输入见 [fingerprints](fingerprints/README.md)。

脚本测试保留平台文件输出、Windows 后端选择、Android ABI/runtime、Apple 切片、
真实归档读写，以及 Android JNI 导出与 Apple 日志命名空间的源码契约检查。
外部编译命令由夹具替代，原生编译由 CI 平台矩阵执行；源码检查不替代 JNI 加载或设备验证。
CI 的核心回归分别使用 Debug 和 `ci-release`；后者继承 Release 优化并关闭 LTO，
正式产物使用标准 `release`。Quality 负责格式、Clippy、feature 编译和依赖来源检查。

## 网络与压力

```sh
container-benchmark interop --source vole=/path/to/Vole
container-benchmark stress --source vole=/path/to/Vole
container-benchmark compare --source vole=/path/to/Vole
```

所有服务端遵守 [容器隔离规则](../docs/testing-isolation.md)。用例和测量参数由 benchmark
维护，结果记录在对应运行或 PR 中；[验收边界](../docs/acceptance.md) 区分编译、互通与设备验证。

`runtime::providers::tests::` 使用临时文件与内存流验证候选发布、坏更新保留、旧会话资源和停止清理；`config::` 同时覆盖 provider、规则集合和 MRS 格式。

`routing::proxy_group::tests::` 覆盖自动选择、容差、恢复与选择缓存；`resource::probe::tests::` 和 `invoke::measure_delay::tests::` 使用内存流验证共享健康探测、HTTP 状态和取消。
