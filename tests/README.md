# 测试

Core 在宿主机运行明确选定的配置、编解码、内存 I/O 和所有权回归。协议互通与压力由独立的 benchmark 工程运行，执行环境和证据范围见[验收边界](../docs/acceptance.md)。

## 本地检查

按[编译文档](../scripts/README.md)准备原生依赖。Linux 与 macOS 的全目标检查以编译为限：

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --locked --all-features --all-targets --no-run
cargo test --locked --manifest-path crates/vole-netstack/Cargo.toml --all-targets
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

Windows 编译和测试显式选择 UWP 或 Wintun。CI 的测试范围及构建 profile 由 [Tests workflow](../.github/workflows/test.yml)维护。含真实监听器的整组测试在隔离环境执行。

## 定向回归

按改动选择以下命令。Cargo 过滤器匹配测试名称，核对结果中实际执行的用例数。各组使用合成输入、内存传输或本机临时文件。

### 配置、规则和生命周期

```sh
cargo test --locked --features cli,interop-test --lib config::tests::
cargo test --locked --lib geodata::tests::
cargo test --locked --features cli --lib routing::proxy_group::tests::
cargo test --locked --features cli --lib dns::runtime::tests::stale_refresh_
cargo test --locked --features cli --lib runtime::providers::apply::http_tests::
cargo test --locked --features cli --lib resource::http_control::tests::
cargo test --locked --features cli --lib invoke::foreground::tests::
cargo test --locked --features cli --lib invoke::tests::envelope_and_payload_are_strict -- --exact
cargo test --locked --features cli --bin vole cli::tests::
```

覆盖配置准入、GeoData、选择与缓存、HTTP 在线候选、资源回收和 Invoke 边界。全量 `invoke::tests::` 含监听用例，宿主执行应使用明确的过滤器。集成范围见[配置与资源](../docs/http-processing.md#配置与资源)及 [Invoke API](../docs/invoke-api.md)。

### 协议与传输

```sh
cargo test --locked --features cli,interop-test --test tuic_memory
cargo test --locked --features cli,interop-test --test grpc_pool --test grpc_protocol_pool
cargo test --locked --features cli,interop-test --test sing_mux
cargo test --locked --features cli,interop-test --test shadowsocks_backpressure --test shadowsocks_uot
cargo test --locked --features cli,interop-test --lib outbound::vless::encryption::records::tests::
cargo test --locked --features cli,interop-test --lib transport::quiche_h3::tests::
cargo test --locked --features cli,interop-test --lib transport::h2_write::tests::
cargo test --locked --features cli,interop-test --lib transport::smux::tests::
cargo test --locked -p vole-blake3-raw --test derive
```

内存对端可验证实际编解码、信用和背压、取消、半关闭与 owner 退出。各协议在真实 TUN 的数据路径、配置组合和容量由 benchmark 分别验证。平台及协议功能见 [出站契约](../docs/outbounds.md)。

### TUN 与内存

```sh
cargo test --locked --features cli --lib tun_runtime::tests::
cargo test --locked --features cli --lib platform::tun_rs_io::tests::
cargo test --locked --manifest-path crates/vole-netstack/Cargo.toml mapped_rx_
```

前两项在 Unix 验证内存 Dispatcher 或 socketpair 的包边界、描述符所有权与取消。接收映射回归检查容量、缓存和 Stop。真实 TUN fd、设备路径和 `phys_footprint` 使用对应平台的实际证据。[TUN 平台层](../docs/tun-platform.md)

## HTTP 处理与 Invoke

```sh
cargo test --locked --features invoke --lib http_processing::config::document::selector_sharing_tests::
cargo test --locked --features invoke --lib http_processing::script_config::tests::
cargo test --locked --features invoke --lib http_processing::script_message::tests::
cargo test --locked --features invoke --lib http_processing::tests::ingress_memory_tests::
cargo test --locked --features invoke --lib http_processing::h2_frame_validation::
cargo test --locked --features invoke --lib shared_collector
cargo test --locked --features invoke --lib outbound::connector::http_reuse_memory_tests::
cargo test --locked --features invoke --lib invoke::http::tests::
cargo test --locked --features invoke,http-diagnostics --lib invoke::tests::http_diagnostics_
```

该组覆盖规则与脚本静态校验、共享入口与原始 URL、内存 H2 帧、正文的收集和回放、静态复用资格、私密输入与只读诊断。macOS 的真实脚本后端测试串行运行，避免独立用例争用进程内的单个执行许可：

```sh
cargo test --locked --features invoke --lib http_processing::tests::script_h1_tests:: -- --test-threads=1
cargo test --locked --features invoke --lib http_processing::scripts::tests:: -- --test-threads=1
cargo test --locked --features invoke --lib platform::apple_runtime_qos::tests::
```

这些 Apple 用例验证本进程的事务、JSC 和线程请求等级。HTTPS 客户端信任、物理设备包 I/O 与性能单独运行。[HTTP 处理](../docs/http-processing.md) · [诊断 Invoke](../docs/invoke-api.md#方法)

## Windows原生检查

内存 profile 的名称选择测试使用 Windows UWP feature：

```sh
cargo test --locked --no-default-features --features ffi,windows-uwp --lib windows::host::tests::
```

构建 UWP DLL 后，在同架构 Windows/Python 上检查 C ABI 与 COM 所有权：

```sh
python scripts/check_windows_com.py --dll dist/windows/arm64/uwp/vole.dll
```

x64 产物使用 `dist/windows/x64/uwp/vole.dll`。设备 VPN、包内调用和 Wintun 的验证范围见 [Windows VPN](../docs/windows-vpn.md)。

## 网络与压力

```sh
container-benchmark interop --source vole=/path/to/Vole
container-benchmark stress --source vole=/path/to/Vole
container-benchmark compare --source vole=/path/to/Vole
```

`interop --list` 离线列出组合。网络验收使用真实 TUN，Mac socketpair 模拟另记路径和结果。Controller 仅用作管理入口。外部 benchmark 负责对端、负载和过程记录。[测试隔离](../docs/testing-isolation.md) · [验收边界](../docs/acceptance.md)
