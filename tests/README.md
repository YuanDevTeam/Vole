# 测试

本仓库维护配置、协议编解码、内存I/O、资源所有权和生命周期回归。
网络互通与压力由独立容器工具管理，公开结果见[benchmark](../docs/benchmark.md)。

## 本地检查

按[编译文档](../scripts/README.md)准备原生依赖后执行：

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --locked --all-features --all-targets --no-run
cargo test --manifest-path crates/vole-netstack/Cargo.toml --all-targets
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

宿主只运行明确的无网络对端回归，全目标测试仅编译。`invoke::tests::`包含监听器用例，
不能整体在宿主执行。CI完整过滤器以[Tests workflow](../.github/workflows/test.yml)为准；
CI使用Debug和继承Release优化的`ci-release`，正式产物使用标准`release`。
Windows的UWP/Wintun feature互斥，应明确选择后端，不使用`--all-features`。

## 定向回归

对受影响范围选择过滤器，不逐次重跑整张表。下列库测试使用：

```sh
cargo test --locked --no-default-features --features cli,interop-test --lib <过滤器>
```

| 范围 | 过滤器 | 覆盖重点 |
| --- | --- | --- |
| 配置 | `config::tests::` | YAML准入、图、字段单位与边界 |
| GeoData | `geodata::tests::` | 合成DAT/MMDB、selector、更新发布和取消 |
| 资源与Provider | `runtime::providers::tests::`、`resource::cache::tests::` | 候选提交、失败保留、旧代资源与缓存 |
| 策略组 | `routing::proxy_group::tests::`、`routing::balance::tests::` | 选择、容差、恢复和负载均衡 |
| DNS | `dns::cache::tests::`、`dns::runtime::tests::dns_fallback_`、`dns::runtime::tests::resolve_ipv6_` | 缓存、双栈、竞速和取消 |
| QUIC与H3 | `transport::quic::`、`transport::quinn_h3::tests::`、`transport::quiche_h3::tests::`、`dns_quic_` | 官方窗口、真实内存QUIC、请求取消、兄弟请求及Stop |
| XHTTP与XUDP | `transport::xhttp::`、`transport::h2_write::tests::`、`xudp::tests::` | 正文缓冲共享、标量部分写入、flush确认、计时与Stop |
| TLS与ECH | `security::context::tests::`、`security::ech::tests::`、`dns::runtime::ech_tests::` | 证书与身份、内存TLS、动态ECH来源 |
| TrustTunnel／Mieru／MASQUE | `trusttunnel`、`mieru`、`masque_` | 真实编解码、信用/背压、复用、单流关闭及同步Stop |
| 有界队列与内存策略 | `routing::datagram_ready::tests::`、`managed_udp_connections_`、`allocator_relief`、`platform::process_memory::tests::` | 就绪轮询、排空、取消和单次回收 |
| TUN 响应背压 | `tun_runtime::tests::backpressured_udp_response_handoff` | 满队列下每源至多暂持一包、双向推进及取消 |
| UoT | `outbound::uot::tests::` | 半帧取消后继续、版本首部、原期限、单槽响应与Stop |
| CLI前台 | `invoke::foreground::tests::` | 文件/stdin、路径、信号及清理 |

独立集成回归按目标运行，例如：

```sh
cargo test --locked --no-default-features --features cli,interop-test --test tuic_memory
cargo test --locked --no-default-features --features cli,interop-test --test grpc_pool --test grpc_protocol_pool
cargo test --locked --no-default-features --features cli,interop-test --test sing_mux
cargo test --locked --no-default-features --features cli --bin vole cli::tests::
cargo test --locked -p vole-blake3-raw --test derive
```

内存QUIC/H3对端通过受控DatagramTransport交换真实包，不绑定宿主监听器。
Mieru回归保留TCP/UDP分池、慢读背压、单槽交接、终态传播、接收分配复用和未读响应下的Stop。
GeoData、AGE、Provider和缓存测试使用合成输入、公开固定向量、内存流及临时文件。
这些局部预算与行为检查不证明进程RSS、网络吞吐或真机内存达标。

协议输入见[protocols](protocols/README.md)，ClientHello输入见[fingerprints](fingerprints/README.md)。
脚本回归验证产物布局、后端/ABI选择和归档；真实编译与原生加载分别验证。

## Windows原生检查

名称选择只使用JSON和未注册的内存profile对象，不创建系统VPN或启动连接：

```sh
cargo test --locked --no-default-features --features ffi,windows-uwp --lib windows::host::tests::
```

构建UWP DLL后，在同架构Windows/Python上执行C ABI与COM所有权检查：

```sh
python scripts/check_windows_com.py --dll dist/windows/arm64/uwp/vole.dll
```

x64使用`dist/windows/x64/uwp/vole.dll`。四个独立子进程覆盖线程初始化、MTA所有权、
线程切换、STA拒绝和响应释放；仅查询未打包环境，不访问VPN或网络。
通过不代表包内、Wintun或设备验证。

## 网络与压力

```sh
container-benchmark interop --source vole=/path/to/Vole
container-benchmark stress --source vole=/path/to/Vole
container-benchmark compare --source vole=/path/to/Vole
```

所有网络业务经真实TUN，Controller仅作管理入口；服务端与原站遵守[容器隔离](../docs/testing-isolation.md)。
`interop --list`可离线列举当前用例。测试工具维护负载、对端和计量，Vole不依赖其checkout编译。
互通、压力、平台编译、原生调用与真机验证的结果分别记录，见[验收边界](../docs/acceptance.md)。
