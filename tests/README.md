# 测试

本仓库维护配置、协议编解码、内存I/O、资源所有权和生命周期回归。
网络互通与压力由独立容器工具管理，结果与结论统一保存在 benchmark 工程。

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

TUN 网络计划（纯内存，不查询宿主路由或创建接口）：`config::tun_network::tests::`、
`platform::linux_network::plan::tests::`、`platform::linux_network::tests::`；
Linux 目标的报文编码：`platform::linux_network::netlink::tests::`。
被动 TCP 的 PMTU 与兄弟流：netstack 集成过滤器
`passive_tun_pmtu_resegments_only_live_sent_tcp_and_preserves_siblings`。

Controller 推送（纯内存 duplex，无网络监听）：`controller::websocket::tests::`；
安全传输/CORS：`controller::secure_tests::`；实例日志脱敏/动态过滤：`logging::tests::`。
组固定清除：`routing::proxy_group::tests::automatic_fixed_clear_uses_existing_health_without_probe`。
这些过滤器不代替真实 TUN 计数与 Stop 验证。

功能出站（纯内存）：`config::functional::tests::`、`outbound::dns::tests::`、
`outbound::reject::tests::`；直连解析角色接线：
`dns::runtime::tests::runtime_dns_separates_bootstrap_proxy_direct_and_hosts`。

进程规则与原始元信息（纯内存，无系统查询）：`config::process::tests::`、
`process::tests::`、`process::linux::tests::`（Linux）、`process::macos::tests::`（macOS）、
`routing::program::tests::process_cursor_is_lazy_once_and_keeps_dns_and_subrule_progress`、
`routing::program::tests::classical_process_provider_resumes_without_selector_side_effects`、
`dialer::tests::process_inspection_small_concurrency_preserves_identity_and_joins_stop`。
共享 socket 初始化槽占满的身份查询截止：`dialer::tests::process_inspection_shared_socket_capacity_has_its_own_deadline`。

对受影响范围选择过滤器，不逐次重跑整张表。下列库测试使用：

```sh
cargo test --locked --no-default-features --features cli,interop-test --lib <过滤器>
```

| 范围 | 过滤器 | 覆盖重点 |
| --- | --- | --- |
| 配置 | `config::tests::` | YAML准入、图、字段单位与边界 |
| 物理出口 | `config::egress::tests::`、`config::dns::upstream_options_tests::`、`runtime::egress_tests::`、`dialer::tests::egress_clones_keep_the_protection_and_stop_owner` | 全局/节点继承、Provider整数覆盖、DNS名称优先与池身份、auto-route冲突和共同Stop owner |
| GeoData | `geodata::tests::` | 合成DAT/MMDB、selector、更新发布和取消 |
| 资源与Provider | `config::rule_provider::`、`runtime::providers::tests::`、`resource::cache::tests::`、`resource::provider_input::tests::`、`resource::http::tests::` | 域名紧凑索引、MRS、URI/Base64/AGE候选、流式gzip与认证隔离、失败保留与旧代资源 |
| 策略组 | `routing::proxy_group::tests::`、`routing::balance::tests::` | 选择、容差、恢复和负载均衡 |
| DNS | `dns::cache::tests::`、`dns::runtime::tests::dns_fallback_`、`dns::runtime::tests::resolve_ipv6_` | 缓存、双栈、竞速和取消 |
| 入口嗅探 | `tcp_sniffer::tests::`、`tcp_sniffer::http2::tests::`、`udp_sniffing::tests::`、`tun_runtime::tests::quic_` | HTTP1/HTTP2目标、HPACK与完整前缀回放；共享QUIC域名键、ECH、预算与重组 |
| QUIC与H3 | `transport::quic::`、`transport::quinn_h3::tests::`、`transport::quiche_h3::tests::`、`dns_quic_` | 官方窗口、真实内存QUIC、DATA读取背压、请求取消、兄弟请求及Stop |
| XHTTP与XUDP | `transport::xhttp::`、`transport::h2_write::tests::`、`xudp::tests::` | 正文缓冲共享、标量部分写入、flush确认、计时与Stop |
| TLS与ECH | `security::context::tests::`、`security::ech::tests::`、`dns::runtime::ech_tests::` | 证书与身份、内存TLS、动态ECH来源 |
| TrustTunnel／Mieru／MASQUE | `trusttunnel`、`mieru`、`masque_` | 真实编解码、信用/背压、复用、单流关闭及同步Stop |
| 有界队列与内存策略 | `routing::datagram_ready::tests::`、`managed_udp_connections_`、`allocator_relief`、`platform::process_memory::tests::` | 就绪轮询、排空、取消和单次回收 |
| TUN 响应背压 | `tun_runtime::tests::backpressured_udp_response_handoff` | 满队列下每源至多暂持一包、双向推进及取消 |
| UoT | `outbound::uot::tests::` | 半帧取消后继续、v2首部、原期限、单槽响应与Stop |
| SS2022 | `outbound::shadowsocks::datagram::tests::` | 三种 cipher、空 UDP、EIH、取消后的 packet ID 与重放边界 |
| CLI前台 | `invoke::foreground::tests::` | 文件/stdin、路径、信号及清理 |

独立集成回归按目标运行，例如：

```sh
cargo test --locked --no-default-features --features cli,interop-test --test tuic_memory
cargo test --locked --no-default-features --features cli,interop-test --test grpc_pool --test grpc_protocol_pool
cargo test --locked --no-default-features --features cli,interop-test --test sing_mux
cargo test --locked --no-default-features --features cli,interop-test --test shadowsocks_backpressure --test shadowsocks_uot
cargo test --locked --no-default-features --features cli --bin vole cli::tests::
cargo test --locked -p vole-blake3-raw --test derive
```

内存QUIC/H3对端通过受控DatagramTransport交换真实包，不绑定宿主监听器。
SS2022 的严格官方 TCP codec 回归可单独选择 `official_tcp_codecs_all_ciphers_` 和
`tcp_response_header_time_salt_auth_and_fragmentation_follow_official_codec`；不要在宿主整体运行
`outbound::shadowsocks::tests::`，其中还包含监听器用例。
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


在线配置的纯内存定向回归：`resource::config_apply::tests::`、`config::live_update::tests::`、`controller::configs::tests::`、`runtime::providers::apply::tests::`、`configuration_candidate_reads_bundle_without_persisting_body_or_metadata`、`configuration_publication_stops_late_old_tree_hint_refill`。覆盖单候选许可、异步／外部线程结果交付、取消后持许可至收尾、严格 API 字段、启动资源拒绝、坏候选保旧图、新 provider 模板延续、候选不写活动资源，以及退休 DNS 树不能回填活动提示。真实 TUN 见证由 benchmark 夹具执行，内存回归不代替平台或业务互通。

共享流式安全身份的纯内存检查（不启动宿主监听器）：

```shell
cargo test --locked --lib config::security::tests::
cargo test --locked --lib security::client_identity_tests::
```

配置检查覆盖具名协议的安全模式、传输限制、XHTTP 两腿继承和 cover mTLS 文件预算；
内存 IO 检查共享连接器握手取消和每次握手的独立状态。真实对端互通另行验收。


SS2022 流式插件的纯内存过滤器：`config::shadowsocks_plugin::tests::`、
`transport::ss_framed::tests::`、`transport::smux::`、`transport::kcptun::`。
它们使用内存流或内存数据报，不启动网络对端；真实TUN互通与压力仍由外部夹具单独验收。

VMess mKCP 的纯内存回归使用 `--lib mkcp_`，覆盖配置/线协议向量、seed/header、
丢包乱序、ACK/flush和Stop；不创建 socket。官方对端业务仍须真实TUN另验。

HY2 Gecko/Realm 的配置和内存wire回归按 `gecko_`、`realm_` 中列出的memory-only名称定向执行；
TUIC ClientHello 使用 `tuic_disable_sni_changes_real_quic_hello_without_changing_verification_policy`。
不得将包含网络peer的整个outbound模块直接作为宿主测试执行。
