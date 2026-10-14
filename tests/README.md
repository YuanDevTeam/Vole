# 测试

核心配置、内存 I/O 和生命周期回归留在本仓库。网络互通与压力测试由
独立容器测试工具管理，公开实测结论见 [benchmark](../docs/benchmark.md)。

## 本地检查

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --locked --all-features --all-targets --no-run
cargo test --locked --no-default-features --features cli --bin vole cli::tests::
cargo test --locked --no-default-features --features cli --lib invoke::foreground::tests::
cargo test --locked --features cli,interop-test --lib transport::quic::
cargo test --locked -p vole-blake3-raw --test derive
cargo test --locked --features cli,interop-test --test tuic_memory configured_ip_sni_millisecond_heartbeat_and_uot_versions_are_consumed
cargo test --locked --features cli --lib tuic_uot_
cargo test --locked --lib config::tests::
cargo test --locked --features cli --lib trusttunnel
cargo test --locked --features cli --lib mieru
cargo test --locked --features cli --lib masque_
cargo test --locked --lib config::credentials::tests::
cargo test --locked --features cli --lib age_
cargo test --locked --lib dns::hosts::tests::
cargo test --locked --lib config::name_regex::tests::
cargo test --locked --lib config::override_expr::tests::
cargo test --locked --lib override_expr_materializes_after_filters_and_structured_names
cargo test --locked --no-default-features --features cli --lib dns::runtime::ech_tests::
cargo test --locked --no-default-features --features cli --test ech_config
cargo test --locked --lib config::tls_policy_tests::
cargo test --locked --lib config::tls_trust::tests::
cargo test --locked --lib security::context::tests::
cargo test --locked --no-default-features --features cli --test grpc_config --test grpc_pool --test grpc_protocol_pool
cargo test --locked --no-default-features --features cli --lib transport::h2_empty::tests::
cargo test --locked --no-default-features --features cli --lib grpc_duplex_pool_keeps_response
cargo test --locked --no-default-features --features cli --test sing_mux_config --test sing_mux
cargo test --locked --no-default-features --features cli --lib sing_mux
cargo test --locked --lib outbound::anytls::client::tests::idle_minimum_
cargo test --locked --lib outbound::anytls::client::tests::disabled_reuse_
cargo test --locked --lib outbound::anytls::session::tests::initial_batches_
cargo test --locked --no-default-features --features cli --lib prepares_shared_mux_capabilities
cargo test --locked --lib explicit_verification_name_does_not_change_sni_or_allow_skip_to_override_it
cargo test --locked --lib mutual_tls_identity_is_required_verified_and_not_shared_between_clients
cargo test --locked --lib geodata::tests::
cargo test --locked --features cli --lib asn_
cargo test --locked --all-features --lib resource::http::tests::
cargo test --locked --all-features --lib outbound::http::tests::
cargo test --locked --all-features --lib outbound::wireguard::tests::
cargo test --locked --all-features --lib platform::linux_network::tests::
cargo test --locked --all-features --lib connections::tests::
cargo test --locked --all-features --lib routing::diagnostics::tests::
cargo test --locked --all-features --lib routing::datagram_ready::tests::
cargo test --locked --all-features --lib polled_datagram_
cargo test --locked --all-features --lib managed_udp_connections_
cargo test --locked --all-features --lib runtime::tests::controller_diagnostics_are_opt_in_for_business_routes
cargo test --locked --all-features --lib subrule_
cargo test --locked --lib config::domain_regex::tests::
cargo test --locked --lib address_suffix_preserves_low_bits_and_address_family
cargo test --locked --lib suffix_rules_use_source_low_bits_and_resume_with_shared_provider_budget
cargo test --locked --lib rule_budget_propagates_through_fake_ip_policy_and_sniffer_without_egress
cargo test --locked --lib classical_selectors_keep_complete_logical_domain_and_ip_predicates
cargo test --locked --lib classical_logical_selectors_drive_dns_policy_and_sniffing_without_egress
cargo test --locked --all-features --lib ingress_
cargo test --locked --all-features --lib routing::balance::tests::
cargo test --locked --all-features --lib load_balance_routes_
cargo test --locked --all-features --lib dialer::connections::tests::
cargo test --locked --all-features --lib fake_ip_
cargo test --locked --all-features --lib sniffing::tests::
cargo test --locked --all-features --lib tcp_sniffer::tests::
cargo test --locked --all-features --lib dns::fallback::tests::
cargo test --locked --all-features --lib dns::runtime::tests::dns_fallback_
cargo test --locked --all-features --lib dns::runtime::tests::resolve_ipv6_
cargo test --locked --lib dns::tests::cache_
cargo test --locked --lib dns::cache::tests::
cargo test --locked --lib dns::tests::opaque_cache_
cargo test --locked --lib dns::runtime::tests::dns_cache_
cargo test --locked --lib config::tests::dns_rcode_
cargo test --locked --lib dns::runtime::tests::dns_rcode_
cargo test --locked --lib dns::runtime::tests::dns_flush_
cargo test --locked --features cli --lib dns::source::tests::
cargo test --locked --features cli --lib dns::runtime::tests::dns_source_
cargo test --locked --features cli --lib config::tests::dns_source_
cargo test --locked --features cli --lib config::dns::upstream_options_tests
cargo test --locked --features cli --lib dns::options::tests::
cargo test --locked --features cli --lib dns::runtime::tests::upstream_
cargo test --locked --features cli --lib dns::runtime::encrypted_tests::upstream_tls_options_
cargo test --locked --features cli --lib doh_
cargo test --locked --features cli --lib dns_quic_
cargo test --locked --features cli --lib controller_secure_
cargo test --locked --features cli --lib dns::runtime::encrypted_tests::encrypted_dns_
cargo test --locked --features cli --lib invoke::tests::update_dns_network_
cargo test --manifest-path crates/vole-netstack/Cargo.toml --all-targets
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
```

DNS URL 参数、DoH GET/Basic、H2 并发与取消、ALPN/H1 回退只使用内存报文、显式来源快照和 duplex TLS 对端。DoQ/H3 与冷建连版本竞争使用有界 memory DatagramTransport，驱动官方 Quinn 与 shared h3/h3-quinn；不读取宿主 DNS 或启动监听服务。
`dns::runtime::ech_tests::` 与 `security::ech_dynamic_tests::` 使用内存 DNS 报文、显式来源快照和 duplex TLS，验证 HTTPS65 ECH 来源、节点角色、内层名称、取消和 Stop。`security::ech::tests::` 用真实 rustls Outer/Inner 加解密验证各 KEM/KDF/AEAD 家族，命名模板保留独立准入。
`controller_secure_` 使用 duplex HTTP/TLS/H2、内存证书与临时文件，验证 CORS、共享鉴权/路由、客户端认证与握手签名、RSA 2048、候选更新及 Stop；不绑定宿主监听器。

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

`outbound::wireguard::tests::` 在内存中交换真实 Noise 与 raw-IP 包，覆盖主动 TCP、双栈 UDP、真实握手重试、多 peer 最长前缀与 reserved、节点远端 DNS、端点更新、取消与 Stop；不打开 socket 或系统接口。

`mieru` 包含真实加密数据报的纯内存回归，覆盖独立接收信用、累计 ACK、乱序前缀、远端关闭后的读取与无读者 Stop；小容量 Partial 路径单独保留。

`masque_` 使用内存密钥、IP/UDP 包和受控 QUIC 对端，验证模式准入、CONNECT、
capsule、流关联、包预算及 Stop。实际内存 H2 双端验证响应准入、DATA 保留与取消隔离；
节点 DNS 验证启用规则、来源继承与缓存失效，共享创建验证独立期限和取消所有权。
主动栈的原始 TCP/PMTU 回归位于 `vole-netstack`。

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
`age_` 使用官方 Go AGE 生成的公开 X25519/Hybrid fixture、内存流和临时文件验证解密、
私钥准入、认证/取消/大小预算、密文缓存与失败更新保留；不运行外部进程或打开网络 socket。
`resource::cache::tests::` 使用内存 HTTP 流和临时缓存验证订阅元信息的候选提交、304、失败保留与磁盘恢复；`resource::subscription::tests::` 验证有界数值解析。

`routing::proxy_group::tests::` 覆盖自动选择、容差、恢复与选择缓存；`resource::probe::tests::` 和 `invoke::measure_delay::tests::` 使用内存流验证共享健康探测、HTTP 状态和取消。

Controller 主动探测与内存使用纯内存过滤：`manual_probes_keep_one_history`、`delay_query_preserves_reference`、`admits_mixed_only_direct_controller`、`current_process_has_resident_memory`。真实 HTTP 对端由 benchmark 隔离运行。

规则bundle的定向内存/临时文件验证使用 `resource::bundle` 与 `resource::cache::tests::bundle_`，覆盖真实MRS成员、解码预算/取消、缓存优先及原HTTP来源回退，不启动宿主服务。

`transport::quic::` 验证官方 Quinn Middle 固定窗口、独立初始/最大值和规范 DATAGRAM 容量。
`tuic_memory` 使用真实内存 Quinn 对端覆盖固定信用、数据报预算、未读取流与 Stop；
`dns_quic_` 覆盖 DoQ/H3 的独立发送/接收预算、实际 DNS GET/Basic/ID 包装、复用与取消；
响应 HEADERS/body 被对端暂停后取消仍能复用兄弟请求，8192 字节字段在 4098 字节初始信用下继续读取，
正常 SETTINGS 和 GOAWAY 能推进；GOAWAY 后的新查询建立新连接，旧查询继续完成。
未发布初始化、握手取消与移交前的坏预算失败均验证 driver / adapter Stop 回收。
peer 暂停响应阶段验证 DNS 所有权，不声称每次都精确落在某个内部 Pending poll；共享层的显式 Pending 取消另由
`transport::quinn_h3::tests::` 验证。它们不修改 registry 源码。
独立 DNS feature 编译使用 `cargo check --locked --no-default-features --features dns-quic --lib`；
该闭包不启用 quiche，`cli` / `ffi` 仍通过 TUN 启用 TrustTunnel / MASQUE 等 quiche 协议。
`transport::quiche_h3::tests::` 与 `transport::h3_connect::` 使用真实内存 QUIC，
覆盖 TrustTunnel/MASQUE 的 CONNECT、Cloudflare token、实际 peer SETTINGS、未知 DATAGRAM flow 丢弃与 Stop 回收；
CONNECT 驱动还验证 512 KiB 双向内容、信用推进、对端实际收到请求 FIN 与同步 Stop。
`security::tls::tests::quiche::` 验证 quiche H3 路径的证书、pin、mTLS 和 ECH。
这些用例不启动网络 listener。
TUIC额外内存对端消费入口ip、SNI、毫秒Heartbeat和UoT v1/v2
字节；不创建宿主监听服务。它们不替代最终参考互通、吞吐和RSS测量。
