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

Linux Unix Controller 的配置与共享鉴权（不绑定 socket）：
`config::controller::tests::controller_unix_`、
`controller::tests::local_context_shares_limits_and_bypasses_only_local_rest_and_websocket_auth`、
`invoke::foreground::overrides::tests::unix_override_`、
二进制 `cli::tests::unix_controller_flag_only_transports_the_explicit_text_value`。
实际文件权限、绑定冲突、对象替换、drop/Stop 清理在隔离 Linux 真实 TUN 夹具验收。
管理 mark 另选 `config::controller::tests::controller_mark_`、
`invoke::foreground::overrides::tests::mark_override_` 和二进制
`cli::tests::controller_mark_flag_`；实际管理回复包 mark 在同一 Linux 夹具核对。

Controller 推送（纯内存 duplex，无网络监听）：`controller::websocket::tests::`；
安全传输/CORS：`controller::secure_tests::`；DNS 展示：`controller::dns::tests::`；
实例日志脱敏/动态过滤：`logging::tests::`。
组固定清除：`routing::proxy_group::tests::automatic_fixed_clear_uses_existing_health_without_probe`。
这些过滤器不代替真实 TUN 计数与 Stop 验证。
临时规则控制另选 `routing::rule_disable::tests::`、`controller::rules::tests::`、
`controller::tests::small_json_body_`、
`routing::program::tests::disabled_main_rules_skip_subprograms_and_keep_the_decision_snapshot`、
`routing::diagnostics::tests::rule_switch_view_shares_only_small_state_with_the_program` 和
`runtime::providers::tests::file_refresh_publishes_valid_members_and_preserves_old_sessions`。

规则重匹配的配置与失败关闭（纯内存）：`config::functional::tests::rematch_`、
`config::measure::tests::measurement_rejects_routing_only_rematch_nodes`、
`routing::tests::rematch_name_predicate_is_trimmed_nonempty_and_case_sensitive`、
`outbound::control::tests::`。
运行时消费者与续跑另选 `routing::program::tests::rematch_`、`routing::rematch::tests::`、
`routing::dispatcher::tests::rematch_`、`dns::runtime::tests::rematch_`；这些用例只使用内存
Dispatcher 和合成端点，不建立监听器或发送网络报文，不代替真实 TUN 组切换验收。

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
| DNS | `dns::cache::tests::`、`dns::runtime::tests::stale_refresh_`、`dns::runtime::tests::dns_fallback_`、`dns::runtime::tests::resolve_ipv6_` | 缓存、过期答复/后台预算/退避/epoch/Stop、双栈、竞速和取消 |
| 入口嗅探 | `tcp_sniffer::tests::`、`tcp_sniffer::http2::tests::`、`udp_sniffing::tests::`、`tun_runtime::tests::quic_` | HTTP1/HTTP2目标、HPACK与完整前缀回放；共享QUIC域名键、ECH、预算与重组 |
| QUIC与H3 | `transport::quic::`、`transport::quinn_h3::tests::`、`transport::quiche_h3::tests::`、`dns_quic_` | 官方窗口、真实内存QUIC、DATA读取背压、请求取消、兄弟请求及Stop |
| XHTTP与XUDP | `transport::xhttp::`、`transport::h2_write::tests::`、`xudp::tests::` | 正文缓冲共享、标量部分写入、flush确认、计时与Stop |
| TLS与ECH | `security::context::tests::`、`security::ech::tests::`、`dns::runtime::ech_tests::` | 证书与身份、内存TLS、动态ECH来源 |
| TrustTunnel／Mieru／MASQUE | `trusttunnel`、`mieru`、`masque_` | 真实编解码、信用/背压、复用、单流关闭及同步Stop |
| 有界队列与内存策略 | `routing::datagram_ready::tests::`、`managed_udp_connections_`、`allocator_relief`、`platform::process_memory::tests::` | 就绪轮询、排空、取消和单次回收 |
| TUN 响应背压 | `tun_runtime::tests::backpressured_udp_response_handoff` | 满队列下每源至多暂持一包、双向推进及取消 |
| UoT | `outbound::uot::tests::` | 半帧取消后继续、v2首部、原期限、单槽响应与Stop |
| VMess 响应边界 | `outbound::vmess::header::delayed_response_memory_tests::`、`outbound::vmess::stream::tests::`、`--test vmess_lifecycle` | 官方延迟响应向量、提交前期限、响应认证、nonce 耗尽与关闭 |
| SS2022 | `outbound::shadowsocks::datagram::tests::` | 官方内存对端、三种 cipher、空 UDP/EIH、认证后 cipher 准入、取消与轮换 ID、重放边界 |
| HTTP 编译与执行 | `http_processing::` | 严格规则与 provider、URL/头/正文、压缩与 JSON Patch、选择性 TLS、H1/H2 和有界回退 |
| HTTP Invoke | `invoke::http::`、`resource::http_control::tests::` | 有界私密输入、离线演算、来源未准备、下载 dispatcher 接线、单一准入、取消与 Stop 收尾 |
| HTTP 在线配置 | `runtime::providers::apply::http_tests::` | 活动快照继承、变更要求重连、旧候选保留 |
| CLI前台 | `invoke::foreground::tests::`、`invoke::foreground::input::tests::` | 文件/stdin、原生路径、显式 HTTP 文件、CA 读取边界、信号取消及清理 |

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
`transport::ss_framed::tests::`、`transport::smux::`。
它们使用内存流，不启动网络对端；真实TUN互通与压力仍由外部夹具单独验收。

HY2 Gecko/Realm 的配置和内存wire回归按 `gecko_`、`realm_` 中列出的memory-only名称定向执行；
TUIC ClientHello 使用 `tuic_disable_sni_changes_real_quic_hello_without_changing_verification_policy`。
不得将包含网络peer的整个outbound模块直接作为宿主测试执行。

## HTTP 处理与 Invoke

`http_processing::` 使用合成规则、临时文件、内存 dispatcher 和 duplex，不创建宿主监听器。
规则入口采用 `http-ports`、`mitm`、`rewrite-providers`、`rewrite` 四个顶层字段，
覆盖严格类型与数值、URL 捕获与替换、请求／响应头、文本与 JSON Patch、压缩、正文预算及整阶段回退。
provider 回归覆盖启用引用的有序展开、关闭引用零 I/O、来源身份、实际 payload 快照、
失败保留、缓存原子发布与取消。规则与私密 CA 的完整合同见 [HTTP 处理](../docs/http-processing.md)。

H1/H2 内存对端覆盖共享 TUN/mixed/CONNECT 适配、预读、最终目标单次选路、
原始 URL 选择、跨 origin 凭据隔离、Expect 早响应、流式背压、半关闭、截断拒绝与取消。
选择性 TLS 同时检查 CA/私钥匹配、叶证书 AKI、证书缓存计费与逐 authority 授权。
未命中正文规则时不收集完整正文；命中后只在有界工作区完成处理，失败恢复原始阶段内容。

`invoke::http::` 检查私密输入在 JSON Value 分配前的准入与 `testHttp` 离线演算。
离线演算不下载、不读 provider、不生成证书；没有实际来源时报告未准备，
没有方向样本时仅报告规则被选中，不声称正文已验证。重写总开关关闭仍可演算启用规则，
真实 HTTPS 授权与 CA 条件单独判断。

`resource::http_control::tests::` 检查指定 dispatcher 的传递、共享配置许可、
Store 争用及取消后等待下载收尾；`invoke::http::` 同时检查 idle refresh 与实例创建互斥。
`runtime::providers::apply::http_tests::` 检查普通路由更新保留活动 HTTP 快照，
HTTP 内容或来源上下文变更要求显式重连。失败恢复的策略组选择另选
`recovery_snapshot_keeps_current_group_member_without_selection_persistence`。

显式配置传递另选 `main_config_and_provider_rebuild_preserve_the_addendum_until_explicit_clear`、
`update_http_addendum_preserves_optional_clear_and_its_separate_byte_limit` 和二进制
`cli::tests::http_addendum_option_only_transports_an_explicit_native_path`。
`resource::paths::tests::` 与
`resource::cache::tests::authorized_provider_roots_read_file_sources_and_write_only_http_caches`
检查原生授权根、符号链接边界、file 读取与 HTTP 缓存写入分离；候选回归同时检查授权上下文继承。
`resource::cache::tests::provider_metadata_requires_bounded_regular_files` 检查 sidecar 大小与 FIFO 拒绝，坏 metadata 不阻止有效正文读取。
`invoke::foreground::overrides::tests::` 检查具体 Controller 覆盖、空值保留及沿用地址解析器；
`invoke::foreground::input::tests::` 检查 Base64 来源优先、标准 padding、认证 AGE 固定向量、
输入预算、取消、单份有效输入复用与主文件重读；
`runtime::providers::apply::http_tests::routing_updates_keep_active_http_and_changed_http_requires_reconnect`
同时检查 foreground 内部模板输入共用候选工作器、坏候选保留与启动资源变化拒绝。`invoke::tests::owned_invoke_uses_the_shared_strict_and_runtime_thread_boundaries`
检查 CLI 的 owned 请求与借用请求共用严格准入和重入边界。
`invoke::foreground::tests::` 检查显式文件与路径、校验不初始化、不自动加载 HTTP 文件、
MITM 关闭不读 CA、无 HTTP 配置的 CA 参数提前拒绝，以及启动期信号取消后 join 清理。
Windows 平台另编译 `snapshot_identity_and_readback_include_the_http_addendum`，
`snapshot_preserves_valid_http_content_expanded_beyond_one_mibibyte` 和
`snapshot_json_budget_counts_actual_escaping_before_allocation`，检查规则实际内容、
独立展开预算、JSON 转义计数与私密材料的会话快照边界。
无默认特性的纯内存回归选择
`http_documents_without_adapter_are_rejected_before_resource_preparation`；
`ca_identity_is_public_der_and_does_not_require_the_http_adapter` 检查公开证书身份不依赖 HTTP 适配器，
启用 HTTP 后另选 `ca_identity_matches_runtime_authority_without_weakening_key_validation` 检查运行期密钥校验。

HTTP/1 早响应与空正文 Upgrade 的定向内存回归：`inbound::http::server::early_final_memory_tests::`；不运行包含宿主 socket 的整个入站测试模块。
上传完成后的响应等待、静默上限与首字节后绝对读头期限：`inbound::http::server::response_deadline_memory_tests::`；使用 paused Tokio clock 和内存 duplex。

这些回归不证明真实 TUN 互通、进程 RSS、吞吐、设备信任安装、系统 VPN 或平台真机行为；
对应验收分别由容器夹具、平台构建和设备测试完成。

IP4P 纯解码与严格配置回归：`config::ip4p::tests::`；不创建 socket 或解析网络名称。

IP4P 接点纯内存回归：`dns::resolution::ip4p_tests::`、
`dialer::tests::connected_ip4p_conversion_precedes_family_and_source_binding_only_at_opted_in_seams`、
`dialer::tests::ip4p_loopback_mapping_cannot_acquire_a_new_literal_exemption`、
`outbound::connector::tests::ip4p_udp_node_endpoint_retains_chain_identity_and_uses_actual_reply_peer`。
这些测试不建立网络 socket；真实 TUN 的 TCP/SS2022/SOCKS5/WireGuard 及 UWP 平台路径单独验收。
