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
Core Debug、Release 和 Quality 测试使用 Ubuntu 26.04；发布构建的 Linux runner 保持 Ubuntu 24.04。
Windows的UWP/Wintun feature互斥，应明确选择后端，不使用`--all-features`。

## 定向回归

原生 URL 选择器共享的纯内存过滤器为
`http_processing::config::document::selector_sharing_tests::`。
真实 Document／Payload 编译覆盖本次候选共享、跨候选隔离、最后 owner 释放、
来源顺序、捕获模板及重复 pattern 仍逐条执行的文本／规则／禁用边界；
不创建网络对端，也不证明搜索缓存或进程 phys_footprint 的实际节省。

已知长度共享正文 collector 的纯内存过滤器为 `--lib shared_collector`，
另运行 `http_processing::body_budget::mapped_output_tests::` 的实际映射／失败回退／last-slice 控制。
这些测试经过真实共享 Transaction、H1 Cursor、H2 长度和实际 duplex RecvStream，
检查已知边界、未知溢出与 trailer 回放、部分 EOF、原生回退、完整原文及最后 owner 退款。
独立原生入口保持 Vec；metadata-only 脚本仍可能因原生正文规则进入共享 collector。
映射路径 fixture 单独显式运行，合法 Vec 回退不等于语义错误；受控物理 mapper 失败
与真实 selector 控制分别取证，不伪称宿主发生真实 mmap 失败。
这些无 host socket 的控制不证明 45MiB phys_footprint 或吞吐，最终仍须实际压力窗口。

TUIC 业务 HTTP 静态资格的纯内存过滤器为
`outbound::tuic::http_reuse_memory_tests::`；真实 TLS 身份控制为
`config::identity_files::http_reuse_security_memory_tests::tuic_real_tls_constructor_reuses_inline_but_rejects_file_identity`。
孤立 `inbound-http,outbound-tuic` 组合覆盖五项真实构造器控制和一项身份控制；
额外启用 `outbound-socks5` 时检查真实外层静态 TCP 证明及内层 Stop 撤销。
测试不创建 socket，检查实际 TLS／直接 UDP 工厂的固定身份、动态路径拒绝、保护／绑定限制和取消；
文件身份只用内存来源标记，不读取文件或启动刷新 worker。
这些控制不证明真实 TUIC→业务 TLS→H1/H2 的集成复用、吞吐或 phys_footprint。

TUIC UoT 私有分池纯内存过滤器：启用 `outbound-tuic,interop-test` 后运行
`--test tuic_memory tuic_uot_lane_`。真实 Quinn 经32项内存包队列完成 TLS/exporter
认证与 Connect/UoT wire，检查两类复用、持旧租约时第三条 live 连接、退休隔离、
末旧租约释放及 Stop/join/probe idle；不创建 socket，不证明保护/绑定、真实对端、
吞吐或进程 physical footprint。原 native source stripes 与非 UoT quic relay 回归仍须保留。

macOS 通用 QUIC 的 DIRECT 批量发送纯内存过滤器：公开逐包 poll 生产接缝使用 `macos_public_send_memory_`；真实 generic owner 与嵌套预算包装继续使用 `macos_quic_batch_memory_`。
这些回归检查完整数据报及IPv6目标、首包Pending、FIFO确认正前缀、未发后缀不重放、原32项容量、RX进展、错误与短发送、非法count、取消及close/drop/租约释放。物理接缝只注入内存poll结果，不创建socket或网络对端，不证明真实Tokio/系统调用的重试次数、设备行为或性能达标；实现已不使用私有sendmsg_x ABI。非macOS、代理与codec的默认拒绝继续走既有 `quic_memory_` 单包回归。
macOS MASQUE H3/IP、H3/L4、TUIC quic relay及WireGuard 固定直接UDP发送的纯内存过滤器为 `fixed_udp_memory_`。它驱动实际初始化helper的prepared-owner→connect→成功发布、准备/连接错误、Pending取消后不重试、Drop/close、完整IPv6 peer及实际普通/owned/batch入口的写前拒绝；共享单包完成helper验证完整长度及原错误。上游scope控制使用既有内存connector并证明Group保留旧snapshot和unconnected能力，Proxy保留原预算/路径；不创建socket。原六项 `macos_public_send_memory_` 及六项 `macos_quic_batch_memory_` 控制保持，并扩展两项connected public-poll边界控制。prepared错误只模拟原Dialer保护/策略聚合边界的拒绝，不证明真实OS protect/connect、kernel来源过滤、ICMP、平台绑定或性能；这些需有限隔离benchmark控制与正常构建窗口。
TUIC-only 构建使用 `--no-default-features --features outbound-tuic`，可独立运行上述 `fixed_udp_memory_` 和 `macos_public_send_memory_connected_`；`interop-test` 另启用其它协议，不作为独立 TUIC feature 的证明。
`masque_h3_fixed_factory_memory_` 另经真实 ConnectionFactory 获取尚未打开的传输，检查 H3/L4 的 Direct/LazyDirect 固定物理 peer、完整 IPv6 scope/flow 与全部发送入口的写前拒绝，并保留 H3/IP、Group 快照和 Proxy 请求路径。旧无连接工厂先在实际传输的共享能力检查处失败，不在反例中发送网络包；此检查不启动 QUIC 驱动，不证明 OS connect、吞吐或 phys_footprint。

WireGuard 固定物理 endpoint 的实际工厂过滤器为 `wireguard_connected_factory_memory_`（macOS，`outbound-wireguard`）。
它从真实 Driver::endpoint／transport 获取未打开的传输，覆盖 Direct/LazyDirect、IPv4／IPv6、完整 peer 写前拒绝、原 MTU+32预算和512KiB提示，以及 Group 快照与 Proxy 拒绝回调。
测试仅在固定能力已确认后触发错目标发送；所有真实 netstack owner 先 Stop/join 后判决，不建立 socket、Noise驱动或网络对端。
`--no-default-features --features outbound-wireguard` 可独立编译和运行该过滤器及固定 UDP helper／connected public-poll 控制，不依赖 MASQUE。
端点 refresh、真实 Noise 的 RX／取消与已有批量 pending Drop／close 控制仍分别保留；纯内存结果不证明 OS connect／protect／ICMP、roaming、吞吐或 phys_footprint。

应用 RX 映射纯内存过滤器：在 `crates/vole-netstack` 运行 `mapped_rx_`。保留原 56KiB 应用 RX／112KiB 总 RX 控制，并覆盖 macOS MASQUE H3/IP 的 64KiB 应用 RX／128KiB 总 RX 与 32KiB 总 TX；检查实际 mapping owner、独立两份空缓存、部分读取不归还活跃 backing、映射失败的有限 Vec 回退，以及真实 driver 的握手、accepted tail 与 Stop。它不证明进程 phys_footprint 或协议吞吐达标。

Unix TUN 适配器与数据面循环：`platform::tun_rs_io::tests::`、`tun_runtime::tests::` 使用 Unix socketpair 和内存 Dispatcher 检查包边界、批量收发、配置 MTU、取消与描述符所有权。Linux 仅在 `cfg(test)` 使用共享描述符适配，真实构造器仍拒绝非 TUN；Apple 保留 tun-rs 的包信息头路径。这些回归不代替真实 TUN 验收。

Mieru UDP载体的TCP上传收尾：`outbound::mieru::udp::tests::mieru_udp_upload_`。
五项纯内存回归使用真实编解码、可靠驱动与有界origin流，覆盖尾包首发成功后丢失、重传后EOF，
以及待ACK时的Stop、取消shutdown future、同载体兄弟、立即Drop与对端Close；不代签真实TUN交付或RSS。

关闭后的收包边界：`outbound::mieru::udp::tests::mieru_udp_closed_`，以实际首Close丢失、迟到ACK和origin EOF验证最后SID与同载体兄弟。
`outbound::mieru::udp::balanced_driver_tests::mieru_udp_empty_sid_ready_invalid_preserves_idle_retirement_cancel_and_first_send_gate`
覆盖首发前不收包、空会话持续无效输入下的原空闲退休及Stop；这些纯内存结果不替代真实TUN验收。
`outbound::mieru::udp::tests::mieru_udp_first_close_loss_recovers_with_silent_peer_before_origin_eof`
使用真实可靠驱动、codec与有界origin，覆盖首Close丢失且目标无后续DATA/ACK时的正常原站EOF；
保留payload/hash与资源回收检查，不代签自然关闭故障归因或真实TUN压力表现。
同模块的 `mieru_udp_close_retry_` 使用实际驱动验证无响应时最多两次补发，以及补发等待中的活动Stop与owner回收。
同模块的 `mieru_udp_timeout_epoch_` 以真实codec验证TX拆批间ACK增长、旧flight超时惩罚归并、
实际重发再次超时、fast/timeout优先级及未ACK许可回收；不代替真实TUN的丢失恢复和性能验收。
`outbound::mieru::udp::tests::mieru_udp_saved_rto_` 通过同一物理owner的两类业务与真实codec，验证
UDP发送时期限、TCP动态期限、失败发送不发布状态、快速重传及整write许可回收。
`outbound::mieru::udp::ready_batch_memory_tests::` 使用真实可靠输出、AEAD和写许可，
验证低熵UDP载体首次DATA的有界就绪批次、正数前缀记账、原密文后缀、拒绝/错误及活动取消。
普通发送后仍保留ACK信用；测试不代签真实物理批量调用命中、TUN性能或平台验收。
`mieru_udp_pattern_ready_batch_real_client_stop_joins_active_owned_send` 保留实际流及写等待者，
验证活动批量操作在真实 Client Stop／tracker join 时先于物理关闭释放；仅使用有界内存对端。

smux 纯内存边界：`transport::smux::`，覆盖就绪 DATA 的单次 poll 预算、未读流与兄弟流、整帧分配预算、极小合法配额、本地关闭释放和远端 DATA→FIN 顺序。
调度测试隔离 Tokio 的独立 cooperative allowance；这些测试不代替真实 TUN 性能验证。

VMess／Trojan gRPC 延迟响应（纯内存 H2 duplex，Trojan 加内存 TLS）：启用
`cli,interop-test` 后运行 `--test grpc_protocol_pool`。覆盖认证提交后跨越原期限的上传、
迟到状态校验、Trojan 半关闭尾部，以及同一挂起读取的活动 Stop、对端自然退出和资源释放。
Trojan-only 构建使用 `--no-default-features --features outbound-trojan --lib`；不代替真实 TUN 验证。

VLESS 的同类边界使用 `--test vless_transports grpc_committed_vless_request_outlives_delayed_http_response`，
同 target 的 `grpc_unresponsive_peer_keeps_original_setup_deadline` 检查未收到 SETTINGS 时仍受原期限约束；
另以 `--test vless_lifecycle vless_all_handshakes_keep_the_original_deadline_and_join_cancelled_io`
保留未完成建链的原期限；VLESS-only 编译使用 `--no-default-features --features outbound-vless --lib`，不添加 `cli`。

VLESS Encryption 记录层的纯内存回归使用
`--lib outbound::vless::encryption::records::tests::`，可沿用上述 VLESS-only features。
覆盖发送背压下的接收进展、独立读写调用者的就绪与取消唤醒、恢复前导顺序、
nonce 连续性及 Vision 关闭。真实 `OwnedStream` 的取消反例在释放对象前记录唤醒，
再核对 owner 与 waker 释放；不以析构唤醒替代正常进展，也不代替完整握手或压力验收。

客户端凭据与输入（纯内存）：`config::tests::client_uuid_`、
`config::vmess::cipher_compatibility_tests::`、`config::hysteria2::p08_tests::hopping_`。
实际映射凭据、端口跳跃和各协议数据面由真实 TUN 另验收。
UDP 配置归一化（纯内存）：`config::mihomo_udp_tests::`，覆盖 VLESS `none` 使用
XUDP 并保留 Vision、既有编码，以及 HY2/TUIC 的固有 UDP 能力和 SOCKS5 显式开启控制。
仅经 `Config::parse_yaml` 检查公开配置与归一化结果，不初始化运行时，不代替真实 TUN 选路或协议互通。
WS 查询和头预算：`config::vmess::websocket_query_tests::` 与内存 duplex 的
`--test stream_foundations websocket_early_data_and_remaining_frames_keep_the_original_byte_order`；
XHTTP 输入和自定义上行方法：`--test xhttp_config`、
`--test xhttp_requests packet_metadata_and_upload_methods_are_sent_in_each_supported_location`。
VLESS packetaddr 自主写使用实际 PacketUp Writer 的纯内存 H2 duplex：
`--test vless_transports packetaddr_xhttp_memory::packetaddr_xhttp_keeps_first_flush_and_drives_last_datagram_without_post_ack`。
覆盖请求头／首 DATA 的 POST 确认，以及最后单帧的独立推进、确认前接收和同步 Stop。
已建立关联的部分写取消使用库过滤器
`outbound::vless::datagram::tests::established_packetaddr_partial_write_resumes_by_send_or_receive_without_replay`，
检查越过原建链期限后由 send／receive 恢复同帧、无重放及回复来源。
这些内存 seam 不代替 H3、真实 TUN、进程 RSS 或压力验收。

VLESS 私有 H2 split 活动租约：`--lib outbound::vless::outbound::active_h2_memory_tests::private_split_h2_shares_four_active_leases_and_stops_both_legs -- --exact`，以真实 duplex H2 两腿验证四租约共享、阈值扩容、兄弟关闭、末租约释放和同步 Stop/join；它不是实际 TUN 或 TLS wire 互通验收。
REALITY 资格使用同模块的 `private_split_h2_reality_qualification_shares_four_active_leases_and_stops_both_legs`；
`private_split_h2_reality_peer_stream_credit_opens_new_download_physicals` 检查低对端信用，
Linux 的 `private_split_h2_reality_control_fallback_and_dialer_stop_do_not_take_cached_sender` 检查独立 TCP-control 与 Dialer/节点 Stop。
这些纯内存测试从公开 REALITY 配置进入池选择，但测试 peer 不执行 REALITY/TLS 认证；真实 TUN 认证与 RSS 必须单独验证。

Gun 增量读取（纯内存）：`transport::grpc::streaming_read_memory_tests::`。
实际H2/有界duplex覆盖已校验前缀在消息尾到达前交付、拆分头与varint、空消息、
取消恢复、原有合法编码、截断与trailers，以及半关闭尾读和Stop/join；不代表TUN压力结果。

private h2mux PacketUp 两阶段写（纯内存）：
`outbound::sing_mux::tests::private_packet_up_h2mux_hands_off_tail_and_keeps_strong_flush_fin_stop`
经过真实私有包装器与 duplex H2，覆盖末块自主移交、强 flush、半关闭尾读和活动 Stop/join；
`transport::grpc::private_rst_memory_tests::private_h2mux_real_peer_reset_covers_credit_empty_write_fin_and_eof`
使用真实 duplex h2 peer 的 RST/EOF，检查零信用挂起唤醒、已有余量、RST后空/非空写、
底层capacity→RST→send_data保护及FIN拒绝；两个connection future均inline推进并结束。
原生guard场景不伪称在coalesced函数内部插入竞态，仍需源码锁证明；不是CPU/吞吐或TUN验收。
另用 `transport::grpc::private_demand_memory_tests::` 检查完整接受后调用方 idle、
以及已有缓冲 DATA 后再次完整接受时，不保留未接受的预约信用。
真实内存 H2 对端授予新窗口后再观察，不以额外 flush 或下一次 write 隐藏预约状态；
原短写、RST、物理 flush、FIN 和 Stop 回归仍独立保留。
`transport::h2_write::tests::coalesced_writer_bounds_markers_and_never_flushes_unencoded_or_failed_payloads`
检查固定确认登记、未编码兄弟隔离及取消/失败唤醒。另保留既有 datagram 首帧强 flush/部分写取消回归。
`transport::sing_mux::h2_driver::prequeued_flush_memory_tests::already_queued_large_data_progresses_before_pending_raw_flush_completes`
检查真实 H2 已排队 DATA 在底层强 flush Pending 时继续推进；
`transport::h2_write::productive_repoll_memory_tests::` 检查仅有正写入进度且有存活私有确认所有者时
才重调度一次，以及普通写、零进度、失败、Drop 和强 flush 确认边界。
`transport::h2_write::prefix_wire_tests::` 以真实双流 H2 codec 检查旧确认前缀的推进，
同时保持新 UDP 强收据未确认及双端自然退出；持续兄弟流另检查 128 KiB 字节额度在部分 DATA
帧中暂停、前缀确认后恢复及后缀收据保护。该模型不代替真实 H3 POST 或自主调度验证。
`ordinary_data_exceeds_the_quiet_budget_until_a_late_flush_requests_it` 验证未请求确认的真实
H2 DATA 可越过轮转观察额度，迟到 flush 会启用闸门，确认前缀后后缀继续且新 Strong 仍未确认；
断言前完成双端协议 owner。marker 控制另覆盖旧 ticket 不清新等待、current Strong 仍受额度限制。
这些检查不证明真实 H3、自主调度或性能。
`transport::sing_mux::h2_driver::receive_credit_memory_tests::held_tcp_windows_leave_receive_credit_for_a_sibling`
调用生产 driver 和真实内存 H2 peer，8 条 CONNECT 各持有 64 KiB 接收信用，检查第 9 条小 DATA 在释放前推进；随后真实返还信用、消费双向 EOF 并完成双方协议 owner。它只验证该有限信用场景，未覆盖完整 UDP codec、自主调度、H3、真机、吞吐或进程内存。
`transport::sing_mux::h2_driver::receive_credit_memory_tests::initial_window_contract::`
另从实际 factory 的 wire 读取 stream SETTINGS 与连接 WINDOW_UPDATE，覆盖 32/64/65/128 KiB
实体完整接收。1 MiB 模式持有八条 128 KiB 流时第九条等待，1.5 MiB 模式可继续推进第九条，
持有十二条后第十三条等待。等待中的流在真实归还信用后恢复，双方协议 owner 最终退出。
65 KiB只是合成 carrier 字节边界，不声称执行了 TLS、业务 HTTP 改写或完整 UDP codec；
不把接收信用或无整窗预分配等同进程内存保证。
这些测试不代替 XHTTP/H3、真实 TUN、内存或容量验收。

共享 H3 PacketUp 有界响应重叠（纯内存）：`transport::xhttp::h3_packet_overlap_memory_tests::`，
经过归一化 VLESS 节点、H2Mux／Yamux 的实际 factory 选择和 H3 driver，
检查单正文回收、两响应槽、乱序确认缺口、低流信用、早错误、FIN／Drop 和同步 Stop。
实际 Yamux 构造器另检查 H1/H2 与 stream-up／stream-one 保持原路径。
该几何 fixture 不执行内层 Yamux／H2Mux codec，不替代真实组合互通；
同模块 udp_budget::yamux_fixed_send_retention_has_no_adaptive_udp_control_or_raise
以阻断 ACK 的原生内存 QUIC 写入观察限定 factory 的固定128KiB留存：实际接受前缀大于96KiB
且不超过128KiB，满后 Pending，解开门控后完整交付并 FIN；没有 UDP 升档 control。
排除 factory、H3 stream-up／stream-one 与仅开几何标记仍以真实 native 写入验证64KiB上界；
H1/H2 版本检查仅验证 factory 选择。新增setter测试另验证clone预算变化的实际dial隔离、
shared资格互斥与Stop，不能作为旧API测试先行语义RED或进程内存／吞吐证据。
H2Mux 原有 metadata flush／退役／取消的64→256KiB证明必须单独保留，不能由Yamux channel-ready推导。
`transport::xhttp::packet_up::overlap::lease_memory_tests::` 检查真实 Bytes 最后引用释放的通知、同一 Vec 回收及 closed／Weak 所有权。
这些检查不代替真实 TUN、RSS、吞吐或平台验收。

规则输入与 selector 元数据（纯内存）：`config::name_regex::tests::`、
`config::domain_regex::tests::`、`config::rule_provider::tests::classical_`、
`routing::tests::in_name_`。覆盖命名/数字捕获编号、IN-NAME 和混合 classical 条件。

TFO 纯内存策略与生命周期：
`config::functional::tests::node_tfo_is_explicit_and_does_not_inherit_across_proxy_chain`、
`config::providers::tests::provider_tfo_override_preserves_false_and_materializes_exact_node_policy`、
Linux `dialer::server_tcp::tests::` 和 `dialer::fast_open::tests::`。
`dialer::fast_open::gate::real_tun_private_tfo_gate` 为显式 ignored 容器驱动，
实际 SYN-data、首读/空写/半关闭、源绑定/protect、建链期限与 Stop 须由 Linux 真实 TUN 验证。
这些内存过滤器不证明内核 Fast Open 或其它平台行为。

MPTCP / TCP Brutal 纯内存过滤器：`--lib mptcp`、`config::functional::tests::`、
`config::sing_mux::tests::`、`transport::sing_mux::brutal::tests::`、
Linux `dialer::tcp_control::tests::`；池与生命周期另用下方 sing_mux 集成回归。
sing-mux 懒响应与首业务写入期限：`transport::sing_mux::tests::`，覆盖纯上传期间
延迟 H2 headers/status、空/未完成写入保留原期限，以及迟到状态校验与半关闭。
双子流、出口约束、TCP 回退、TFO、模块及真实参数/发送侧生效、对端协商与 Stop
须在隔离 Linux 真实 TUN 中另验；1 / 3 Gbps 压力及平台、真机结果分别记录。

TUN 网络计划（纯内存，不查询宿主路由或创建接口）：`config::tun_network::tests::`、
`platform::linux_network::plan::tests::`、`platform::linux_network::tests::`；
Linux 目标的报文编码：`platform::linux_network::netlink::tests::`。
ICMP 配置的纯内存过滤器：`config::tests::tun_icmp_options_`；Linux 覆盖默认/零值、
实际秒值、禁用与现有重连门禁，以及负值/时钟范围/整数溢出拒绝；其他平台验证未知字段拒绝。
Linux Echo 所有权用 `tun_runtime::echo::tests::`，netstack 编解码用 `echo::tests::`；
不打开物理 ping socket，不代替实际 TUN、物理源、校验和、权限与 Stop 验证。
被动 TCP 的 PMTU 与兄弟流：netstack 集成过滤器
`passive_tun_pmtu_resegments_only_live_sent_tcp_and_preserves_siblings`。
`device::tests::no_learned_path_still_enforces_initial_mtu_and_drops_unsupported_oversize`
以单槽 IPv4／IPv6 输出验证首次 PMTU 提示前仍按接口 MTU 分段，且不将超长非 TCP 包直接发送；
首提示授权、未发尾部及回收继续由 `device::tests::`／`segmentation::tests::` 覆盖。

Linux Unix Controller 的配置与共享鉴权（不绑定 socket）：
`config::controller::tests::controller_unix_`、
`controller::tests::local_context_shares_limits_and_bypasses_only_local_rest_and_websocket_auth`、
`invoke::foreground::overrides::tests::unix_override_`、
二进制 `cli::tests::unix_controller_flag_only_transports_the_explicit_text_value`。
实际文件权限、绑定冲突、对象替换、drop/Stop 清理在隔离 Linux 真实 TUN 夹具验收。
Linux socket 创建权限、路径替换与严格 umask 的内核回归使用 `controller::unix::tests:: -- --ignored --test-threads=1`，
仅在隔离 Linux 容器运行；它们检查实际 Unix socket 与本地 IPC，不代替真实 TUN 或完整 Controller 业务验收。
管理 mark 另选 `config::controller::tests::controller_mark_`、
`invoke::foreground::overrides::tests::mark_override_` 和二进制
`cli::tests::controller_mark_flag_`；实际管理回复包 mark 在同一 Linux 夹具核对。

Controller 推送（纯内存 duplex，无网络监听）：`controller::websocket::tests::`；
安全传输/CORS：`controller::secure_tests::`；DNS 展示：`controller::dns::tests::`；
实例完整日志/动态级别过滤：`logging::tests::`。
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

Linux 原生 socket 初始化的许可、取消与 Stop（纯内存）：
`dialer::native_init_memory_tests::typed_admission_bounds_cancelled_waiters_and_waits_for_stop`。
`dialer::native_init_fd_tests::` 默认忽略，包含真实 socket 创建与 bind；仅在隔离 Linux
容器内，借用真实 raw-IP TUN fd 后显式运行。它验证初始化调度、选项、回调与 fd 释放，
不代表 TUN 业务或压力通过；后者使用普通 CLI 的独立真实 TUN 验证。

对受影响范围选择过滤器，不逐次重跑整张表。下列库测试使用：

```sh
cargo test --locked --no-default-features --features cli,interop-test --lib <过滤器>
```

| 范围 | 过滤器 | 覆盖重点 |
| --- | --- | --- |
| 配置 | `config::tests::` | YAML准入、图、字段单位与边界 |
| 物理出口 | `config::egress::tests::`、`config::dns::upstream_options_tests::`、`platform::linux_network::native::tests::`、`dialer::tests::egress_clones_keep_the_protection_and_stop_owner` | 全局/节点继承、Provider整数覆盖、DNS名称优先与池身份、auto-route标记共存和共同Stop owner |
| GeoData | `geodata::tests::` | 合成DAT/MMDB、selector、更新发布和取消 |
| 资源与Provider | `config::rule_provider::`、`runtime::providers::tests::`、`resource::cache::tests::`、`resource::provider_input::tests::`、`resource::http::tests::` | 域名紧凑索引、MRS、URI/Base64/AGE候选、流式gzip与认证隔离、失败保留与旧代资源 |
| 策略组 | `routing::proxy_group::tests::`、`routing::balance::tests::` | 选择、容差、恢复和负载均衡 |
| DNS | `dns::cache::tests::`、`dns::runtime::tests::stale_refresh_`、`dns::runtime::tests::dns_fallback_`、`dns::runtime::tests::resolve_ipv6_` | 缓存、过期答复/后台预算/退避/epoch/Stop、双栈、竞速和取消 |
| 入口嗅探 | `tcp_sniffer::tests::`、`tcp_sniffer::http2::tests::`、`udp_sniffing::tests::`、`tun_runtime::tests::quic_` | HTTP1/HTTP2目标、HPACK与完整前缀回放；共享QUIC域名键、ECH、预算与重组 |
| QUIC与H3 | `transport::quic::`、`transport::quinn_h3::tests::`、`transport::quiche_h3::tests::`、`transport::h3_connect::tests::`、`dns_quic_` | 官方窗口、真实内存QUIC、DATA读取背压、请求取消、兄弟请求及Stop |
| XHTTP与XUDP | `transport::xhttp::`、`transport::h2_write::tests::`、`xudp::tests::` | 正文缓冲共享、标量部分写入、flush确认、计时与Stop |
| TLS与ECH | `security::context::tests::`、`security::ech::tests::`、`dns::runtime::ech_tests::` | 证书与身份、内存TLS、动态ECH来源 |
| TrustTunnel／Mieru／MASQUE | `trusttunnel`、`mieru`、`masque_` | 真实编解码、信用/背压、复用、单流关闭及同步Stop |
| 有界队列与内存策略 | `routing::datagram_ready::tests::`、`managed_udp_connections_`、`allocator_relief`、`platform::process_memory::tests::` | 就绪轮询、排空、取消和单次回收 |
| UDP 共享与隔离 | `managed_udp_connections_`、`fake_ip_routing_preserves_tcp_names_and_distinct_udp_reply_addresses`、`quic_override_resolves_new_domain_and_restores_udp_response_target` | 同源多目标、固定目标、逐目标关闭与旧回复隔离，支持共享的底层仍保留 Fake-IP/嗅探还原隔离 |
| TUN 响应背压 | `tun_runtime::tests::backpressured_udp_response_handoff` | 满队列下每源至多暂持一包、双向推进及取消 |
| UoT | `outbound::uot::tests::` | 半帧取消后继续、v2首部、原期限、单槽响应与Stop |
| VMess 响应边界 | `outbound::vmess::header::delayed_response_memory_tests::`、`outbound::vmess::stream::tests::`、`outbound::vmess::outbound::polled_datagram_memory_tests::`、`--test vmess_lifecycle` | 官方延迟响应向量、HTTP迟到响应与节点取消、提交前期限、响应认证、收发计数回绕、加密 packetaddr 多目标帧与回包来源、跨回绕连续交付、认证错误关闭、逐字节轮询、读写交错取消与关闭 |
| SS2022 | `outbound::shadowsocks::datagram::tests::` | 官方内存对端、三种 cipher、空 UDP/EIH、认证后 cipher 准入、取消与轮换 ID、重放边界 |
| Trojan UDP | `routing::dispatcher::tests::managed_trojan_udp_`、`--test trojan` | 真实内存帧、同源多目标共享、来源及关闭后旧回复隔离、取消与流释放 |
| TUIC UDP | `outbound::tuic::wire::tests::`、`outbound::tuic::datagram::tests::` | 按声明长度交付、分片满表下新包前进、资源界限和来源隔离 |
| SOCKS5 UDP | `outbound::socks5::tests::` | 真实内存握手与帧、同源多目标复用、异源隔离、关闭重建后旧回复隔离、relay 来源和嵌套预算 |
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
`transport::h3_connect::tests::write_waker_memory_tests::` 验证独立读写等待者的发送通知、
读侧完成发送块的交接，以及真实 native Pending 时的停止、Drop 和传输错误释放。
`transport::quiche_h3::native_ready_batch_memory_tests::` 验证真实wire帧的共享排空额度、已轮询FIN/RESET、兄弟流和可靠body前缀；不代替完整driver与TUN验收。
同组还检查取消流在真实 QUIC 回收后释放独立 H3 状态：双向 Drop 顺序、流控背压、
STOP_SENDING 的延迟收集和超过单轮额度的有限清理，保持兄弟正文与正常 FIN。
`quiche_h3_memory_settings_unknown_flow_dispatch_and_joined_stop` 在退役 ID 尚待确认时
执行完整 driver Stop/join，并检查正文、退役索引和两层协议状态均释放；这些纯内存
回归不代替 900Mbps 普通构建下的 phys_footprint 与吞吐验收。
netstack的`active_tcp_shutdown_drains_accepted_tail_before_fin_without_prior_acks`与`active_tcp_drop_drains_accepted_tail_before_fin_without_prior_acks`使用既有缓冲和真实ACK，验证未确认写入的前缀、FIN排序及最终释放。
`stack::tests::failed_fast_retransmit_survives_another_socket_filling_tx`使用两个真实内存TCP socket与重复ACK，
验证兄弟socket占满输出后，失败的快速重传在容量恢复时仍可立即重试；不启动网络对端或TUN。
SS2022 的严格官方 TCP codec 回归可单独选择 `official_tcp_codecs_all_ciphers_` 和
`tcp_response_header_time_salt_auth_and_fragmentation_follow_official_codec`；不要在宿主整体运行
`outbound::shadowsocks::tests::`，其中还包含监听器用例。
Mieru回归保留TCP/UDP分池、慢读背压、单槽交接、终态传播、接收分配复用和未读响应下的Stop。
`outbound::mieru::tcp::udp_send_credit_memory_tests::` 用实际Client::create与有生命周期计数的
内存DatagramTransport验证默认LOW UDP Associate载体共享96 KiB发送信用；非默认预算、
其他业务/模式/载体不变，并组接两个真实RawStream验证共享信用、原FIFO2及取消/Stop回收。
两笔32 KiB写入后仍有32 KiB信用；第三笔写被原FIFO2阻塞，不冒充96 KiB已耗尽。
`outbound::mieru::udp::tests::mieru_udp_send_credit96_two_sids_keep_fragment_leases_until_their_acks`
通过原可靠分片与真实codec输出验证部分/重复ACK、first-send与独立SID许可退休，原TX8不变。
这些用例不创建socket、DNS、监听器或网络对端，不证明真实TUN性能或RSS。

`outbound::mieru::tcp::udp_admission_memory_tests::` 使用原命令通道、完成回执和字节许可，
验证保守四写 UDP 准入、第五笔发送屏障、就绪错误、空写、部分记录取消和 NoWait 收尾；TCP 写入保留原等待边界。
`outbound::mieru::udp::tests::mieru_udp_admission_depth4_` 另通过实际编解码与可靠驱动，验证 FIFO 分片、累计ACK许可释放和延迟Close拒绝。
`outbound::mieru::tcp::udp_pool_memory_tests::` 使用真实池预留、RawStream、原有界命令通道与字节许可，
覆盖繁忙TCP载体与UDP业务隔离、UDP同业务活动复用、许可未退休时背压及Stop释放；不启动物理驱动。
同模块的 `least_load_` 检查真实State与Reservation对两载体复用选择的影响，保留随机tie起点、
原新建桶及非LOW/非UDP载体行为；不测量网络负载或RSS。
新增多目标真实 codec 回归使用 `outbound::mieru::packet_routing_tests::`、
`outbound::trusttunnel::packet::tests::`、`outbound::vmess::header::datagram_memory_tests::`、
`wireguard_memory_shared_udp_targets_cancel_and_close_independently` 与
`masque_ip_memory_shared_udp_leases_cancel_and_close_independently`。
HY2 透明混淆/pacer 传递使用
`salamander_memory_and_pacer_preserve_address_sharing_owned_send_and_close`。
它们覆盖逐包地址、取消与独立关闭，不以能力布尔断言替代真实帧和所有权验证。
GeoData、AGE、Provider和缓存测试使用合成输入、公开固定向量、内存流及临时文件。
fake-IP 热更新使用 `runtime::tests::live_dns_`，经实际运行时组装检查 DNS 停用／重开、
A/AAAA 内存 wire，以及临时 redb 的映射、游标加载和持久 owner 复用，不创建网络 socket。
这些局部预算与行为检查不证明进程RSS、网络吞吐或真机内存达标。
命名指纹准入使用 `config::fingerprint_tests::`；标准 H2 SETTINGS/ACK 与 ALPS 可选性使用
`selected_profiles_use_standard_h2_settings_when_the_server_supports_alps`（内存 TLS/H2）。
REALITY 允许经典/混合协商的配置与两腿真实 share 使用
`--test reality_config --test security_capabilities`（无网络 IO）。

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

HY2 共享握手的纯内存所有权/期限/同步 Stop：`outbound::hysteria2::outbound::shared_handshake_memory_tests::`。

文件 mTLS 身份的纯内存 TLS/临时文件回归：
`security::tls::tests::identity_rotation_memory_tests::`（启用 `outbound-http`；命名后端再启用 `tls-fingerprint`）、
`security::identity::tests::` 与 `config::identity_files::tests::`。
覆盖连续换代/旧连接与票据隔离、坏文件保留和读取失败恢复、来源独立、取消/Stop、输入预算及原生材料按需分配；
不创建监听器，实际 TUN/QUIC 轮换仍由容器夹具验收。

HY2 Gecko/Realm 的配置和内存wire回归按 `gecko_`、`realm_` 中列出的memory-only名称定向执行；
TUIC ClientHello 使用 `tuic_disable_sni_changes_real_quic_hello_without_changing_verification_policy`。
不得将包含网络peer的整个outbound模块直接作为宿主测试执行。

## HTTP 处理与 Invoke

Apple 自有运行时线程 QoS 的纯内存回归：启用 `invoke`，过滤 `platform::apple_runtime_qos::tests::`。
真实新建线程与 engine builder 的 scheduler／blocking 线程检查公开 requested getter，
并确认宿主调用线程不被修改；不创建网络或 TUN，也不证明有效优先级或 CPU 核调度。

`http_processing::` 使用合成规则、临时文件、内存 dispatcher 和 duplex，不创建宿主监听器。
规则入口采用 `http-ports`、`mitm`、`rewrite-providers`、`rewrite`、`http-scripts` 五个顶层字段，
覆盖严格类型与数值、URL 捕获与替换、请求／响应头、文本与 JSON Patch、压缩、正文预算及整阶段回退。
provider 回归覆盖启用引用的有序展开、关闭引用零 I/O、来源身份、实际 payload 快照、
失败保留、缓存原子发布与取消。规则与私密 CA 的完整合同见 [HTTP 处理](../docs/http-processing.md)。

H1/H2 内存对端覆盖共享 TUN/mixed HTTP/SOCKS5/CONNECT 适配、预读、最终目标单次选路、
原始 URL 选择、跨 origin 凭据隔离、Expect 早响应、流式背压、半关闭、截断拒绝与取消。
选择性 TLS 同时检查 CA/私钥匹配、叶证书 AKI、证书缓存计费与逐 authority 授权。
未命中正文规则时不收集完整正文；命中后只在有界工作区完成处理，失败恢复原始阶段内容。

H1 末次正文 flush 与最终响应同时就绪的内存过滤器为
`inbound::http::server::final_flush_repoll_memory_tests::`，以真实 64 KiB、正文 write／flush、响应字节及双方任务退出检查非阻塞补 poll；Pending／错误／缺字节／末次 write 未完成仍关闭，响应后不增加正文 read／write poll。该模型不代表完整脚本、载体压力或进程内存验收。
`prepared_cases::` 另用真实 native/shared 事务、deferred Message 和独立预算账本，检查原始 64 KiB 到等长／32 KiB 输出、末次 write Pending、预算拒绝与真实 slice 最后 owner 退款；该模型不代表 JavaScript 后端执行或进程内存。

静态代理 HTTP 复用资格的纯内存过滤器为
`outbound::connector::http_reuse_memory_tests::`（启用 `inbound-http`，各协议正例另启用对应出站 feature）。
使用真实 HTTP／SOCKS5／SS2022 连接器，只检查不可变路径证明，不创建 socket、执行解析或读取文件；
覆盖字面 IP 与单一预解析端点、静态代理链、策略组与未知依赖排除、地址族与物理出口限制、
TLS 构造、传输插件排除和停止后撤销资格。H1/H2 实际内存 TLS 复用与退役仍由
`http_processing::tests::https_h1_reuse_memory_tests::`、
`http_processing::h2_reuse::integration_tests::` 和
`http_processing::h2_reuse::validation::` 覆盖；结构证明不代替真实 TUN 协议互通、吞吐或进程 footprint 验收。
官方 H2 的 HEADERS／CONTINUATION、DATA／trailer、短写与 Pending、driver join／IO owner 回收使用
`http_processing::h2_frame_validation::` 的纯内存 duplex 回归。
实际 H2 接收设置与共享连接信用另选 `http_processing::h2_tests::receive_credit_memory_tests::`，
使用真实 serve_h2、内存 duplex 和已接受的 wire 帧检查 SETTINGS、短写前缀、连接信用耗尽及原截止；
所有 IO owner 在断言前关闭并 join，不创建宿主监听器，也不代替吞吐或进程内存验收。
普通空正文／固定长度请求的复用补充过滤器为 `--lib completed_post_`：H1/H2 实际内存 TLS 对端检查完整上传、原生正文改写、逐请求选路与已发送请求不重放；`http_processing::h2::completed_post_upload_error_memory_tests::` 直接经过实际 H2 exchange，检查最终响应头后的真实截断上传，以及仅丢弃一个在途交换时撤销新准入、保留兄弟响应并回收 IO owner。该测试观察点仅在 cfg(test) 中存在，不进入普通发布构建。
VMess／Trojan 的实际构造器、安全身份与停止资格补充在
`config::identity_files::http_reuse_security_memory_tests::stream_proxy_` 与
`config::identity_files::http_reuse_security_memory_tests::vmess_plain_tcp_keeps_static_http_proof`；
使用已有内存 PEM 与文件来源标记，不运行文件工作器。覆盖 TCP／WS／gRPC、内联／文件身份、
静态／动态 ECH、上游组与节点／Dialer 停止；纯结构结果不证明完整 HTTP 交付或自然对端关闭。
长 VMess 连接另保留 `outbound::vmess::stream::tests::encrypted_records_continue_across_the_official_counter_wrap`
和 `stream_receives_the_wrapped_peer_record_and_closes_normally` 的内容、计数与关闭回归。

启用 `sing-mux,inbound-http` 时，`http_processing::tests::https_h1_reuse_memory_tests::sing_mux_reuse::`
以真实 yamux、目标元数据和上游 TLS 验证两个 HTTPS/H1 事务复用同一逻辑流、正文 hash、
原站路径及取消后的实际 owner 回收。该内存链路从解密后的下游开始，不代替 H2mux/H3、
完整 MITM、真实 TUN 或性能验收。

实际路由准备另选 `routing::dispatcher::tests::http_reuse_memory_tests::`，覆盖业务域名不在本地解析、
重复 key、账户／入口／authority、路由组实际叶与链、资源身份、REJECT，以及 DIRECT 原有门禁。

`invoke::http::` 检查私密输入在 JSON Value 分配前的准入与 `testHttp` 离线演算。
脚本的纯静态语法/配置检查位于 `http_processing::scripts::frontend::tests::` 与
`http_processing::config::tests::`；Apple 实际 JSC 求值、安全预算与取消位于
`http_processing::scripts::tests::` 和 frontend 的 Apple prelude 定向回归。
`http_processing::script_message::tests::` 检查候选原子性、原始 URL、凭据、headers/状态类别和共享正文 owner；
`http_processing::tests::script_h1_tests::` 与 `http_processing::h2_tests::h2_script`
通过内存双端和实际 JSC 验证共存、只脚本本地响应、终止/回退及早响应，不创建宿主原站。
这些检查不替代真实 NE fd、设备业务、完整进程内存或吞吐验收。
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

统一入口的纯内存回归：`http_processing::tests::ingress_memory_tests::` 检查普通 HTTP
非处理端口仍完整转发、固定代际、同下游退出处理路径时旧上游退役，以及普通 HTTP/CONNECT
共用 force/skip/端口/目标覆盖策略。
`inbound::socks5::server::http_processing_memory_tests::` 使用真实 SOCKS5 握手和 duplex
验证独立 HTTP/MITM 接线、透明回放、入口身份、原生/JS 与取消；不运行包含 socket 的整个入站模块。

这些回归不证明真实 TUN 互通、进程 RSS、吞吐、设备信任安装、系统 VPN 或平台真机行为；
对应验收分别由容器夹具、平台构建和设备测试完成。

IP4P 纯解码与严格配置回归：`config::ip4p::tests::`；不创建 socket 或解析网络名称。

IP4P 接点纯内存回归：`dns::resolution::ip4p_tests::`、
`dialer::tests::connected_ip4p_conversion_precedes_family_and_source_binding_only_at_opted_in_seams`、
`dialer::tests::ip4p_loopback_mapping_cannot_acquire_a_new_literal_exemption`、
`outbound::connector::tests::ip4p_udp_node_endpoint_retains_chain_identity_and_uses_actual_reply_peer`。
这些测试不建立网络 socket；真实 TUN 的 TCP/SS2022/SOCKS5/WireGuard 及 UWP 平台路径单独验收。

TUIC 冷连接的公开 API 门禁（纯内存、无票据缓存或网络 socket）：
`tuic_cold_connection_cannot_publish_an_early_quinn_handle_without_resumption`。
它检查仅启用 early-data 不能取得 Quinn 的早期客户端连接，不代表恢复连接或服务端验收。

Linux 受控物理 QUIC 的纯内存过滤器：`physical_quic_memory_` 与
`physical_quic_switches_are_session_scoped_strict_and_keep_mihomo_defaults`。
检查分段的逐包/总字节预算、来源与显式源覆盖拒绝、完整接收边界、默认值与严格字段；
不创建 socket，不证明真实 ECN/GSO、protect、RSS、吞吐或设备行为。
`transport::quic::physical::tests::physical_quic_memory_revocation_releases_io_with_retained_broadcast_pollers`
在纯内存中检查多等待者广播、注册交错与持有已退役句柄时释放 IO。
`physical_quic_memory_concurrent_read_leases_delay_retirement_until_both_release` 另验两个并发读者、
退役等待双方释放及资源只析构一次。显式 ignored 的
`transport::quic::physical::gate::real_tun_native_udp_retirement_gate` 仅供隔离 Linux
容器以真实 TUN 验证适配器的 fd、资源计数和 Stop；常规内存回归不得执行该网络门禁。

MASQUE 业务 HTTP 静态资格的构造器过滤器为
`outbound::masque::http_reuse_memory_tests::`（启用 `inbound-http,outbound-masque`；HTTP代理链额外启用 `outbound-http`）。
仅在内存生成 ECDSA 材料并构造真实节点，覆盖 H2 TCP／H3直接UDP分界、固定配置与密钥、
字面端点精确匹配、动态组／未知依赖、约束Dialer与递归依赖停止；不启动engine、QUIC、DNS或监听器。
这些查询测试不证明真实业务复用或Stop join；另运行原MASQUE安全、engine取消、H3 L4兄弟流与HTTP H1/H2所有权回归。

MASQUE H2 capsule已就绪合批的纯内存过滤器：
`outbound::masque::ip::h2_output_batch_memory_tests::` 与
`transport::masque_codec::tests::masque_capsule_append_fit_and_rejection_preserve_the_existing_wire_prefix`。
使用实际pump、内存PacketStream与codec验证合并、单包及时提交、大包与单溢出帧顺序、
TTL、取消安全、强flush背压及错误；不创建网络socket，不代替真实TUN与RSS验收。

WireGuard 输出准入的纯内存过滤器：`outbound::wireguard::engine::full_handoff_memory_tests::`。
使用真实 netstack 和原 32 槽队列，检查单 peer 保留满队列包至释放一槽、取消后资源释放，
以及多 peer 的有界交接与兄弟 peer 进展。

WireGuard pending ingress 的纯内存过滤器：
`outbound::wireguard::peer::pending_ingress_memory_tests::`。实际 Noise 和 netstack/pump/peer 的
32 槽队列构造 RX→TX 循环背压，检查 pending 等待期间原 owner 仍发送、单次准入、
原定时器回退后实际 UDP 恢复，以及取消优先和 Stop 回收。受控 Tokio 时间不改变生产 timer；
阶段等待以真实队列/active socket 状态为准，有限 harness poll guard 仅防止测试挂起。
原 `wireguard_memory_ready_receive_does_not_starve_send_or_stop` 和 `full_handoff_memory_tests::`
须一并回归；这些测试不代替实际吞吐、丢包与 phys_footprint 验收。
`vole-netstack` 的 `packet_recover_` 过滤器检查 Full/关闭/验证失败返回原 Packet、
持久 send waiter 的 FIFO 与取消同时 Ready 时不准入；只使用内存队列。

macOS WireGuard 就绪数据批量发送的纯内存过滤器：
`outbound::wireguard::peer::pending_ingress_memory_tests::ready_data_batch_memory_tests::`。
主用例使用实际 Noise、4 个已就绪 UDP 包和原 peer 事件循环；旧逐包路径也应完成认证交付，
取消、物理关闭及真实栈 Stop/join 后才检查已使用批量能力、FIFO 和 owner 归零。
控制用例检查部分前缀后发送原密文后缀、不支持与单包回退、物理发送错误不重放、
pending 操作的取消及原期限回收，以及大 MTU 与真实 Noise 控制报文保持逐包发送。
这些内存用例不代替吞吐、UDP 丢失或 phys_footprint 验收。

macOS WireGuard 就绪接收的纯内存过滤器：
`outbound::wireguard::peer::pending_ingress_memory_tests::ready_receive_memory_tests::`。
私有 helper 合同检查原 Context 单次轮询及 Pending wrapper 回收；实际 Noise 和原 netstack
检查无效输入、保活计入四包上限，待准入 ingress、未建立状态和取消停止额外接收。
这些用例不证明随机 select 的方向公平、控制墙钟延迟或性能，须保留原 peer 进展与 Stop 回归。

WireGuard 路由表的纯内存过滤器：`outbound::wireguard::routes::tests::`。
经实际配置校验和路由表构造检查空表、单前缀、主机边界、双栈隔离、最长前缀及同前缀最后声明的所有者。

WireGuard 业务 HTTP 静态资格的纯内存过滤器：
`outbound::wireguard::http_reuse_memory_tests::`（`outbound-wireguard,inbound-http`）。
实际 Config／WireGuardOutbound 构造覆盖完整多 peer 与重复公钥归一化、代表端点隔离、
初始／非零 refresh 的实际路径、prepared mismatch 的原驱动 retarget、保留多地址拒绝、
IPv6 与 IP4P 编码端口、未知／上游组／TCP proof 不代表 UDP、物理限制、配置与密钥快照、
节点／原 Dialer Stop 和地址族包装器。查询后 engine 仍未创建；测试不执行解析、Noise、
栈或 socket，不证明真实 refresh、peer 故障退役、协议互通、吞吐或 phys_footprint。
已有 Noise／路由／私有 DNS／端点 refresh／peer 故障隔离／活动 Stop 回归仍须独立运行。

TUN 入站头长度观察的纯内存过滤器：启用 `http-diagnostics` 后运行 `tun_ingress_`。
它检查实际读切片与容量的区别、短基本头、未知版本及 IPv6 长度加法，既不验证完整 IP
也不证明真实设备截断；reader 的批次前缀、无效包隔离和有效 MTU 回归另行运行。

TUN driver 观察的纯内存过滤器：在 `vole-netstack` 启用 `diagnostics` 后运行
`driver_observer_`。实际握手和双向传输检查字节、entry 与 drive 计数，另验正常唤醒、
Pending／EOF／取消不混计及默认入口不安装回调、真实 Stop join。
Core 启用 `tun,http-diagnostics` 后串行运行
`tun_runtime::tests::synthetic_fd_with_dns_disabled_dispatches_tcp_and_reuses_udp_association`，
检查 mock TUN 的真实回调接线与正增量；不代替诊断开销、真机吞吐或 footprint 验收。

VLESS 业务 HTTP 静态资格使用 `outbound::vless::outbound::http_reuse_memory_tests::`
（`outbound-vless,inbound-http`，并包含对应共享 TLS／直接 UDP hook）。真实构造在内存覆盖
Vision REALITY、XHTTP H2 REALITY、XHTTP H3 TLS、其它静态模式、H1/H2/H3 隐式与显式下载腿；
检查真实 H3 版本、未知／动态路径与安全身份、非 Dual／绑定／Stop、两腿 owner 取消，
并保留 XHTTP 私有活动池资格。JLS 补充检查实际 Boring 工厂、配置与实际客户端错配、
主／下载各腿 owner／物理限制以及泛型安全 helper 仍拒绝；不借此验证实际 JLS 握手。
Native／XorPublic／Random 的实际 Client 覆盖 `1rtt`／`0rtt`、Vision、Client／节点 Stop、
物理路径限制和各下载腿 owner；Random 另检查上传／下载父依赖的 Client 或节点停止撤销资格。
不会打开流、做 DNS 解析或读文件；不能代签真实协议／吞吐／footprint。
`macos_mptcp_preference_` 使用真实配置、Dialer、VLESS／Dispatcher 和静态路径检查，
确认 macOS 普通 TCP 标记例外与其它物理限制分别生效；其它平台仍拒绝该标记。
`private_split_h2_mptcp_preference_tracks_macos_plain_tcp_scope` 另检查真实 split-H2 两腿
构造、原 mode／版本／安全条件及 Dialer 取消，不把不可变池选择标志当作停止回执。

`outbound::vless::encryption::records::tests::native_h2_duplex_memory::` 以有界内存双向流
承载实际 H2 帧和流量控制，检查四个并发双向实体的内容及 TX 背压期间的 RX 进展，
并在断言前回收 request／driver owner。该接缝使用合成恢复流和已有密码向量，
Random 补充使用真实双向 CTR 与恢复响应解析，检查同一流上的多实体传输及背压；
不执行 KEM／VLESS 握手或 Vision direct 切换，也不代替真实 Encryption HTTP 复用或压力验收。

Hysteria2 业务 HTTP 静态资格选择
`outbound::connector::hysteria2_http_reuse_memory_tests::`（`outbound-hysteria2,inbound-http`）。
真实构造检查精确 literal/direct UDP 首跳、动态/未知上游与组、TCP proof 不代表 UDP、
protect/绑定/地址族/MPTCP、节点及原 Dialer Stop、hopping/Realm/动态 ECH、内联身份。
`config::identity_files::http_reuse_security_memory_tests::hysteria2_` 继续用真实构造和内存身份标记
检查文件来源拒绝及静态/动态 ECH；同模块 `constructed_tls_` 保留 actual Inline/Files 后端负例。
不解析、连接或读取身份文件，不证明真实认证、活动流 Stop、吞吐或进程 phys_footprint。

Mieru 业务 HTTP 静态资格使用纯内存过滤
`outbound::mieru::http_reuse_memory_tests::`：实际构造器覆盖 TCP／UDP、
全部 mux／握手模式、默认／固定 custom pattern、端口范围、域名、多地址、
动态组、未知依赖、受约束 Dialer、节点／Dialer 停止与真实 SOCKS 上游的
TCP 图／直接 UDP 区别。fixture 不打开 socket、DNS 或载体；构造器沿原路径
捕获不可变 hostname 快照。结构测试不证明对端交付、协议互通、吞吐或 footprint。

SS2022 ShadowTLS 的静态资格使用
`static_ss2022_actual_shadowtls_v3_plugin_qualifies_and_stop_revokes_without_stopping_dependency`
（`inbound-http,outbound-shadowsocks,shadow-tls-v3`）。
`outbound::shadowsocks::plugin::shadowtls_reuse_owner_tests::` 以两个独立真实调用者检查
读／写 Pending、另一方向 Ready、父取消唤醒、子令牌隔离及释放；不建立网络连接。
`shadowtls_http_reuse_uses_actual_inline_or_published_file_identity_storage` 另需 `outbound-http`，
使用合成临时文件验证实际 Files 来源被拒绝，不读取用户身份材料。
`ss2022_over_authenticated_shadowtls_preserves_partial_cancelled_write_and_idle_read`
使用内存原生 TLS、Vole ShadowTLS／SS 及官方 SS 服务端 codec，验证两份 64KiB 实体、
真实 raw Pending 和接收字节边界上的取消恢复；对端 ShadowTLS MAC 仍采用 Vole 实现，
不代替官方 ShadowTLS peer、实际路由／HTTP 池、吞吐或进程内存验收。

VMess 单 URI legacy H2 的 HTTP 复用资格内存过滤器：
`config::identity_files::http_reuse_security_memory_tests::vmess_h2_`。真实配置/节点构造验证
静态安全身份、路径限制、单/多 URI 区分和停止撤销；不打开身份文件、socket或系统接口。
载体过滤器 `outbound::vmess::stream::legacy_h2_memory_tests::` 使用实际 VmessStream＋
legacy H2、小流控窗口及 duplex，交换双向各两份64KiB正文，覆盖双向Pending、接收不等待
受阻发送、取得原Driver后的stop/join与peer退出。准备期间取消仍沿原Drop-abort，
不提供该路径的join证明。测试从post-response-authentication seam开始，
不证明完整VMess认证、业务HTTP cache整链、官方wire、吞吐或footprint。


SS2022 obfs HTTP/TLS 的资格与完整流 owner 纯内存过滤器（
`inbound-http,outbound-shadowsocks`）：
`outbound::connector::http_reuse_memory_tests::static_ss2022_obfs_actual_config_requires_owned_http_reuse`
为一个分组测试，以真实 Config、SS 出站和 Dispatcher 覆盖三 cipher×两 mode，
保留 literal／upstream／group／opaque／物理限制及节点、依赖 Stop 负例。
`outbound::shadowsocks::plugin::obfs_reuse_owner_memory_tests::` 包含四项测试；
先单独运行 `obfs_owned_existing_fanout_control_handles_complete_ss_pending_fixture`
确认真实 SsStream 的首写保留、双向 Pending 和既有 fanout 夹具，再运行其余三个
`obfs_owned_` 用例，检查 actual Owner.bind 的 write／flush／shutdown 与读侧独立等待者、
Stop-before-bind 零底层 IO、child Drop 与兄弟流、真实 tracker shutdown 及最终 owner 释放。
三个 owner 用例分别包含18／6／6个分支；所有 raw/waker 清理先于最终行为断言。
控制项显式使用既有 fanout，不代替实际 Obfs bind 资格或官方对端证明。
这些测试不使用 socket、DNS、文件、真实 cover／WS peer 或全局正文账本；
不证明 SS 响应认证、官方 simple-obfs wire、HTTP cache、吞吐或 phys_footprint。

SS2022 裸流／obfs 静态路径与停止边界另运行
`outbound::connector::http_reuse_memory_tests::static_shadowsocks_all_ciphers_preserve_obfs_path_and_stop_guards`，
并保留原 `shadowtls_reuse_owner_tests::`。新增 obfs 绑定仅在 `inbound-http` 构建生效；
其它 WebSocket 模式、Gost 和 JLS 保持单次；下述明文标准 WS mux 是独立固定范围。
既有 ShadowTLS wrapper 的读写、唤醒及 Drop 合同不变。

SS2022 simple-obfs 首响应前缀使用生产模块过滤器
`outbound::shadowsocks::response_header::tests::header_probe_`：按 actual CipherKind 验证 59／91 字节、
真实 Pending 进度、无正文超读、空与部分 EOF、每 poll IO 预算和写入直透。
`outbound::shadowsocks::plugin::obfs_reuse_memory_tests::` 以实际 Owner.open →
生产 prepare_ss_response → 完整 SsStream → bind，覆盖三 cipher×两 cover、
64 字节 duplex、双向各两份 64KiB、TX Pending 时完整 RX、一次 cover／target 及取消释放；
有限 Rust cover peer 不是执行官方 C／Go peer。
该模块的 `header_probe_plain_ss_` 显式为纯内存裸 SS 控制安装 HeaderIo，
不代表生产裸 SS 或未获限定的其它插件已支持该前缀适配；`header_probe_covered_ss_` 只使用一次真正的生产 prepare，不能双重聚合。
`http_cover_requires_both_upgrade_fields` 保留 Connection: Upgrade 与 Upgrade: websocket 的模型校验。
原有官方 SS codec、ss_framed、ShadowTLS 和 HTTP parent/cache 控制仍须独立回归；
这些内存检查不代替官方 peer、实际 TUN、吞吐或 phys_footprint 验收。

SS2022 无 early-data 的明文标准 WebSocket v2ray-plugin 单通道 mux 的纯内存过滤器
（`inbound-http,outbound-shadowsocks`）：
`outbound::connector::http_reuse_memory_tests::static_ss2022_v2ray_mux_` 包含三项测试；
真实 Config／SS／Dispatcher 覆盖三 cipher 的许可、字面端点／完整上游／物理限制与 Stop，
另保留 TLS、Gost、无 mux、HTTPUpgrade 及 fast-open 的15个构造负例，
以及三 cipher 真实解析 `path: /memory-mux/?ed=128` 的 early-data 拒绝复用控制。
`outbound::shadowsocks::plugin::v2ray_mux_reuse_owner_memory_tests::` 包含四项测试；
先单独运行 `v2ray_mux_owned_existing_fanout_control_handles_complete_ss_pending_fixture`
确认真实完整 SsStream 和既有 fanout 夹具，再运行其余三项实际 Owner.bind 测试。
其9／3／3个分支保留独立读写 Pending／唤醒、Stop-before-bind 四种 IO 零底层轮询、
单流 Drop 不取消父及兄弟流、tracker barrier 与取消轮询后实际 IO／weak owner 释放。
两组总共七项测试，重复选择同一 control 不增加唯一测试数量。
这些构造／owner 检查不执行 Owner.open／WS 握手、mux framing 或 SS 响应认证，
不代替首响应分片、HTTP cache、官方 peer、吞吐或 phys_footprint 验收。

SS2022 明文标准 WS 单通道 mux 的载体过滤器：
`outbound::shadowsocks::plugin::v2ray_mux_reuse_memory_tests::`。
三项测试通过真实并发 server WS 握手、actual Owner.open／prepare_ss_response／完整 SsStream／bind，
分别检查完整首响应前缀、两个合法 mux Data 记录分拆，以及一个 Data 记录跨两个完整 Binary Message。
各组依次收集三 cipher 的结果后统一判决，保持 64 字节 duplex、双向各两份 64KiB、
真实 TX Pending 时完整 RX 和原期限。每个 case 在分类成功、错误、timeout 或 unwind 前，
先验证真实 Owner.shutdown 返回、tracker closed／empty、两端 Raw Drop 和共享计数 Weak 释放；
不把取消或任意错误当作成功。有限 mux peer 的首回复为 Keep/Data，并保留普通无 Data KeepAlive、
正常 End 和 WS 关闭；不据此宣称 KeepAlive／End 携带 Data 或全部错误矩阵已验证。
实际限定无 early-data 的 WS mux 与 Obfs 在所有 feature 组合下均使用现有 59／91 字节前缀适配；
HTTP 复用资格和 child 绑定仍仅在 `inbound-http` 范围。
这些内存模型不是运行官方 Go mux server，也不代替真实完整负载与进程内存验收。

`ss_v2ray_mux_https_` 在 Apple 平台选择十项实际 SS／标准 WS mux 载体下的 H1/H2 cache 测试。
原八项在三 cipher 下保留原 native 规则，覆盖两个 POST、已提交第二次请求失败不重放、部分上传停止和早响应后退役；它们不启用 JS。
新增 `ss_v2ray_mux_https_h1_native_then_js_` 与 `ss_v2ray_mux_https_h2_native_then_js_` 各在三 cipher 下实际启用 request／response 脚本，两个完整 POST 仍共用一个经过认证的 SS／WS／上游 TLS 载体。
H1 脚本须先读到 native request header 和 response 正文 `changed`，再生成原站实际收到的 `transformed`、独立 JS request／response header 与最终正文 `Changed`。
H2 request 脚本须读到 native header 并使原站实际收到 `transformed`；response native 先把 `x-proof` 设为 `before-js`，只有脚本读到 native 正文 `from_origin` 后改回 `native` 才能通过原响应检查。
脚本未运行、失败回退或 native-only 均无法满足这些正文／header／原站见证；真实 TLS、原 HTTP 父级、cache、Stop／join 与实际 IO Drop 收据保持。
每条真实载体只发一次 mux New；SS 目标、WS 握手和实际 IO 销毁也有独立收据。
所有原 Obfs cache 测试保留同一默认载体；这组纯内存测试不代替完整下游 MITM 或实际压力窗口，非 Apple 构建只选择原八项。

VMess 固定明文 HTTP 首包伪装的纯内存过滤器（`inbound-http,outbound-vmess`）：
`outbound::connector::http_reuse_memory_tests::static_vmess_http_cover_` 包含实际 Config／VMess／ConnectorDispatcher 的四 cipher、空／单值头工厂，以及 TLS、多 URI／头值、完整静态路径和停止负控制。
`outbound::vmess::outbound::http_cover_reuse_owner_memory_tests::` 使用真实 prepare／finish／connect_stream 和完整 VMess 流，检查独立读写 Pending 的 Stop 唤醒、整流关闭、Stop-before-finish、兄弟 child 与实际 raw／waker Weak 释放；24 个双向等待分支不计作24个独立测试。受控 IO 只提供有限 HTTP200 头或尚无 cover 响应，未伪造 VMess 响应认证成功；这些测试不证明完整认证 peer、业务 HTTP cache、真实 TUN、吞吐或 phys_footprint。既有 official-vector 响应认证、原建链期限、计数回绕和 H1/H2 cache 回归仍须独立保留。

`outbound::vmess::stream::http_cover_reuse_memory_tests::` 包含八项有界真实载体测试，四 cipher 共36个分支：从真实 wire 验证 UUID／AuthID／请求 AEAD、目标和 FNV，再检查双向两份64KiB、错误 UUID、坏响应认证（含 None）和兄弟流停止。KDF／AEAD 原语、地址解析与 BodyCodec 接缝复用 Core，不代替独立官方服务端互通。
单字节分支分别覆盖先写后读、先挂起响应再接受上传的进度，显式 flush 正控，以及 RX 已有数据而 TX flush Pending 的优先级。部分上传后读取会推动已接受写缓存，非零写入会通知此前挂起的 reader；这两点只用于固定明文 HTTP 载体。整流关闭控制先消费该进度通知并真实重挂读等待，再独立观察关闭唤醒。所有原始流、tracker 和 Weak 释放仍在判决前完成。

VMess 明文、单 URI／单值头 HTTP 首包伪装的完整载体与业务缓存组合过滤器：
`vmess_http_cover_https_h1_`、`vmess_http_cover_https_h2_`（`inbound-http,outbound-vmess`）。
两组各五项：四项保留原 native POST 的完整双请求、已提交第二请求失败不重放、活动部分上传 Stop、早响应后退役；Apple 另有一项实际 request／response 脚本的 native→JS 见证。每项顺序覆盖 Auto、None、AES128、ChaCha 四 cipher；Apple 共10项／40个分支，其它平台8项／32个分支，分支数不冒充独立测试数。
可选 VMess factory 默认 None，SS 和裸 duplex 原路径保留；同时配置两个 factory 明确拒绝。真实 VMess 请求／目标由有界内存 peer 从 wire 认证，后续仍经过原 TLS、Plan/key、HTTP 父级和 H1/H2 cache；该模型复用明确的 test-only BodyCodec 接缝，不是运行官方 Go server。H2 早响应继续实际发起退役后的 GET、要求两个认证载体，其余模式要求一个。
所有内容／脚本错误、超时和展开均先走真实节点 shutdown、tracker／原父级／driver／peer join，随后读取值快照，丢弃 fixture 与 factory 并检查 Weak，再判定结果。正常模式要求真实认证、一次 cover、raw 双端释放、节点取消／closed／wait-returned／tasks-empty 计数完整，认证失败计数为0；JS 跳过、回退或 native-only 不能满足原站正文和 header 见证。
这些测试从已终止下游 TLS 的 HTTP 上下文进入，保留实际上游 TLS；不代签完整下游 MITM、真实选路／物理出口、官方 peer、TUN、吞吐或 phys_footprint。R1 的实际 Config／ConnectorDispatcher 结构证明、R2 的独立等待者取消，以及既有路由变更、H2并发、认证／期限和计数回绕回归仍需独立保留。
