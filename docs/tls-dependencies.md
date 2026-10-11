# TLS 依赖与发布

版本、Git revision 和 registry 校验值以 Cargo.toml/Cargo.lock 为准。
[Tests workflow](../.github/workflows/test.yml) 的 `Audit the locked TLS dependency graph`
统一审查实际依赖图，平台构建使用 `--locked`。

| 用途 | 来源与约束 |
| --- | --- |
| 普通 TLS、QUIC、WebPKI | 官方 rustls/tokio-rustls，ring provider；rustls-native-certs 只读取可用平台根，不替换验证器 |
| QUIC 状态机 | registry Quinn 0.11.12 + 仓库内 quinn-proto 0.11.19；窗口、DATAGRAM frame 限额及可选逐包拥塞反馈/pacing 补丁，保留官方许可证/来源 |
| 新协议 QUIC 拥塞控制 | [Google QUIC 原生算法移植](../src/transport/quic/congestion/README.md)，保留 BSD-3-Clause；Meta v1/v2 参数适配独立实现，现有 HY2/TUIC 控制器保持原样 |
| HTTP/3 | 官方 h3 0.0.8 的[仓库内源码](../vendor/h3/README.vole.md)，修正普通 CONNECT 伪头；官方 h3-quinn 0.0.10 adapter，保留 MIT 许可与现有 provider |
| Controller 随机服务端身份 | 官方 rsa 仅生成 RSA 2048 密钥；rcgen + ring 签发自签证书，实际 TLS 和握手签名仍由 rustls + ring 处理；随 Controller 入站 feature 启用 |
| 命名 ClientHello、REALITY、JLS、ShadowTLS v3 | YuanDevTeam/boring，同一 fork 的本地 development path；发布门禁仍要求 release 分支及批准 revision |
| SS 2022 | 官方 shadowsocks，仅 `aead-cipher-2022` |
| Mieru 分段认证 | 官方 RustCrypto chacha20poly1305 0.11.0 + ring PBKDF2；不使用 TLS 或另一套 TLS provider |
| Encryption | 同一 boring 的 X25519、ML-KEM、AEAD、AES-CTR；官方 blake3 |
| 静态/动态 ECH | 官方 hpke + rustls HPKE trait；指纹模板使用 boring ECH selector |
| Provider AGE | 官方 age/age-core 的 armor、MAC 和 STREAM；Hybrid 身份用官方 hpke XWing，关闭插件与 CLI |

QUIC 的受影响 protocol crate 通过 root `[patch.crates-io]` 指向
[vendor/quinn-proto](../vendor/quinn-proto/README.vole.md)。完整官方源、MIT/Apache 许可证和来源记录
保留；CI 核对版本、仓库内路径、wrapper 依赖边及 rustls/ring provider。升级须重新核查官方
稳定版本/校验值并审查本地补丁；不修改 registry 缓存或 Quinn wrapper。

AWS-LC 只用于 `shadowsocks → shadowsocks-crypto → aws-lc-rs → aws-lc-sys`，
不用于 TLS/REALITY。禁止 FIPS、2022-extra 和第二套 REALITY 后端。
BoringSSL 子模块保持原样，fork 补丁通过 feature 控制。

AGE 使用获准的官方兼容稳定版本 `age 0.11.5` 与 `age-core 0.11.0`。
其 0.12 系列强制依赖的旧 ML-KEM 与当前 `hpke 0.14.1` 的正式 KEM 依赖不兼容；
此版本例外仅限上述两项，Hybrid 保持最新稳定 HPKE/RustCrypto 路径。

## 开发与升级

1. 本地开发可将 boring、tokio-boring、测试用 boring-sys 一起切为同一自有 fork 的
   相对 path，保留版本与 feature 约束并更新 Cargo.lock。
2. 发起或更新 PR 前，将 fork 改动发布至 YuanDevTeam/boring 的 `release`，三个 crate
   一起切回 Git release 来源；更新锁文件和 CI 批准 revision。
3. 在不依赖本地 fork 的 checkout 执行 locked 构建，核对来源、provider/feature graph，
   运行受影响的 TLS、协议和平台回归。回退同样通过新提交恢复已验证的锁文件。

普通 TLS 与 REALITY 使用独立的不可变连接器。REALITY/JLS 握手、临时密钥和原生
验证边界见 [REALITY](reality-wire-protocol.md)；模板与证书策略见 [TLS 指纹](tls-client-fingerprint.md)。
Encryption 的二进制 context 使用 [薄 FFI](../crates/vole-blake3-raw/README.md) 中未修改的
官方 BLAKE3 C 源码，保留其来源、许可证和符号隔离。

本地开发统一使用 `../boring/{boring,tokio-boring,boring-sys}`，当前原生实现为本地提交
`4bac76121f259adcdb829f56ba52e864d10eaef5`。此来源需要配套 fork checkout，不是独立可移植
Git 构建；未发布该提交。CI 的公开 Git 来源及批准 revision 门禁保持原样，本地 path 验证
不代表发布门禁通过。发布前仍须按上述流程恢复三个 crate 的统一 Git 来源。

## 原生构建

构建需要 C/C++、CMake、Perl 和 libclang。Apple 最终链接 libc++；Android 随库打包
同 ABI、同 NDK 的 `libc++_shared.so`。

构建与发布入口见 [编译与发布](../scripts/README.md)。

ECH 接收算法按实际后端区分。rustls HPKE adapter 支持 X25519、P-256/P-384/P-521、
ML-KEM-768/1024、X-Wing、ML-KEM-768+P-256 和 ML-KEM-1024+P-384；
KDF 为 HKDF-SHA256/384/512、SHAKE128/256，AEAD 为 AES128/256-GCM 或 ChaCha20-Poly1305。
使用官方 hpke 的 `nistp/mlkem/shake` feature 和公开 HPKE trait，不增加 TLS fork。
命名模板的原生 ECH selector 仍只接收 X25519/HKDF-SHA256 和上述三种 AEAD；
不能以原生通用 HPKE API 的值域推断 ECH selector 支持。
