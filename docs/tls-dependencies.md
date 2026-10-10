# TLS 依赖与发布

版本、Git revision 和 registry 校验值以 Cargo.toml/Cargo.lock 为准。
[Tests workflow](../.github/workflows/test.yml) 的 `Audit the locked TLS dependency graph`
统一审查实际依赖图，平台构建使用 `--locked`。

| 用途 | 来源与约束 |
| --- | --- |
| 普通 TLS、QUIC、WebPKI | 官方 rustls/tokio-rustls，ring provider；rustls-native-certs 只读取可用平台根，不替换验证器 |
| 命名 ClientHello、REALITY、JLS、ShadowTLS v3 | YuanDevTeam/boring，release 分支及锁定 revision |
| SS 2022 | 官方 shadowsocks，仅 `aead-cipher-2022` |
| Encryption | 同一 boring 的 X25519、ML-KEM、AEAD、AES-CTR；官方 blake3 |
| 静态 ECH | 官方 hpke + rustls HPKE trait，命名模板使用 boring ECH 接口 |
| Provider AGE | 官方 age/age-core 的 armor、MAC 和 STREAM；Hybrid 身份用官方 hpke XWing，关闭插件与 CLI |

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

## 原生构建

构建需要 C/C++、CMake、Perl 和 libclang。Apple 最终链接 libc++；Android 随库打包
同 ABI、同 NDK 的 `libc++_shared.so`。

构建与发布入口见 [编译与发布](../scripts/README.md)。
