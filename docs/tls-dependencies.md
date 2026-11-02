# TLS 依赖与发布

版本、Git revision 和 registry 校验值以 Cargo.toml/Cargo.lock 为准。
[Tests workflow](../.github/workflows/test.yml) 的 `Audit the locked TLS dependency graph`
统一审查实际依赖图，平台构建使用 `--locked`。

| 用途 | 来源与约束 |
| --- | --- |
| 普通流 TLS、WebPKI | 官方 rustls/tokio-rustls，ring provider；rustls-native-certs 只读取可用平台根，不替换验证器 |
| Quinn QUIC | HY2、TUIC、DoQ、XHTTP H3 和 DoH/H3 使用官方 registry Quinn 0.11.12 / quinn-proto 0.11.19、rustls/ring；窗口与数据报预算通过公开 API 和 Core 包装处理；Linux DIRECT 的有限 GSO/ECN 使用同一受保护 fd 的 Linux ancillary API，不另建 socket |
| Quinn HTTP/3 | HY2 认证、XHTTP 和 DoH/H3 使用 registry h3 0.0.8 + h3-quinn 0.0.10，MIT；HY2 认证与业务共用同一 Quinn 连接，XHTTP/DNS 的取消和帧预算由 Core 公开 trait 包装处理，不修改上游源码 |
| quiche HTTP/3 | TrustTunnel 和 MASQUE 使用 registry quiche 0.30.0，BSD-2-Clause；自有低层驱动使用公开 API，共用同一 boring/boring-sys，不启用 quiche FFI、qlog 或另一套 TLS 来源 |
| QUIC 拥塞控制 | HY2/TUIC 保留其 Quinn 控制器；XHTTP/DoH 使用 Quinn 原生默认控制器，TrustTunnel/MASQUE 使用 quiche 原生控制器，配置映射见 [出站](outbounds.md) |
| MASQUE 密钥 TLS | H2 使用 rustls/ring，H3 使用 quiche + 同一 boring；ECDSA 身份、逐证书 SPKI pin 与握手签名认证保持独立于 WebPKI |
| Controller 随机服务端身份 | 官方 rsa 仅生成 RSA 2048 密钥；rcgen + ring 签发自签证书，实际 TLS 和握手签名仍由 rustls + ring 处理；随 Controller 入站 feature 启用 |
| 业务 HTTPS 处理 | rcgen + ring 使用宿主提供的 CA 签发短期叶证书；官方 x509-parser 校验 CA、密钥匹配与有效期，不生成根 CA 或安装信任，见 [HTTP 处理](http-processing.md) |
| 命名 ClientHello、REALITY、JLS、ShadowTLS v3 | YuanDevTeam/boring；开发使用同一 fork 的本地 path，PR 和发布使用固定 commit |
| SS 2022 | 官方 shadowsocks，仅 `aead-cipher-2022` |
| Mieru 分段认证 | UDP 低熵编码及 TCP 保留官方 RustCrypto chacha20poly1305 0.11.0；其余 UDP 复用同一 boring/boring-sys 的安全可变 XChaCha20-Poly1305 原位 AEAD，均用 ring PBKDF2；Mieru 不使用 TLS，不引入另一套 TLS provider |
| Encryption | 同一 boring 的 X25519、ML-KEM、AEAD、AES-CTR；官方 blake3 |
| 静态/动态 ECH | rustls 使用官方 hpke + 公开 HPKE trait；命名模板及 quiche H3 使用同一 boring ECH selector |
| Provider AGE | 官方 age/age-core 的 armor、MAC 和 STREAM；Hybrid 身份用官方 hpke XWing，关闭插件与 CLI |

Quinn 与 quinn-proto 均来自官方 registry，使用其原生拥塞实现。
CI 核对锁定版本、registry 来源、wrapper 依赖边及 rustls/ring provider；不维护 protocol fork。

AWS-LC 只用于 `shadowsocks → shadowsocks-crypto → aws-lc-rs → aws-lc-sys`，
不用于 TLS/REALITY。禁止 FIPS、2022-extra 和第二套 REALITY 后端。
BoringSSL 子模块保持原样，fork 补丁通过 feature 控制。

AGE 使用获准的官方兼容稳定版本 `age 0.11.5` 与 `age-core 0.11.0`。
其 0.12 系列强制依赖的旧 ML-KEM 与当前 `hpke 0.15.1` 的正式 KEM 依赖不兼容；
此版本例外仅限上述两项，Hybrid 保持最新稳定 HPKE/RustCrypto 路径。

## 开发与升级

1. 本地开发将 boring、tokio-boring、boring-sys 的直接／开发依赖，以及
   `[patch.crates-io]` 中 quiche 使用的 boring/boring-sys，统一指向
   `../boring/{boring,tokio-boring,boring-sys}` 对应的相对 path；保留版本与 feature
   约束并更新 Cargo.lock。
2. 发起或更新 Vole PR 前，检查 Boring checkout 的源码变更和拟引用提交的公开状态。
   若所需自有修改尚未提交、推送或进入 Boring PR，先整理提交并推送，发起或更新
   对应 Boring PR，确认所需变更已包含于可公开获取的 commit。
3. 将三个 crate 的直接／开发依赖和两个 patch 一起切为相同 Git URL 与 `rev`，
   使用完整 40 位 commit SHA；更新 Cargo.lock，CI 以清单中的 `rev` 核对实际来源。
   可以引用已推送的 Boring PR head commit，来源不绑定分支或 tag。
4. 在不依赖本地 fork 的 checkout 执行 locked 构建，核对来源、provider/feature graph，
   运行受影响的 TLS、协议和平台回归。回退同样通过新提交恢复已验证的锁文件。

`stream-security` 由 VMess/Trojan/AnyTLS/VLESS 共同启用，不依赖另一个出站协议；
Vision 仍单独随 VLESS 编译。ShadowTLS 由 `shadow-tls-v3` 独立控制。
普通 TLS 与 REALITY 使用独立的不可变连接器。REALITY/JLS 握手、临时密钥和原生
验证边界见 [REALITY](reality-wire-protocol.md)；模板与证书策略见 [TLS 指纹](tls-client-fingerprint.md)。
Encryption 的二进制 context 使用 [薄 FFI](../crates/vole-blake3-raw/README.md) 调用
官方 BLAKE3 C API；平台脚本通过官方 vcpkg 准备静态包，编译时隔离符号，不内置第三方源码。

本地 path 验证需要配套 fork checkout，不代表固定 Git commit 的独立构建通过。
PR 和发布验收使用实际锁定 commit；直接依赖、quiche patch、锁文件与 CI 必须一致。

## 原生构建

构建需要 C/C++、CMake、Perl 和 libclang。Apple 最终链接 libc++；Android 随库打包
同 ABI、同 NDK 的 `libc++_shared.so`。

构建与发布入口见 [编译与发布](../scripts/README.md)。

ECH 接收算法按实际后端区分。rustls HPKE adapter 支持 X25519、P-256/P-384/P-521、
ML-KEM-768/1024、X-Wing、ML-KEM-768+P-256 和 ML-KEM-1024+P-384；
KDF 为 HKDF-SHA256/384/512、SHAKE128/256，AEAD 为 AES128/256-GCM 或 ChaCha20-Poly1305。
使用官方 hpke 的 `nistp/mlkem/shake` feature 和公开 HPKE trait，不增加 TLS fork。
命名模板与 quiche H3 的原生 ECH selector 只接收 X25519/HKDF-SHA256 和上述三种 AEAD。
静态和动态来源均按最终后端重新选择；没有兼容配置则明确失败，不关闭 ECH、不降级或重拨。
quiche H3 在发送首包前通过公开 SSL 接口配置 ECH，握手后检查实际接受状态与 ALPN，
通过后才开放 HTTP 请求。不能以原生通用 HPKE API 的值域推断 ECH selector 支持。
