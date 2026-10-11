# REALITY V1 客户端协议

本文定义 Vole 的 REALITY V1 客户端线上行为。它不是通用 REALITY 规范。经典模式为默认，可显式要求混合密钥交换。可选的四套 ClientHello 模板及混合兼容边界见 [TLS 指纹](tls-client-fingerprint.md)。

## 版本边界

当前 REALITY 实现基于自有 boring 5.2.0 fork 的原生 BoringSSL 扩展。线上行为由本文和 fork 内的确定性测试向量共同约束。升级 TLS 后端、加密提供方或握手字节时，必须重新验证普通 TLS、REALITY、并发、取消和目标平台构建。

V1 只支持：

- 客户端模式；
- TLS 1.3；
- 经典 X25519，或显式要求 X25519MLKEM768 的 TLS 密钥交换；
- classic Ed25519 临时证书认证；
- 0–8 字节 short ID，在线上右侧补零到 8 字节；
- BoringSSL 原生握手和加密实现。

不支持 REALITY 服务端、TLS 1.2 协商、QUIC 传输、实际 ECH、HelloRetryRequest、会话恢复、0-RTT 或 `fp`。ECH GREASE 与实际 ECH 不同。收到 HRR 或 REALITY 认证失败时立即终止，不降级为普通 WebPKI。

## ClientHello 认证

每次 REALITY 认证绑定本次原生 SSL 握手中的一份真实 X25519 临时私钥，同时用于：

1. TLS 1.3 ClientHello 的实际 X25519 share，或混合 share 中的 X25519 分量；
2. 与配置中的服务端静态 X25519 公钥执行 ECDH。

Vole 不能读取该私钥，也不能为两个用途生成不同密钥。

原生封装按实际 GroupID 找到唯一 X25519 share，不依赖 share 下标。Firefox 可保留
额外 P-256 share，但认证始终绑定同一 X25519 临时私钥。Chrome133 的普通 TLS
ML-KEM group/share 在 classic REALITY 中裁剪。显式混合模式保留模板中的真实混合 share；
无命名指纹时只提供混合 share。若同时存在独立 X25519，优先用它派生认证，否则使用
实际混合 share 内的 X25519 分量，与 Mihomo 的认证取值一致。
重复/缺失认证 share、低阶点均失败。显式混合模式还在 ServerHello 处理时要求
实际选择 group 4588，经典组或 HRR 立即失败，不重新发起经典握手。REALITY 身份
认证仍是经典 X25519/Ed25519，不能将混合 TLS 密钥交换称为后量子身份认证。

ClientHello 的 legacy session ID 固定为 32 字节。生成密文前先把该字段清零，再编码完整 TLS Handshake `ClientHello`，将其作为 AES-GCM 的 AAD。

`signature_algorithms` 保留所选模板的列表；REALITY 不强行加入 Ed25519。原生实现仅在临时证书先通过 REALITY HMAC 认证后，允许它的 Ed25519 CertificateVerify，并仍验证签名。该局部例外不放宽普通 TLS 的签名算法检查。

命名指纹保留 TLS1.2 的版本/cipher/扩展声明（Safari 的 TLS1.0/1.1 仍裁剪），
而非先用 TLS1.3-only 的通用编码过滤模板。原生 REALITY 在 ServerHello 阶段独立拒绝
TLS1.2，且仍禁止恢复、0-RTT 和普通证书兜底；声明并不代表允许降级协商。

session ID 明文前 16 字节为：

```text
offset  size  value
0       3     客户端版本，当前为 26.7.11
3       1     保留字节 0
4       4     Unix 秒，uint32 大端序
8       8     short ID，右侧补零
```

密钥派生：

```text
auth_secret = X25519(client_ephemeral_private, server_static_public)
auth_key    = HKDF-SHA256(auth_secret,
                          salt=client_random[0..20],
                          info="REALITY",
                          length=32)
nonce       = client_random[20..32]
session_id  = AES-256-GCM-Seal(auth_key, nonce,
                               plaintext[0..16],
                               aad=zero-session-id ClientHello)
```

输出为 16 字节密文和 16 字节 GCM tag。低阶点、全零共享密钥、时钟失败、重复封装或缺少连接状态都会使握手失败。

## 服务端证书认证

服务端必须只发送一张 DER X.509 证书。解析输入上限为 16 KiB，只接受规范的 definite-length DER、RFC 5280 字段顺序、无参数 Ed25519 `AlgorithmIdentifier`、32 字节 SPKI 公钥和 64 字节外层签名。

验证顺序：

1. 从 DER 结构读取 Ed25519 公钥和外层 `signatureValue`；
2. 常数时间比较 `signatureValue` 与 `HMAC-SHA512(auth_key, ed25519_public_key)`；
3. 把通过 HMAC 的同一公钥绑定到当前连接；
4. 使用该公钥验证 TLS 1.3 `CertificateVerify`，签名算法必须为 Ed25519；
5. 无论成功或失败都立即消费认证状态，禁止再次使用。

真实站点证书、中间证书、错误 HMAC、错误 DER/SPKI、错误 `CertificateVerify` 和缺失状态全部失败。Vole 不提供 WebPKI 或 spider fallback。

## 状态与资源

共享连接器只保存不可变的服务端公钥、short ID、客户端版本和模板策略。临时私钥、ECDH 结果、`auth_key` 和已认证公钥只存在于单个连接中，不使用全局表、跨连接锁或共享认证槽位。

连接取消、失败或释放时清零临时私钥、共享密钥和 `auth_key`。证书解析深度和输入大小固定，不依据对端长度创建无界容器。fork 不创建线程、异步任务、连接池或队列。

## 固定向量

boring fork 的测试固定：

- RFC 7748 X25519 私钥、公钥和共享密钥；
- 清零 session ID 的 ClientHello AAD、HKDF 结果和 32 字节 REALITY session ID；
- Ed25519 SPKI、证书 HMAC 和 TLS 1.3 `CertificateVerify`；
- 截断或非规范 DER、错误 HMAC、错误签名、缺失状态、低阶公钥和 HRR 负例；
- 多配置并发和连接状态隔离。

Vole 的互操作测试还覆盖 XHTTP 模式、取消重连、错误 key/short ID 和普通 TLS 回归。实际执行范围见 [验收矩阵](acceptance.md)，依赖发布要求见 [TLS 依赖](tls-dependencies.md)。
