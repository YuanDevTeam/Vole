# Vole

<p align="center">
  English · <a href="./readme/README.zh_CN.md">简体中文</a> · <a href="./readme/README.ru.md">Русский</a>
</p>

Vole is a Rust proxy core for VPN clients and local proxies, available as native libraries and a foreground CLI. It routes TCP/UDP traffic through direct connections, proxy nodes, groups, and chains, with integrated DNS, GeoData, and a cross-platform TUN data plane.

Configuration uses **Mihomo-compatible YAML for the supported feature set**. Vole focuses on client-side capabilities rather than implementing every Mihomo field or its complete Dashboard API.

## What Vole can do

- **Accept application and VPN traffic:** HTTP forwarding, CONNECT and Upgrade; SOCKS5 CONNECT and UDP ASSOCIATE; host-provided IPv4/IPv6 TUN packets.
- **Route traffic:** rule/global/direct modes; domain, source/destination IP and port, TCP/UDP, GeoSite/GeoIP, rule providers and logical rules, with DIRECT and REJECT actions.
- **Choose and chain proxies:** nested select/url-test/fallback/load-balance groups, health checks and persistent selection; `dialer-proxy` chains can reference nodes or groups. Existing connections retain their selected path.
- **Handle DNS:** hosts, separate bootstrap/node/direct resolvers, UDP/TCP/DoH/DoT, domain/GeoSite/rule-set policies, fallback, bounded caching, redir-host and persistent fake-IP mappings; intercept configured TUN DNS targets.
- **Identify traffic for routing:** HTTP/TLS sniffing for TUN and mixed TCP, QUIC sniffing for TUN UDP, with force/skip conditions and configurable destination override. ICMPv4/ICMPv6 Echo is answered locally.
- **Manage routing assets:** HTTP/file/inline proxy and rule providers, dynamic groups, filters and overrides; YAML/Text and domain/ipcidr MRS. GeoData loads complete referenced categories and supports routed downloads and periodic updates. Failed updates retain usable state. See [GeoData boundaries](docs/geodata.md#内存与安全边界).
- **Expose client controls:** group/resource state, connection snapshots and cancellation, rule counters, effective configuration and bounded DNS diagnostics, alongside TUN traffic metrics and isolated node/chain delay measurement.

## Proxy protocols

All ten protocols below are enabled in the default build. HTTP CONNECT itself is TCP-only; native UDP support for other protocols is configured per node.

| Protocol | Capabilities |
| --- | --- |
| [VLESS](docs/vless.md) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP first-packet camouflage, legacy H2, [XHTTP H1/H2/H3](docs/xhttp.md); Vision, Encryption, REALITY, JLS and static ECH in supported combinations |
| [VMess AEAD](docs/outbounds.md#vmess-aead) | TCP, WebSocket / HTTPUpgrade, gRPC, HTTP first-packet camouflage and legacy H2; TCP/UDP, plaintext or standard TLS |
| [Trojan](docs/outbounds.md#trojan) | TCP/UDP over TLS TCP, WebSocket / HTTPUpgrade or gRPC |
| [Shadowsocks 2022](docs/outbounds.md#shadowsocks-2022) | TCP/UDP; AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; AES identity chains; optional strict ShadowTLS v3 TCP wrapping and UoT v2 |
| [AnyTLS](docs/outbounds.md#anytls) | TLS sessions and UDP over TCP v2 |
| [HTTP / HTTPS CONNECT](docs/outbounds.md#http--https-connect) | TCP CONNECT, optional proxy authentication and TLS |
| [SOCKS5](docs/outbounds.md#socks5) | CONNECT and UDP ASSOCIATE, with optional username/password authentication |
| [Hysteria2](docs/outbounds.md#hysteria2) | QUIC TCP/UDP, bandwidth control, Salamander, port hopping and mTLS |
| [TUIC v5](docs/outbounds.md#tuic-v5) | QUIC TCP/UDP, native/quic UDP relay modes and selectable congestion control |
| [WireGuard](docs/outbounds.md#wireguard) | TCP/UDP over standard WireGuard, with a user-space IP stack |

The shared [sing-mux wrapper](docs/xhttp.md#通用-sing-mux) supports all enabled node protocols. It provides TCP and, with `only-tcp: false`, UDP over the node's ordinary TCP path. The peer must provide sing-mux decoding; a normal HTTP/SOCKS5 listener does not automatically decode it.

Standard TLS connections support certificate verification and SHA-256 certificate pins. Applicable TCP TLS paths can use Chrome, Firefox or Safari ClientHello templates; `client-fingerprint` is independent of the certificate `fingerprint`. See [TLS profiles and certificate policy](docs/tls-client-fingerprint.md) for the exact names and combinations. These features do not promise indistinguishability from a browser or unrestricted protocol combinations.

SS2022 uses the unmodified official Rust library; its known empty-first-write/server-first and padding risks remain documented in the [Shadowsocks contract](docs/outbounds.md#shadowsocks-2022).

## Mihomo-style configuration

Use the familiar `proxies`, `proxy-groups`, `rules`, `dns`, `mixed-port` and `tun` structures. For example:

```yaml
mixed-port: 1080
allow-lan: false

proxies:
  - name: edge
    type: anytls
    server: proxy.example.com
    port: 443
    password: replace-with-your-password
    client-fingerprint: chrome
    udp: true

proxy-groups:
  - name: Proxy
    type: select
    proxies: [edge, DIRECT]

dns:
  enable: true
  nameserver:
    - "udp://223.5.5.5:53#DIRECT"

rules:
  - GEOSITE,cn,DIRECT
  - GEOIP,cn,DIRECT,no-resolve
  - MATCH,Proxy
```

Replace the example endpoint and credentials. GeoSite/GeoIP rules use assets under `<dataDir>/geodata`; missing required assets are downloaded through the configured route, and affected rules remain unavailable until loading succeeds. See the [complete configuration reference](docs/config.yaml) and [GeoData behavior](docs/geodata.md).

`mixed-port` shares one TCP port between HTTP and SOCKS5 and enables SOCKS5 UDP on the same port. `allow-lan` controls binding independently of `authentication`: omitting `authentication` or using `[]` allows unauthenticated access on either loopback or wildcard addresses; configured credentials are checked by both HTTP and SOCKS5. Top-level `port`, `socks-port`, `udp` and `listeners` are rejected; proxy-node `port` and `udp` keep their outbound meanings.

Compatibility covers the documented subset of Mihomo fields. Unknown fields and unsupported combinations are rejected. See [current compatibility scope](docs/mihomo-compatibility.md) and the individual contracts for platform and protocol limits.

Library hosts start an instance with inline `configYaml`; TUN device, file descriptor, MTU, DNS interception and UDP timeout belong to the `tun` configuration. Platform callbacks remain runtime-local. The CLI sends options through the same Invoke API, whose foreground operation reads the file selected by `-f`. Linux core-owned TUN can configure automatic routing and systemd-resolved DNS; borrowed descriptors and App platform networks remain host-owned.

## CLI

Build the foreground executable with `uv run --project scripts --locked vole-scripts build cli`. Windows CLI builds always use Wintun; FFI builds use `build windows --backend wintun|uwp` (default: UWP). Tagged releases publish CLI and FFI together, with Windows CLI using Wintun and FFI offering both backends. See [build scripts](scripts/README.md) for targets and package contents.

```sh
vole -f /path/to/config.yaml
vole -d /path/to/data -f ./config.yaml
vole -t -f ./config.yaml
```

`-d` selects the configuration/data directory; `-f` selects the configuration file independently. Relative paths use the launch working directory. Without `-f`, Vole reads `<data-dir>/config.yaml`; the directory defaults to the user's `.config/vole`, with Mihomo-style `XDG_CONFIG_HOME` fallback. `-f -` reads standard input. `VOLE_HOME_DIR` / `VOLE_CONFIG_FILE` provide environment defaults; explicit flags override them. `-t` only validates configuration, `-v` prints version/build identity, and `-h` prints help. See [CLI and tag releases](docs/cli.md).

## Platforms and integration

| Platform | TUN integration |
| --- | --- |
| iOS / macOS | Host-provided utun file descriptor; macOS can also open/create a native utun |
| tvOS 17+ | Host-provided utun file descriptor; ARM64 device and simulator targets |
| Android | `VpnService` file descriptor with outbound socket protection |
| Linux | Real single-queue raw-IP TUN from a borrowed fd or a core-opened device; core-owned Linux TUN supports automatic routes and system DNS |
| Windows | Mutually exclusive `windows-wintun` desktop and `windows-uwp` packaged Provider/Session Host builds sharing the core |

Vole provides native libraries and a foreground CLI. Apple, Android and Windows hosts own system network configuration and application lifecycle; Linux core-owned TUN additionally supports automatic routes and system DNS. Unix hosts own the original TUN descriptor; Vole uses and closes its own duplicate. Apple's public packetFlow API does not guarantee raw-fd access, so actual Network Extension integration and device validation remain host responsibilities. See [TUN integration](docs/tun-platform.md) and [platform acceptance boundaries](docs/acceptance.md).

Desktop Wintun loads a host-provided `wintun.dll` from the process executable's directory. The host configures interface addresses, DNS, routes and physical egress; Windows Wintun device validation is separate from the existing packaged VPN results. See [CLI usage and tag releases](docs/cli.md) for command-line delivery.

The cross-platform C ABI accepts JSON requests through Invoke API:

```c
char *VoleInvoke(const char *request_json);
void VoleFree(char *response);
```

One public instance follows `initialize → createInstance → start(configYaml) → stop → destroyInstance`; preparation is internal to `start`. `validateConfig` requires no initialization. The CLI uses the explicit foreground Invoke operation for files, environment defaults, signals and cleanup. The API also provides state queries, GeoData status and delay measurement. See [Invoke API](docs/invoke-api.md), [Controller API](docs/controller-api.md) and the [Windows integration example](example/windows-uwp/README.md).

## Benchmark

[**Vole / Mihomo TUN benchmark**](https://github.com/YuanDevTeam/container-benchmark) contains the reproducible setup, measured results and comparison charts for both cores under the same native Linux TUN environment.

The benchmark project also owns protocol interoperability (`interop`) and memory-pressure runs (`stress`), with an explicit `--source vole=PATH` checkout. Vole's own scripts only compile core and platform artifacts.

Workloads, input assets and measured results are maintained in the benchmark project.
See [acceptance boundaries](docs/acceptance.md) for the scope of build, network and device validation.

## Documentation

- [Documentation index](docs/README.md)
- [Configuration reference](docs/config.yaml)
- [Mihomo compatibility scope](docs/mihomo-compatibility.md)
- [Core and platform builds](scripts/README.md)
- [CLI usage and tag releases](docs/cli.md)
- [Core regression tests](tests/README.md)
- [Resource policy](docs/runtime-resource-policy.md)
- [Acceptance and known limitations](docs/acceptance.md)

## Credits

Vole builds on and learns from public dependencies, protocol implementations and platform references:

- TUN dependencies: the local [`vole-netstack`](crates/vole-netstack/README.md) uses [smoltcp](https://github.com/smoltcp-rs/smoltcp); Unix and Windows Wintun packet I/O use [tun-rs](https://github.com/tun-rs/tun-rs) (Apache-2.0).
- WireGuard: [boringtun](https://github.com/cloudflare/boringtun) (BSD-3-Clause), without host-device, FFI or JNI features.
- [Wintun](https://www.wintun.net/): the runtime DLL is supplied by the host, not bundled. The upstream [API header](https://github.com/tun-rs/tun-rs/blob/2.8.11/src/platform/windows/tun/wintun.h) included by tun-rs is copyright 2018–2021 WireGuard LLC, licensed `GPL-2.0 OR MIT`; distribution of the linked API bindings must retain its copyright and MIT alternative license notice.
- Name expressions: [fancy-regex](https://github.com/fancy-regex/fancy-regex) (MIT), used only for bounded provider/group lookaround and backreferences.
- Networking and routing references: [clash-rs](https://github.com/Watfaq/clash-rs), [netstack-smoltcp](https://github.com/cavivie/netstack-smoltcp), [Mihomo](https://github.com/MetaCubeX/mihomo), [Xray-core](https://github.com/XTLS/Xray-core) and [Leaf](https://github.com/eycorsican/leaf). These reference projects are not netstack dependencies.
- TLS and Shadowsocks: [rustls](https://github.com/rustls/rustls), [boring](https://github.com/cloudflare/boring), [BoringSSL](https://boringssl.googlesource.com/boringssl/) and [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust). Derived replay-window code retains its [MIT notices](src/outbound/shadowsocks/packet_window.rs).
- Windows integration: [windows-rs](https://github.com/microsoft/windows-rs), [UWP VPN Plugin Sample](https://github.com/microsoft/UwpVpnPluginSample), [wireguard-uwp-rs](https://github.com/luqmana/wireguard-uwp-rs), [Maple](https://github.com/YtFlow/Maple) and [YtFlowCore](https://github.com/YtFlow/YtFlowCore).

## License

[MIT](LICENSE).
