# Project Overview

Vole is a standalone Rust proxy core with native libraries and an optional foreground CLI. The native library contract is the JSON Invoke API, with no API or configuration revision fields. The `invoke` feature owns the shared request handler; `cli` and `ffi` are its command-line and native transports. The CLI parses flags, calls Invoke, renders responses, and sets exit status without requiring C ABI or Windows package entry points. Runtime configuration uses the strict schema documented in `docs/config.yaml`; native callers pass it inline as `configYaml` / `configYamls`; the explicit Invoke `foreground` operation owns bounded file/stdin reads, environment/path defaults, signals, and cleanup for CLI use. YAML does not contain `default-proxy`. Business proxy listeners use only `mixed-port`: shared HTTP/SOCKS5 TCP and SOCKS5 UDP require both inbound features. Top-level `port`, `socks-port`, `udp`, and `listeners` are rejected; proxy-node `port` and `udp` retain their outbound semantics. `allow-lan` and `authentication` are independent; omitted or empty authentication leaves both loopback and wildcard bindings unauthenticated. Public lifecycle state is runtime-local and single-instance.

iOS, tvOS 17+ (ARM64 device/simulator), macOS, Android and Linux use config-owned `tun.file-descriptor` through the Unix `tun-rs` adapter; positive descriptors remain host-owned and Vole closes only its duplicate. With descriptor 0, Linux and macOS can create/open native TUN devices from `tun.device`. Linux validates a real single-queue raw-IP TUN and its configured MTU; the host owns borrowed-fd addresses, DNS, namespace/routing isolation, and physical egress. Core-owned Linux TUN supports auto-detect-interface, auto-route and per-link systemd-resolved setup with rollback; package installation supplies capabilities and noninteractive DNS authorization. Apple packetFlow does not publicly guarantee raw-fd access; Linux or simulator results do not sign off a physical Network Extension. Windows has mutually exclusive `windows-uwp` (`windows-rs` / `Windows.Networking.Vpn`) and `windows-wintun` builds sharing the same core. Validate Wintun devices and packaged UWP integration separately.

# Sources of Truth

Current source, tests, and the public contract documents under `docs/` define implemented behavior. Keep documentation focused on current usage and contracts; record validation results in the relevant CI run or PR rather than accumulating development logs. When touching a documented boundary, reconcile its document with the Invoke API and current tests in the same change.

Keep all development plans in the workspace's `references/plan/` directory outside Git repositories (`../references/plan/` from this checkout). Repository documentation contains finalized conclusions, accepted decisions, and current contracts; implementation plans and task lists stay in that external directory.

Read the relevant document completely before changing that area:

- Mihomo compatibility, protocol interoperability, or compatibility/performance tradeoffs: `docs/mihomo-compatibility.md`. Apply its compatibility principles to implementation, tests, and reviews. For performance or defect fixes, first compare local Mihomo, clash-rs and official client source, then profile the matched workload to locate the bottleneck, and only then change Vole. Distinguish Core, peer and benchmark causes; retain confirmed peer failures instead of changing Core for them. Shared-layer changes require explicit regressions of affected previously passing windows; historical PASS does not sign off changed code.
- Invoke, FFI, lifecycle, Android protect, or config delivery: `docs/invoke-api.md`, `src/invoke/`, and `src/ffi/`.
- YAML, proxy graph, proxy groups, DNS, rules, or sniffer: `docs/config.yaml`, `docs/tun-icmp-dns.md`, and `src/config/`.
- HTTP/SOCKS5 inbound, authentication, or listeners: `docs/inbounds.md` and `src/inbound/`.
- Business HTTP rewrite, selective TLS, or its separate configuration: `docs/http-processing.md` and `src/http_processing/`.
- SOCKS5, AnyTLS, Trojan, VMess, Hysteria2, TUIC v5 or SS 2022: `docs/outbounds.md`.
- VLESS, Vision, Encryption, JLS or static ECH: `docs/vless.md`.
- XHTTP request fields, download legs, H1/H2/H3 or sing-mux: `docs/xhttp.md`.
- Runtime Controller, proxy-group selection, or TUN traffic metrics: `docs/controller-api.md` and `src/controller.rs`.
- GeoData: `docs/geodata.md`.
- TLS profiles, certificate policy or TLS dependencies: `docs/tls-client-fingerprint.md` and `docs/tls-dependencies.md`; REALITY also requires `docs/reality-wire-protocol.md`. Before local Boring development or opening/updating a Vole PR, follow the path-to-commit workflow and Boring PR prerequisite in `docs/tls-dependencies.md`. Keep dependency auditing in CI rather than duplicating it in platform build scripts.
- TUN fields, resource acquisition, fd ownership, packet I/O, MTU, or UDP idle policy: `docs/config.yaml`, `docs/tun-platform.md`, and `docs/tun-icmp-dns.md`.
- Windows VPN/TUN, outbound binding, AppContainer packet buffers, or package lifecycle: `docs/windows-vpn.md` and `docs/tun-platform.md`.
- CLI, foreground file/environment/path/signal behavior, or tag releases: `docs/cli.md`, `docs/invoke-api.md`, `scripts/README.md`, `src/cli.rs`, `src/invoke/foreground.rs`, and `.github/workflows/release.yml`; distinguish configured workflows from executed release validation.
- Builds: `scripts/README.md`; `vole-scripts build` compiles platform outputs, and `vole_scripts.release` packages them for CI.
- Offline regressions: `tests/README.md`. Rust memory/configuration tests remain in Vole; run explicit pure-memory filters, with all-target coverage limited to `--no-run`.
- Protocol interoperability or pressure: isolated benchmark tooling owns container orchestration and fixtures. Supply the checkout explicitly with `--source vole=PATH`; Vole builds do not import it or infer workspace paths. Keep benchmark results, comparisons and conclusions in the benchmark project; Vole documents implementation contracts and acceptance criteria. Keep tooling repository addresses and raw runs outside Vole.
- Server-side tests: `docs/testing-isolation.md`. Use isolated benchmark containers for every server peer and network origin; container failure is not permission for a host fallback.
- Claims that something passed: `docs/acceptance.md`. Record only commands and environments actually executed; host tests and cross-builds do not prove physical-device data paths.

# Architecture Boundaries

- `src/invoke/` owns shared JSON dispatch, registry, lifecycle admission, panic containment, and engine completion. `start(configYaml)` performs internal preparation and platform acquisition; no public `prepare` or fd/framing payload exists. `validateConfig` needs no initialization.
- `src/ffi/` adapts C ABI and Android JNI to Invoke and preserves native buffer/callback boundaries.
- `src/cli.rs` owns argument parsing, Invoke request conversion, rendering, and exit status. `src/invoke/foreground.rs` owns file/stdin reads, native path metadata, environment defaults, process signals, stderr logging, and foreground cleanup. Foreground validation reads its input but does not initialize data, resolve remote endpoints, or inspect platform devices.
- `src/runtime.rs` prepares and owns DNS, routing, outbound graphs, listeners, GeoData, and long-lived tasks.
- `src/tun_runtime.rs` connects platform raw-IP I/O to `vole-netstack` and dispatches TCP, UDP, DNS, ICMP, and sniffing.
- `src/platform/` contains platform adapters. Keep framing internal, propagate configured MTU, and preserve original borrowed-fd flags and ownership. Windows backend selection occurs at compilation; keep Windows callback semantics here instead of simulating a Unix fd.
- `src/dialer.rs` is the shared physical TCP/UDP socket seam. Fix socket protection or Windows `(source IP, interface index)` binding once here rather than in each outbound.
- Static and provider-backed select, url-test and fallback groups share Running Session selection between routing and `dialer-proxy`. Provider candidates validate the complete graph before publication; existing sessions retain their old resource generation until release. Keep protocol configuration immutable, validate the complete node/member DAG, and retain only declared dependencies to avoid Arc cycles. Resolve upstreams at the `OutboundConnector` seam using one setup deadline and per-group selection snapshot; resolve DIRECT server endpoints on demand through the proxy DNS role. `measureDelay` remains node-only.
- `crates/vole-netstack` is platform-independent raw-IP state and must not depend on WinRT, JNI, Swift, or host UI frameworks.
- Core runtime lifecycle does not infer App, extension, service, or daemon roles and does not implement cross-process state or IPC. The Windows-only host Invoke is the explicit package integration seam for profile/status/Session Snapshot/StartupTask operations and an optional bounded `sessionBackend`; its Session Host owns backend process liveness without interpreting arguments, files, ports, or protocols. Provider runtime state remains process-local.

# Development Rules

1. Keep the latest-only schema strict. Reject unknown and obsolete fields instead of adding compatibility branches or silent migration.
2. Preserve bounded queues, packet/buffer/parser limits, cancellation, and synchronous stop barriers. Do not turn UDP callback paths into blocking waits.
3. CLI and Controller logs preserve each emitted event's complete target, message and fields, including strings, errors and Debug values. Apply configured log levels and bounded subscription queues, without content redaction, field allowlists, truncation or additional rate limits. Do not add logging of configuration/request bodies or credentials merely to populate logs; API error and snapshot contracts remain separate.
4. Platform trust boundaries fail closed. Android protect failure, WinRT VPN physical-interface loss, invalid packet-buffer ownership, or unsupported target startup must not fall back to an unprotected socket. Desktop Wintun leaves interface addresses, DNS, routes and physical-egress isolation to the host; it does not inherit the WinRT Provider's binding or network-change monitor.
5. Packaged Windows VPN uses official `Windows.Networking.Vpn` through `windows-rs`. `VpnPacketBuffer` bytes are copied within callbacks. After acquiring a framework buffer, return it to Windows before propagating any later local error; a return-API failure propagates the platform error and fails closed. Every framework buffer is returned exactly once. Network changes stop this path; they do not silently rebind or reconnect.
6. Reuse the existing raw-IP netstack, runtime and outbound graph. Windows WinRT VPN and desktop Wintun use separate platform adapters with the shared Dialer and synchronous stop barrier; Wintun's DLL and first-release network configuration are host-owned. Add no second Windows proxy core, per-protocol socket factory or fake fd layer.
7. Keep optional protocol/platform code feature- and target-gated. Default non-TUN builds must continue to compile.
8. When copying or modifying third-party source, record the upstream project and preserve all applicable license terms. Audit linked dependencies against the resolved release graph. Do not describe independent rewrites, protocol interoperability, or architectural references as derived source without evidence; Credits provide context and attribution, not a substitute for release license review.
9. Keep every public surface—code, documentation, tests, examples, commits, issues, pull requests, reviews, CI output, and releases—limited to Vole and public dependencies. Keep private downstream repository or product identities, links, implementation details, status, artifacts, and roadmaps outside this repository and its GitHub surfaces. Before publishing, search the staged diff and proposed GitHub text for downstream identifiers.
10. Make changes on a separate branch, never directly on `main`.
11. Use the official latest stable third-party dependencies, including test-only experiments. Check current non-prerelease, non-yanked releases when selecting or upgrading them; reference projects' old pins are not a version policy. Keep lockfiles for reproducible validation, refresh affected dependency audits, and rerun applicable tests. If freshness conflicts with the approved fork/provider or a platform's compatible dependency set, report the conflict and obtain an explicit exception or scope decision instead of silently retaining an old version or changing the security architecture.

# Validation

Choose the smallest relevant set, then expand for shared contracts:

```shell
cargo fmt --all -- --check
# Select an explicit memory-only regression named in tests/README.md.
cargo test --locked --lib geodata::tests::
# All-target compilation only; network peers must be containerized.
cargo test --locked --all-features --all-targets --no-run
cargo clippy --locked --all-features --lib --bins -- -D warnings
cargo test --manifest-path crates/vole-netstack/Cargo.toml --all-targets
cargo clippy --manifest-path crates/vole-netstack/Cargo.toml --all-targets -- -D warnings
uv run --project scripts --locked python -m unittest discover -s scripts/tests
uv run --project scripts --locked ruff check scripts
uv run --project scripts --locked ruff format --check scripts
git diff --check
```

Changes to FFI, shared runtime, TUN, socket creation, TLS, or packaging also require affected target builds and scoped regressions. Validate native consumers and device behavior separately from compilation and packaging. External interop and physical-device results remain `NOT RUN` unless executed in the current validation run.

## Agent skills

### Issue tracker

Before GitHub issue or PR operations, read the [issue tracker](docs/agents/issue-tracker.md) for repository selection and request/spec conventions.

### Triage labels

Before triage or label operations, read the [five-role label mapping](docs/agents/triage-labels.md).

### Domain docs

Before codebase exploration or design, read the [single-context domain workflow](docs/agents/domain.md) for terminology and ADR rules.
