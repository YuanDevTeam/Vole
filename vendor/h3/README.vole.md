# HTTP/3 source

This directory contains the complete official `h3` 0.0.8 crate, the current stable
version checked against [official documentation](https://docs.rs/h3/latest/h3/)
on 2026-10-11. The official registry archive in Cargo's download cache was verified
against its registry checksum before extraction:
`10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`.
The registry entry marks this version as non-yanked.

Upstream revision: `22c1aa3f44d1463cd7644c8f654fffc9a6da305c`, directory `h3`
in [hyperium/h3](https://github.com/hyperium/h3/tree/22c1aa3f44d1463cd7644c8f654fffc9a6da305c/h3).
Original MIT license, manifests, lockfile and VCS metadata are retained.

The root manifest patches only this crate. The registry `h3-quinn` 0.0.10 adapter
and the existing rustls/ring provider remain unchanged. The header change is in
`src/proto/headers.rs`: ordinary CONNECT emits only `:method` and `:authority`,
as required by RFC 9114 section 4.4. Extended CONNECT retains its protocol,
scheme and path; other requests retain their original encoding.

`SendRequest::can_open_request` exposes the existing connection admission state
without changing it. Pools can retire a connection after GOAWAY while keeping
its existing streams alive, before QUIC reports physical connection closure.

The `vole_connect_pseudo_headers_preserve_request_modes` unit fixture is purely
in memory. Broad upstream integration tests start servers and must not run on
the host. The H3 header fixture in the [test workflow](../../.github/workflows/test.yml)
temporarily supplies upstream's sibling-adapter test layout from Cargo's official
download cache and removes the symlink on exit. No registry files are modified.
Updates must preserve source attribution and review the local patch.
