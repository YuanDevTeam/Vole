# Go Unicode case-range data

Only the directional case-range data is adapted from the official Go `go1.26.8` Unicode 15.0.0 table. Vole independently implements the binary search and bounded output/cancellation adapter. No Mihomo source or Go conversion function is copied.

Source: https://github.com/golang/go/blob/go1.26.8/src/unicode/tables.go (`_CaseRanges`). Original SHA-256: `6a88d48746c4b2c471cc04ae40559694b734770212e6f5ea5f1962adb0c0bdb1`.

The accompanying `LICENSE` is the Go Authors' BSD-3-Clause notice and terms. Retain this notice with source redistribution; release license handling remains governed by the repository's packaging contract.

Each of the 328 entries retains its start/end and upper/lower deltas. The unused titlecase delta is omitted. Delta 0x110000 marks alternating uppercase/lowercase pairs. The table consumes 5,248 bytes as four 32-bit fields per entry, before alignment or linking effects; this is a static data estimate, not a measured binary or RSS increment.

This fixed table preserves the reference consumer's Unicode 15 mapping, including identity mappings for later Unicode characters. It is compatibility data, not a Rust crate version pin. Updating the table requires a corresponding public consumer contract and boundary verification.
