"""Audit the official h2 registry dependency and reject local source overrides."""

from __future__ import annotations

import argparse
import json
import subprocess
import tomllib
from pathlib import Path

VERSION = "0.4.20"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
CRATE_SHA256 = "7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118"
ROOT = Path(__file__).resolve().parents[3]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit_h2_source(root, metadata):
    root = Path(root).resolve(strict=True)
    require(
        Path(metadata["workspace_root"]).resolve() == root, "metadata root mismatch"
    )
    vendor = root / "vendor"
    require(not vendor.exists() and not vendor.is_symlink(), "vendor is forbidden")
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    require(
        manifest["dependencies"]["h2"] == VERSION,
        "h2 must use its official version requirement",
    )
    require(
        all(
            name != "h2"
            and not (isinstance(spec, dict) and spec.get("package") == "h2")
            for entries in manifest.get("patch", {}).values()
            for name, spec in entries.items()
        )
        and not any(
            key.split(":", 1)[0] == "h2" for key in manifest.get("replace", {})
        ),
        "h2 source overrides are forbidden",
    )
    packages = [item for item in metadata["packages"] if item["name"] == "h2"]
    require(len(packages) == 1, "expected one resolved h2 across the graph")
    item = packages[0]
    require(
        item["version"] == VERSION
        and item.get("source") == REGISTRY
        and item.get("license") == "MIT",
        "h2 must resolve to the official registry package",
    )
    require(
        item["id"] in {node["id"] for node in metadata["resolve"]["nodes"]}
        and item["id"] not in metadata["workspace_members"],
        "h2 must be a resolved external dependency",
    )
    rows = [
        row
        for row in tomllib.loads((root / "Cargo.lock").read_text())["package"]
        if row["name"] == "h2"
    ]
    require(
        len(rows) == 1
        and rows[0]["version"] == VERSION
        and rows[0].get("source") == REGISTRY
        and rows[0].get("checksum") == CRATE_SHA256,
        "h2 lock must retain the official registry source and archive checksum",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path)
    options = parser.parse_args()
    if options.metadata:
        metadata = json.loads(options.metadata.read_bytes())
    else:
        metadata = json.loads(
            subprocess.check_output(
                [
                    "cargo",
                    "metadata",
                    "--offline",
                    "--locked",
                    "--all-features",
                    "--format-version",
                    "1",
                ],
                cwd=ROOT,
                timeout=120,
            )
        )
    audit_h2_source(ROOT, metadata)
    print("Official h2 registry source, archive checksum and unique graph passed")


if __name__ == "__main__":
    main()
