"""Check official dependency acceptance and reject local or ambiguous sources."""

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from vole_scripts.h2_source import audit_h2_source


class H2SourceAuditTests(unittest.TestCase):
    def setUp(self):
        owner = tempfile.TemporaryDirectory()
        self.addCleanup(owner.cleanup)
        self.root = Path(owner.name).resolve()
        self.manifest = '[dependencies]\nh2 = "0.4.20"\n'
        (self.root / "Cargo.toml").write_text(self.manifest)
        self.lock = (
            'version = 4\n[[package]]\nname = "h2"\nversion = "0.4.20"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "'
            "7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118"
            '"\n'
        )
        (self.root / "Cargo.lock").write_text(self.lock)
        self.package = {
            "id": "synthetic-official-h2",
            "name": "h2",
            "version": "0.4.20",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "license": "MIT",
        }
        self.metadata = {
            "workspace_root": str(self.root),
            "workspace_members": [],
            "packages": [self.package],
            "resolve": {"nodes": [{"id": self.package["id"]}]},
        }

    def test_official_registry_package_and_lock_pass(self):
        audit_h2_source(self.root, self.metadata)

    def test_vendor_directory_is_rejected(self):
        (self.root / "vendor").mkdir()
        with self.assertRaises(ValueError):
            audit_h2_source(self.root, self.metadata)

    def test_local_git_and_duplicate_packages_are_rejected(self):
        for source in (None, "git+https://example.invalid/h2", "registry+other"):
            changed = deepcopy(self.metadata)
            changed["packages"][0]["source"] = source
            with self.subTest(source=source), self.assertRaises(ValueError):
                audit_h2_source(self.root, changed)
        changed = deepcopy(self.metadata)
        changed["packages"].append(self.package | {"id": "second-h2"})
        with self.assertRaises(ValueError):
            audit_h2_source(self.root, changed)

    def test_manifest_source_overrides_are_rejected(self):
        for extra in (
            '\n[patch.crates-io]\nh2 = { path = "local-h2" }\n',
            '\n[patch.crates-io]\nh2_local = { package = "h2", path = "local-h2" }\n',
            '\n[replace]\n"h2:0.4.20" = { path = "local-h2" }\n',
        ):
            (self.root / "Cargo.toml").write_text(self.manifest + extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                audit_h2_source(self.root, self.metadata)

    def test_missing_registry_identity_or_wrong_checksum_is_rejected(self):
        for text in (
            self.lock.replace(
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n', ""
            ),
            self.lock.replace("7d290202", "00000000"),
        ):
            (self.root / "Cargo.lock").write_text(text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit_h2_source(self.root, self.metadata)

    def test_workspace_and_unresolved_h2_are_rejected(self):
        for field, value in (
            ("workspace_members", [self.package["id"]]),
            ("resolve", {"nodes": []}),
        ):
            changed = deepcopy(self.metadata)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit_h2_source(self.root, changed)
