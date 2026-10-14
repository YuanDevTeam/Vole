from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from .builds import (
    build_android,
    build_apple,
    build_cli,
    build_linux,
    build_windows,
    prepare_native_dependencies,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vole-scripts",
        description="Build Vole platform artifacts.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    dependencies = commands.add_parser(
        "deps", help="prepare official native dependencies"
    )
    dependencies.add_argument(
        "--target", help="Rust target triple (default: native host)"
    )
    dependencies.add_argument("--backend", choices=("wintun", "uwp"), default="wintun")
    dependencies.add_argument(
        "--github-env", type=Path, help="append paths for CI Cargo checks"
    )

    build = commands.add_parser("build", help="build platform artifacts")
    platforms = build.add_subparsers(dest="platform", required=True)
    for name, description in (
        ("apple", "build LibVole.xcframework on macOS"),
        ("android", "build Android libvole.so artifacts"),
        ("windows", "build Windows native artifacts"),
        ("linux", "build native Linux FFI artifacts"),
    ):
        command = platforms.add_parser(name, help=description)
        command.add_argument(
            "--low-memory",
            action="store_true",
            help="enable the low-memory core feature",
        )
        if name == "windows":
            command.add_argument("--backend", choices=("wintun", "uwp"), default="uwp")
    command = platforms.add_parser("cli", help="build the foreground executable")
    command.add_argument("--target", help="Rust target triple (default: native host)")
    command.add_argument("--profile", choices=("debug", "release"), default="release")
    command.add_argument(
        "--low-memory", action="store_true", help="enable the low-memory core feature"
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "deps":
            prepare_native_dependencies(args.target, args.backend, args.github_env)
        elif args.platform == "cli":
            build_cli(args.target, args.profile, low_memory=args.low_memory)
        elif args.platform == "apple":
            build_apple(low_memory=args.low_memory)
        elif args.platform == "android":
            build_android(low_memory=args.low_memory)
        elif args.platform == "windows":
            build_windows(args.backend, low_memory=args.low_memory)
        else:
            build_linux(low_memory=args.low_memory)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"vole-scripts: {error}", file=sys.stderr)
        return 1
    return 0
