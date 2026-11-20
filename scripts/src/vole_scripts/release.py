"""Build and package CLI/FFI artifacts; GitHub publication stays in the workflow."""

from __future__ import annotations

import argparse
import gzip
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

from . import builds

ANDROID_TARGETS = ("aarch64-linux-android", "x86_64-linux-android")
LINUX_TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
WINDOWS_TARGETS = ("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")
FFI_TARGETS = {
    "apple": builds.APPLE_TARGETS,
    "android": ANDROID_TARGETS,
    **{
        f"linux-{arch}": (target,)
        for arch, target in zip(("amd64", "arm64"), LINUX_TARGETS, strict=True)
    },
    **{
        f"windows-{backend}-{arch}": (target,)
        for arch, target in zip(("amd64", "arm64"), WINDOWS_TARGETS, strict=True)
        for backend in ("wintun", "uwp")
    },
}
SMOKE_CONFIG = """tun:
  enable: true
proxies:
  - name: probe
    type: socks5
    server: probe.invalid
    port: 1080
rules:
  - MATCH,probe
"""


def cli_archive(target: str) -> str:
    system, architecture = builds.CLI_TARGETS[target]
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}[system]
    architecture = "amd64" if architecture == "x64" else "arm64"
    suffix = "zip" if system == "windows" else "gz"
    return f"vole-{system}-{architecture}.{suffix}"


def ffi_archive(key: str) -> str:
    return f"vole-ffi-{key}" + (".zip" if key.startswith("windows-") else ".tar.gz")


ASSETS = {cli_archive(target) for target in builds.CLI_TARGETS} | {
    ffi_archive(key) for key in FFI_TARGETS
}


def release_info(tag: str | None) -> dict:
    version = tomllib.loads((builds.CORE_DIR / "Cargo.toml").read_text())["package"][
        "version"
    ]
    if tag is not None and (
        not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or tag != "v" + version
    ):
        raise ValueError("release tag must be vX.Y.Z and match Cargo package version")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=builds.CORE_DIR, text=True
    ).strip()
    return {"version": version, "commit": commit}


def _check_build_settings() -> None:
    # These options change the file set or features selected by the release matrix.
    overrides = [
        key
        for key in (
            "VOLE_FEATURES",
            "VOLE_ANDROID_TARGETS",
            "VOLE_ANDROID_OUTPUT_DIR",
            "VOLE_APPLE_DIST_DIR",
        )
        if os.environ.get(key)
    ]
    if overrides or os.environ.get("VOLE_BUILD_PROFILE", "release") not in {
        "",
        "release",
    }:
        raise ValueError(
            "release builds require the default production features, "
            "profile and output layout"
        )


def _guard_output(output: Path) -> None:
    relative = output.relative_to(builds.CORE_DIR)
    if len(relative.parts) < 2 or relative.parts[0] != "dist" or ".." in relative.parts:
        raise ValueError(
            "release output must be a child of the checkout dist directory"
        )
    # The release commands replace this directory; never follow a link outside dist.
    current = builds.CORE_DIR
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if (
            stat.S_ISLNK(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(
                "release output must not contain symlinks or reparse points"
            )


def _reset_output(output: Path) -> None:
    _guard_output(output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)


def _smoke(binary: Path, *, rosetta: bool = False) -> None:
    command = ["/usr/bin/arch", "-x86_64", str(binary)] if rosetta else [str(binary)]
    with tempfile.TemporaryDirectory(prefix="vole-cli-smoke-") as directory:
        cwd = Path(directory)
        config = cwd / "config.yaml"
        config.write_text(SMOKE_CONFIG, encoding="utf-8")
        for arguments in (("-h",), ("-v",), ("-t", "-f", str(config))):
            subprocess.run([*command, *arguments], cwd=cwd, check=True, timeout=30)
        subprocess.run(
            [*command, "-t", "-f", "-"],
            input=SMOKE_CONFIG,
            text=True,
            cwd=cwd,
            check=True,
            timeout=30,
        )


def build_cli(target: str, tag: str | None, output: Path) -> Path:
    output = builds.CORE_DIR / output
    _guard_output(output)
    _check_build_settings()
    host = builds.native_target()
    rosetta = (host, target) == ("aarch64-apple-darwin", "x86_64-apple-darwin")
    if target != host and not rosetta:
        raise ValueError("CLI release builds require the native target")
    release_info(tag)
    binary = builds.build_cli(target)
    _smoke(binary, rosetta=rosetta)
    _reset_output(output)
    archive = output / cli_archive(target)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            stream.write(binary, arcname="vole.exe")
    else:
        with binary.open("rb") as source, gzip.open(archive, "wb") as stream:
            shutil.copyfileobj(source, stream)
    print(archive)
    return archive


def ffi_key(platform: str, target: str | None, backend: str | None) -> str:
    if platform in {"apple", "android"}:
        if target or backend:
            raise ValueError("Apple and Android packages use their full target set")
        return platform
    allowed = LINUX_TARGETS if platform == "linux" else WINDOWS_TARGETS
    if target not in allowed or (platform == "linux" and backend):
        raise ValueError("select a supported FFI target and backend")
    architecture = "amd64" if target.startswith("x86_64-") else "arm64"
    key = (
        f"windows-{backend}-{architecture}"
        if platform == "windows"
        else f"linux-{architecture}"
    )
    if key not in FFI_TARGETS:
        raise ValueError("Windows FFI requires --backend wintun or uwp")
    return key


def ffi_files(platform: str, backend: str | None) -> set[str]:
    if platform == "apple":
        slices = (
            "ios-arm64",
            "ios-arm64-simulator",
            "macos-arm64_x86_64",
            "tvos-arm64",
            "tvos-arm64-simulator",
        )
        return {"LibVole.xcframework/Info.plist"} | {
            f"LibVole.xcframework/{part}/{name}"
            for part in slices
            for name in ("libvole.a", "Headers/vole.h", "Headers/module.modulemap")
        }
    if platform == "android":
        return {
            f"{abi}/{name}"
            for abi in ("arm64-v8a", "x86_64")
            for name in ("libvole.so", "libc++_shared.so")
        } | {"include/vole.h"}
    if platform == "linux":
        return {"libvole.so", "libvole.a", "include/vole.h"}
    return {"vole.dll", "vole.dll.lib", "include/vole.h"} | (
        {
            "vole-windows-vpn-host.exe",
            "vole-windows-session-host.exe",
            "include/vole_windows_uwp.h",
        }
        if backend == "uwp"
        else set()
    )


def _write_archive(base: Path, archive: Path) -> None:
    files = sorted(path for path in base.rglob("*") if path.is_file())
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
            for path in files:
                stream.write(path, arcname=path.relative_to(base).as_posix())
    else:
        with tarfile.open(archive, "w:gz") as stream:
            for path in files:
                stream.add(
                    path, arcname=path.relative_to(base).as_posix(), recursive=False
                )


def build_apple_target(target: str, tag: str | None, output: Path) -> Path:
    output = builds.CORE_DIR / output
    _guard_output(output)
    _check_build_settings()
    release_info(tag)
    library = builds.build_apple_target(target)
    _reset_output(output)
    destination = output / "libvole.a"
    shutil.copy2(library, destination)
    print(destination)
    return destination


def assemble_apple(incoming: Path, output: Path) -> Path:
    incoming = builds.CORE_DIR / incoming
    artifacts = {
        target: incoming / target / "libvole.a" for target in builds.APPLE_TARGETS
    }
    built = builds.assemble_apple(artifacts)
    return _package_ffi(
        "apple", None, built, builds.CORE_DIR / output / ffi_archive("apple")
    )


def _package_ffi(
    platform: str, backend: str | None, built: Path, archive: Path
) -> Path:
    output = archive.parent
    _guard_output(output)
    if output.resolve().is_relative_to(
        built.resolve()
    ) or built.resolve().is_relative_to(output.resolve()):
        raise ValueError(
            "FFI archive output must be separate from platform build output"
        )
    with tempfile.TemporaryDirectory(prefix="vole-package-") as directory:
        staging = Path(directory)
        for name in sorted(ffi_files(platform, backend)):
            origin = (
                builds.CORE_DIR / name
                if name == "include/vole.h" and platform == "android"
                else built / name
            )
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, destination)
        _reset_output(output)
        _write_archive(staging, archive)
    print(archive)
    return archive


def build_ffi(
    platform: str,
    target: str | None,
    backend: str | None,
    tag: str | None,
    output: Path,
) -> Path:
    key = ffi_key(platform, target, backend)
    root = builds.CORE_DIR
    output = root / output
    _guard_output(output)
    raw = root / "dist" / platform
    if output.resolve().is_relative_to(raw.resolve()) or raw.resolve().is_relative_to(
        output.resolve()
    ):
        raise ValueError(
            "FFI archive output must be separate from platform build output"
        )
    _check_build_settings()
    if platform in {"linux", "windows"} and target != builds.native_target():
        raise ValueError("FFI release builds require the native target")
    release_info(tag)
    if platform == "windows":
        built = builds.build_windows(backend)
    elif platform == "linux":
        built = builds.build_linux(target)
    elif platform == "apple":
        built = builds.build_apple()
    else:
        built = builds.build_android()
    return _package_ffi(platform, backend, built, output / ffi_archive(key))


def assemble_release(
    tag: str | None,
    incoming: Path,
    output: Path,
    notes_path: Path,
    repository: str = "YuanDevTeam/Vole",
) -> list[Path]:
    info = release_info(tag)
    root = builds.CORE_DIR
    incoming, output, notes_path = root / incoming, root / output, root / notes_path
    _guard_output(output)
    if output.resolve().is_relative_to(
        incoming.resolve()
    ) or incoming.resolve().is_relative_to(output.resolve()):
        raise ValueError("release output must be separate from the input archives")
    if notes_path.resolve().is_relative_to(output.resolve()):
        raise ValueError("release notes must be outside the asset directory")
    archives = sorted(path for path in incoming.glob("*/*") if path.is_file())
    if len(archives) != len(ASSETS) or {path.name for path in archives} != ASSETS:
        raise ValueError("release requires exactly the fourteen CLI/FFI archives")
    _reset_output(output)
    for archive in archives:
        shutil.copy2(archive, output / archive.name)
    source = f"https://github.com/{repository}/tree/{info['commit']}"
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text(
        f"Vole {info['version']}: six CLI and eight FFI archives.\n\n"
        "Windows CLI uses Wintun; Windows FFI provides Wintun and UWP builds. "
        "Wintun requires a host-provided wintun.dll; "
        "addresses, DNS and routes are host-owned.\n\n"
        f"[Source]({source}) · [Dependencies]({source}/Cargo.lock)\n",
        encoding="utf-8",
    )
    return sorted(output / name for name in ASSETS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cli = commands.add_parser("build-cli")
    cli.add_argument("--target", choices=builds.CLI_TARGETS, required=True)
    cli.add_argument("--output", type=Path)
    ffi = commands.add_parser("build-ffi")
    ffi.add_argument(
        "--platform", choices=("apple", "android", "linux", "windows"), required=True
    )
    ffi.add_argument("--target", choices=LINUX_TARGETS + WINDOWS_TARGETS)
    ffi.add_argument("--backend", choices=("wintun", "uwp"))
    ffi.add_argument("--output", type=Path)
    apple_target = commands.add_parser("build-apple-target")
    apple_target.add_argument("--target", choices=builds.APPLE_TARGETS, required=True)
    apple_target.add_argument("--output", type=Path, required=True)
    apple = commands.add_parser("assemble-apple")
    apple.add_argument("--inputs", type=Path, required=True)
    apple.add_argument("--output", type=Path, required=True)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--inputs", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--notes", type=Path, required=True)
    for command in (cli, ffi, apple_target, assemble):
        command.add_argument(
            "--tag", default=os.environ.get("VOLE_RELEASE_TAG") or None
        )
    assemble.add_argument("--repository", default="YuanDevTeam/Vole")
    args = parser.parse_args()
    if args.command == "build-cli":
        build_cli(
            args.target,
            args.tag,
            args.output or Path("dist/release") / ("cli-" + args.target),
        )
    elif args.command == "build-ffi":
        key = ffi_key(args.platform, args.target, args.backend)
        build_ffi(
            args.platform,
            args.target,
            args.backend,
            args.tag,
            args.output or Path("dist/release") / ("ffi-" + key),
        )
    elif args.command == "build-apple-target":
        build_apple_target(args.target, args.tag, args.output)
    elif args.command == "assemble-apple":
        assemble_apple(args.inputs, args.output)
    else:
        for path in assemble_release(
            args.tag, args.inputs, args.output, args.notes, args.repository
        ):
            print(path)


if __name__ == "__main__":
    main()
