"""Prepare the official static C package outside the source checkout."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[2] / "native/blake3"
DEPENDENCY_NAMES = ("VOLE_BLAKE3_INCLUDE_DIR", "VOLE_BLAKE3_LIB_DIR")
ARCHITECTURES = {"aarch64": "arm64", "x86_64": "x64", "armv7": "arm"}
APPLE = {
    "aarch64-apple-ios": ("iOS", "iphoneos", "IPHONEOS", "13.0"),
    "aarch64-apple-ios-sim": ("iOS", "iphonesimulator", "IPHONEOS", "14.0"),
    "aarch64-apple-darwin": ("Darwin", "macosx", "MACOSX", "11.0"),
    "x86_64-apple-darwin": ("Darwin", "macosx", "MACOSX", "10.15"),
    "aarch64-apple-tvos": ("tvOS", "appletvos", "TVOS", "17.0"),
    "aarch64-apple-tvos-sim": ("tvOS", "appletvsimulator", "TVOS", "17.0"),
}
ANDROID_ABIS = {
    "aarch64-linux-android": "arm64-v8a",
    "x86_64-linux-android": "x86_64",
    "armv7-linux-androideabi": "armeabi-v7a",
}


def _run(command: list[str], env: dict[str, str]) -> None:
    subprocess.run(command, env=env, check=True)


def _quote(value: str | Path) -> str:
    text = str(value).replace("\\", "/")
    if "\n" in text or "\r" in text:
        raise ValueError("native dependency paths cannot contain line breaks")
    return '"' + text.replace("$", "\\$").replace('"', '\\"') + '"'


def _minimum(value: str, minimum: str) -> str:
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value):
        raise ValueError("invalid Apple deployment target")
    return max((value, minimum), key=lambda item: tuple(map(int, item.split("."))))


def _triplet(target: str, env: dict[str, str], backend: str) -> tuple[str, list[Path]]:
    try:
        architecture = ARCHITECTURES[target.split("-", 1)[0]]
    except KeyError as error:
        raise ValueError("unsupported BLAKE3 target architecture") from error
    windows = target.endswith("-pc-windows-msvc")
    runtime = "static" if windows and backend != "uwp" else "dynamic"
    lines = [
        f"set(VCPKG_TARGET_ARCHITECTURE {architecture})",
        "set(VCPKG_LIBRARY_LINKAGE static)",
        "set(VCPKG_BUILD_TYPE release)",
        f"set(VCPKG_CRT_LINKAGE {runtime})",
        "list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "
        '"-DCMAKE_POSITION_INDEPENDENT_CODE=ON")',
    ]
    tracked = [CONFIG_DIR / "namespace.cmake"]
    if target in APPLE:
        system, sdk, deployment, minimum = APPLE[target]
        key = deployment + "_DEPLOYMENT_TARGET"
        env[key] = _minimum(env.get(key, minimum), minimum)
        sdk_path = subprocess.run(
            ["xcrun", "--sdk", sdk, "--show-sdk-path"],
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        lines += [
            f"set(VCPKG_CMAKE_SYSTEM_NAME {system})",
            f"set(VCPKG_OSX_SYSROOT {_quote(sdk_path)})",
            f"set(VCPKG_OSX_ARCHITECTURES "
            f"{'x86_64' if architecture == 'x64' else 'arm64'})",
            f"set(VCPKG_OSX_DEPLOYMENT_TARGET {env[key]})",
        ]
        if system == "tvOS":
            tracked.append(CONFIG_DIR / "tvos.cmake")
            lines.append(f"set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE {_quote(tracked[-1])})")
    elif target in ANDROID_ABIS:
        ndk = Path(env["ANDROID_NDK_HOME"]).resolve()
        api = env.get("VOLE_CMAKE_ANDROID_API", env.get("VOLE_ANDROID_API", "24"))
        if not api.isdigit() or int(api) < 21:
            raise ValueError("Android BLAKE3 API must be 21 or newer")
        lines += [
            "set(VCPKG_CMAKE_SYSTEM_NAME Android)",
            f"set(VCPKG_CMAKE_SYSTEM_VERSION {api})",
            "set(VCPKG_ENV_PASSTHROUGH ANDROID_NDK_HOME)",
            "list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "
            f"{_quote('-DANDROID_ABI=' + ANDROID_ABIS[target])} "
            f"{_quote('-DCMAKE_ANDROID_NDK=' + str(ndk))} "
            '"-DANDROID_STL=c++_shared")',
        ]
    elif target.endswith("-unknown-linux-gnu"):
        lines.append("set(VCPKG_CMAKE_SYSTEM_NAME Linux)")
    elif windows:
        if backend not in {"wintun", "uwp"}:
            raise ValueError("Windows BLAKE3 backend must be wintun or uwp")
        # vcpkg identifies desktop Windows with an empty system name, unlike
        # CMake. A chainloaded Clang toolchain still needs the native SDK env.
        system = "WindowsStore" if backend == "uwp" else '""'
        lines += [
            f"set(VCPKG_CMAKE_SYSTEM_NAME {system})",
            "set(VCPKG_LOAD_VCVARS_ENV ON)",
        ]
        # This is a C library, with no C++/CX or WinRT types. UWP still uses
        # the official WindowsStore toolchain and its API-family definitions.
        lines.append("set(VCPKG_MSVC_CXX_WINRT_EXTENSIONS OFF)")
        if backend == "uwp":
            lines.append(
                "list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS "
                '"-DCMAKE_TRY_COMPILE_CONFIGURATION=Release" '
                '"-DVCPKG_MSVC_CXX_WINRT_EXTENSIONS=OFF" '
                '"-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES='
                'VCPKG_MSVC_CXX_WINRT_EXTENSIONS")'
            )
        if architecture == "arm64":
            tracked.append(CONFIG_DIR / "windows-arm64.cmake")
            lines += [
                f"set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE {_quote(tracked[-1])})",
                "set(VCPKG_ENV_PASSTHROUGH "
                "CC_aarch64_pc_windows_msvc CXX_aarch64_pc_windows_msvc)",
            ]
    else:
        raise ValueError("unsupported BLAKE3 Rust target")
    lines.append(
        "list(APPEND VCPKG_HASH_ADDITIONAL_FILES "
        + " ".join(map(_quote, tracked))
        + ")"
    )
    lines.append(f"include({_quote(CONFIG_DIR / 'namespace.cmake')})")
    return "\n".join(lines) + "\n", tracked


def _cache_dir(env: dict[str, str]) -> Path:
    if override := env.get("VOLE_NATIVE_CACHE_DIR"):
        return Path(override).expanduser().resolve()
    if platform.system() == "Windows":
        root = Path(env["LOCALAPPDATA"])
    elif platform.system() == "Darwin":
        root = Path.home() / "Library/Caches"
    else:
        root = Path(env.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    return root / "vole/native"


def _paths(target: str, include: str, lib: str) -> dict[str, str]:
    suffix = "_" + target.upper().replace("-", "_")
    archive = "blake3.lib" if target.endswith("-msvc") else "libblake3.a"
    for value, name in ((include, "blake3.h"), (lib, archive)):
        path = Path(value)
        if not path.is_absolute() or not (path / name).is_file():
            raise RuntimeError(f"missing absolute BLAKE3 dependency path: {name}")
    return dict(
        zip((name + suffix for name in DEPENDENCY_NAMES), (include, lib), strict=True)
    )


def environment(
    target: str, host: str, env: dict[str, str], backend: str = "wintun"
) -> dict[str, str]:
    """Keep explicit dependency overrides; otherwise install the locked package."""
    env = env.copy()
    suffix = "_" + target.upper().replace("-", "_")
    overrides = [
        env[name + suffix]
        if name + suffix in env
        else env.get(name)
        if target == host
        else None
        for name in DEPENDENCY_NAMES
    ]
    if any(value is not None for value in overrides):
        if any(value is None for value in overrides):
            raise RuntimeError("set both BLAKE3 include and library dependency paths")
        return env | _paths(target, *overrides)

    manifest = (CONFIG_DIR / "vcpkg.json").read_bytes()
    registry = json.loads(manifest)["builtin-baseline"]
    triplet_text, tracked = _triplet(target, env, backend)
    # Only our small package configuration enters this cache identity. Third-
    # party source acquisition and package ABI tracking remain vcpkg's job.
    identity = hashlib.sha256(manifest + triplet_text.encode())
    for path in tracked:
        identity.update(path.read_bytes())
    triplet = f"{target.replace('_', '-')}-vole-{identity.hexdigest()[:12]}"
    cache = _cache_dir(env)
    overlay = cache / "triplets"
    overlay.mkdir(parents=True, exist_ok=True)
    (overlay / (triplet + ".cmake")).write_text(triplet_text, encoding="utf-8")
    checkout = cache / ("vcpkg-" + registry)
    if not (checkout / ".git").is_dir():
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "https://github.com/microsoft/vcpkg.git",
                str(checkout),
            ],
            env,
        )
        _run(["git", "-C", str(checkout), "checkout", "--detach", registry], env)
    current = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if current != registry:
        raise RuntimeError("managed vcpkg checkout does not match the locked registry")
    windows = platform.system() == "Windows"
    executable = checkout / ("vcpkg.exe" if windows else "vcpkg")
    if not executable.is_file():
        bootstrap = checkout / (
            "bootstrap-vcpkg.bat" if windows else "bootstrap-vcpkg.sh"
        )
        command = (
            [env.get("COMSPEC", "cmd.exe"), "/d", "/c", "call", str(bootstrap)]
            if windows
            else ["bash", str(bootstrap)]
        )
        _run([*command, "-disableMetrics"], env)
    host_architecture = ARCHITECTURES[host.split("-", 1)[0]]
    host_system = {"Windows": "windows", "Darwin": "osx", "Linux": "linux"}[
        platform.system()
    ]
    installed = cache / "installed" / triplet
    command = [
        str(executable),
        "install",
        f"--triplet={triplet}",
        f"--host-triplet={host_architecture}-{host_system}",
        f"--x-manifest-root={CONFIG_DIR}",
        f"--overlay-triplets={overlay}",
        f"--x-install-root={installed}",
        "--disable-metrics",
        "--x-wait-for-lock",
    ]
    try:
        _run(command, env)
    except subprocess.CalledProcessError:
        for stage in ("detect_compiler", "blake3"):
            logs = (checkout / "buildtrees" / stage).glob(f"config-{triplet}*-out.log")
            for log in sorted(logs)[-2:]:
                try:
                    with log.open("rb") as stream:
                        stream.seek(0, 2)
                        stream.seek(max(0, stream.tell() - 16_384))
                        detail = stream.read(16_384).decode(errors="replace")
                except OSError:
                    continue
                print(f"\n{stage}/{log.name}:\n", flush=True)
                print(detail, flush=True)
        raise
    package = installed / triplet
    return env | _paths(target, str(package / "include"), str(package / "lib"))
