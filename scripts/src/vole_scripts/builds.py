from __future__ import annotations

import locale
import os
import platform
import re
import shutil
import subprocess
import sysconfig
import tempfile
from pathlib import Path

from . import blake3

CORE_DIR = Path(__file__).resolve().parents[3]
# Both transports enable the production core through invoke -> tun in Cargo.toml.
DEFAULT_FEATURES = "ffi"

APPLE_TARGETS = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-apple-tvos",
    "aarch64-apple-tvos-sim",
)
WINDOWS_BACKENDS = {"wintun", "uwp"}
CLI_TARGETS = {
    "x86_64-unknown-linux-gnu": ("Linux", "x64"),
    "aarch64-unknown-linux-gnu": ("Linux", "arm64"),
    "x86_64-apple-darwin": ("Darwin", "x64"),
    "aarch64-apple-darwin": ("Darwin", "arm64"),
    "x86_64-pc-windows-msvc": ("Windows", "x64"),
    "aarch64-pc-windows-msvc": ("Windows", "arm64"),
}


def windows_features(backend: str = "uwp") -> str:
    if backend not in WINDOWS_BACKENDS:
        raise ValueError("Windows backend must be wintun or uwp")
    return DEFAULT_FEATURES + ",windows-" + backend


def native_target() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    architecture = (
        _windows_architecture()
        if system == "Windows"
        else {
            "x86_64": "x64",
            "amd64": "x64",
            "aarch64": "arm64",
            "arm64": "arm64",
        }.get(machine)
    )
    for target, identity in CLI_TARGETS.items():
        if identity == (system, architecture):
            return target
    raise RuntimeError("unsupported native build platform or architecture")


def cli_features(target: str) -> str:
    if target not in CLI_TARGETS:
        raise ValueError("unsupported CLI Rust target")
    if CLI_TARGETS[target][0] == "Windows":
        return "cli,windows-wintun"
    return "cli"


def tvos_deployment_target() -> str:
    value = _env("VOLE_TVOS_DEPLOYMENT_TARGET", "17.0")
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", value) or tuple(
        map(int, value.split("."))
    ) < (17, 0):
        raise ValueError("tvOS deployment target must be 17.0 or newer")
    return value


def _env(name: str, default: str | os.PathLike[str]) -> str:
    return os.environ.get(name) or os.fspath(default)


def _cargo_target_dir(env: dict[str, str] | None = None) -> Path:
    """Resolve the output used by Cargo commands executed in this checkout."""
    value = (os.environ if env is None else env).get("CARGO_TARGET_DIR")
    if not value:
        return CORE_DIR / "target"
    directory = Path(value)
    return directory if directory.is_absolute() else CORE_DIR / directory


def _run(
    command: list[str | os.PathLike[str]], *, env: dict[str, str] | None = None
) -> None:
    subprocess.run(command, cwd=CORE_DIR, env=env, check=True)


def _profile() -> tuple[str, list[str]]:
    profile = _env("VOLE_BUILD_PROFILE", "release")
    if profile == "release":
        return profile, ["--release"]
    if profile == "debug":
        return profile, []
    raise RuntimeError(f"unsupported VOLE_BUILD_PROFILE: {profile}")


def _production_features(features: str) -> str:
    names = {name.rsplit("/", 1)[-1] for name in re.split(r"[,\s]+", features)}
    if "interop-test" in names:
        raise RuntimeError("platform builds cannot enable test-only features")
    return features


def _cargo_build(
    target: str,
    profile_flags: list[str],
    features: str,
    env: dict[str, str],
    artifacts: tuple[str, ...] = ("--lib",),
) -> Path:
    _production_features(features)
    env = blake3.environment(
        target,
        native_target(),
        env,
        "uwp" if "windows-uwp" in re.split(r"[,\s]+", features) else "wintun",
    )
    _run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(CORE_DIR / "Cargo.toml"),
            "--locked",
            "--target",
            target,
            *profile_flags,
            "--no-default-features",
            "--features",
            features,
            *artifacts,
        ],
        env=env,
    )
    profile = "release" if "--release" in profile_flags else "debug"
    return _cargo_target_dir(env) / target / profile


def prepare_native_dependencies(
    target: str | None = None, backend: str = "wintun", github_env: Path | None = None
) -> None:
    """Prepare the same package for direct Cargo checks outside platform builds."""
    host = native_target()
    target = host if target is None else target
    env = os.environ.copy()
    if target in blake3.ANDROID_ABIS:
        if platform.system() not in {"Darwin", "Linux"}:
            raise RuntimeError("Android dependencies require macOS or Linux")
        env["ANDROID_NDK_HOME"] = str(_android_ndk_home())
    elif target in APPLE_TARGETS:
        if platform.system() != "Darwin":
            raise RuntimeError("Apple dependencies require macOS")
        for variable, override, default in (
            ("IPHONEOS", "VOLE_IOS_DEPLOYMENT_TARGET", "13.0"),
            ("MACOSX", "VOLE_MACOS_DEPLOYMENT_TARGET", "10.15"),
            ("TVOS", "VOLE_TVOS_DEPLOYMENT_TARGET", "17.0"),
        ):
            env.setdefault(variable + "_DEPLOYMENT_TARGET", _env(override, default))
    elif target != host:
        raise ValueError("Linux and Windows dependencies require the native target")
    if platform.system() == "Windows":
        env = _windows_msvc_environment(CLI_TARGETS[host][1])
    env = blake3.environment(target, host, env, backend)
    suffix = "_" + target.upper().replace("-", "_")
    entries = [
        f"{name + suffix}={env[name + suffix]}" for name in blake3.DEPENDENCY_NAMES
    ]
    if github_env is not None:
        with github_env.open("a", encoding="utf-8") as stream:
            stream.write("\n".join(entries) + "\n")
    for entry in entries:
        print(entry)


def build_cli(target: str | None = None, profile: str = "release") -> Path:
    target = native_target() if target is None else target
    features = cli_features(target)
    system, architecture = CLI_TARGETS[target]
    if platform.system() != system:
        raise RuntimeError("CLI target must use the build host operating system")
    if profile not in {"debug", "release"}:
        raise ValueError("CLI profile must be debug or release")
    environment = (
        _windows_msvc_environment(architecture)
        if system == "Windows"
        else os.environ.copy()
    )
    if system == "Darwin":
        minimum = "11.0" if architecture == "arm64" else "10.15"
        environment.setdefault("MACOSX_DEPLOYMENT_TARGET", minimum)
    built = _cargo_build(
        target,
        ["--release"] if profile == "release" else [],
        features,
        environment,
        ("--bin", "vole"),
    )
    artifact = built / ("vole.exe" if system == "Windows" else "vole")
    print(artifact)
    return artifact


def build_linux(target: str | None = None) -> Path:
    if platform.system() != "Linux":
        raise RuntimeError("Linux artifacts must be built on native Linux")
    native = native_target()
    target = native if target is None else target
    if target != native:
        raise ValueError("Linux FFI build requires the native GNU Rust target")
    architecture = CLI_TARGETS[target][1]
    environment = os.environ.copy()
    release = _cargo_build(
        target,
        ["--release"],
        DEFAULT_FEATURES,
        environment,
    )
    output = CORE_DIR / "dist/linux" / architecture
    shutil.rmtree(output, ignore_errors=True)
    (output / "include").mkdir(parents=True)
    for name in ("libvole.so", "libvole.a"):
        shutil.copy2(release / name, output / name)
    shutil.copy2(CORE_DIR / "include/vole.h", output / "include/vole.h")
    print(output)
    return output


def _android_target(target: str, api: str) -> tuple[str, str, str]:
    targets = {
        "aarch64-linux-android": (
            "arm64-v8a",
            f"aarch64-linux-android{api}-clang",
            "AARCH64_LINUX_ANDROID",
        ),
        "x86_64-linux-android": (
            "x86_64",
            f"x86_64-linux-android{api}-clang",
            "X86_64_LINUX_ANDROID",
        ),
        "armv7-linux-androideabi": (
            "armeabi-v7a",
            f"armv7a-linux-androideabi{api}-clang",
            "ARMV7_LINUX_ANDROIDEABI",
        ),
    }
    try:
        return targets[target]
    except KeyError as error:
        raise RuntimeError(f"unsupported Android Rust target: {target}") from error


def _android_toolchain(ndk_home: Path) -> Path:
    host_os = platform.system().lower()
    host_arch = platform.machine().lower()
    aliases = {
        "aarch64": "arm64",
        "amd64": "x86_64",
        "x86-64": "x86_64",
    }
    host_arch = aliases.get(host_arch, host_arch)
    prebuilt = ndk_home / "toolchains" / "llvm" / "prebuilt"
    for tag in dict.fromkeys(
        [f"{host_os}-{host_arch}", f"{host_os}-x86_64", f"{host_os}-arm64"]
    ):
        candidate = prebuilt / tag
        if candidate.is_dir():
            return candidate
    raise RuntimeError(f"Android NDK toolchain not found under {ndk_home}")


def _android_ndk_home() -> Path:
    """Resolve an explicit NDK path/version or the newest installed stable major."""
    if override := os.environ.get("ANDROID_NDK_HOME"):
        return Path(override).resolve()
    android_home = (
        Path(sdk_home)
        if (sdk_home := os.environ.get("ANDROID_HOME"))
        else Path.home() / "Library" / "Android" / "sdk"
    )
    installed = android_home / "ndk"
    selector = _env("VOLE_ANDROID_NDK_VERSION", "30")
    if not selector.isdigit():
        return (installed / selector).resolve()
    candidates = []
    for path in installed.glob(selector + ".*"):
        properties = path / "source.properties"
        if (
            not path.is_dir()
            or not re.fullmatch(r"\d+\.\d+\.\d+", path.name)
            or not properties.is_file()
        ):
            continue
        revision = re.search(
            r"(?m)^\s*Pkg\.Revision\s*=\s*(\S+)\s*$",
            properties.read_text(encoding="utf-8"),
        )
        # SDK preview directories can have numeric names. Their revision still
        # carries a beta/rc suffix, so use package metadata to reject previews.
        if revision and revision.group(1) == path.name:
            candidates.append((tuple(map(int, path.name.split("."))), path))
    if not candidates:
        raise RuntimeError(f"no installed stable Android NDK for major {selector}")
    return max(candidates, key=lambda candidate: candidate[0])[1].resolve()


def build_android() -> Path:
    if platform.system() not in {"Darwin", "Linux"}:
        raise RuntimeError("Android artifacts must be built on macOS or Linux")
    ndk_home = _android_ndk_home()
    android_api = _env("VOLE_ANDROID_API", "24")
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VOLE_FEATURES", DEFAULT_FEATURES))
    targets = _env(
        "VOLE_ANDROID_TARGETS", "aarch64-linux-android x86_64-linux-android"
    ).split()
    if not targets:
        raise RuntimeError("VOLE_ANDROID_TARGETS must not be empty")
    output = Path(
        _env("VOLE_ANDROID_OUTPUT_DIR", CORE_DIR / "dist" / "android")
    ).resolve()
    toolchain = _android_toolchain(ndk_home)

    base_env = os.environ.copy()
    base_env.update(
        {
            "ANDROID_NDK_HOME": str(ndk_home),
            "ANDROID_NDK_ROOT": str(ndk_home),
            "ANDROID_NDK": str(ndk_home),
        }
    )
    if profile_name == "release":
        base_env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"

    for target in targets:
        abi, clang, cargo_name = _android_target(target, android_api)
        linker = toolchain / "bin" / clang
        cpp = toolchain / "bin" / (clang + "++")
        archive = toolchain / "bin" / "llvm-ar"
        if not linker.is_file():
            raise RuntimeError(f"Android linker not found: {linker}")
        if not archive.is_file():
            raise RuntimeError(f"Android archiver not found: {archive}")
        if not cpp.is_file():
            raise RuntimeError(f"Android C++ compiler not found: {cpp}")
        runtime_target = (
            "arm-linux-androideabi" if target == "armv7-linux-androideabi" else target
        )
        cpp_runtime = (
            toolchain / "sysroot/usr/lib" / runtime_target / "libc++_shared.so"
        )
        if not cpp_runtime.is_file():
            raise RuntimeError(f"Android C++ runtime not found: {cpp_runtime}")
        target_env = target.replace("-", "_")
        bindgen_key = f"BINDGEN_EXTRA_CLANG_ARGS_{target}"
        bindgen_extra = base_env.get(
            bindgen_key,
            base_env.get(
                f"BINDGEN_EXTRA_CLANG_ARGS_{target_env}",
                base_env.get("BINDGEN_EXTRA_CLANG_ARGS", ""),
            ),
        )
        env = base_env | {
            f"CC_{target_env}": str(linker),
            f"CXX_{target_env}": str(cpp),
            f"AR_{target_env}": str(archive),
            f"CARGO_TARGET_{cargo_name}_LINKER": str(linker),
            f"CARGO_TARGET_{cargo_name}_AR": str(archive),
            f"CMAKE_TOOLCHAIN_FILE_{target_env}": str(
                CORE_DIR / "scripts/cmake/android.toolchain.cmake"
            ),
            "VOLE_CMAKE_ANDROID_ABI": abi,
            "VOLE_CMAKE_ANDROID_API": android_api,
            # NDK 30 rejects bindgen's default unversioned Rust target. Use
            # the same API-qualified compiler triple as CC/CXX and CMake.
            bindgen_key: (
                f"--target={clang.removesuffix('-clang')} {bindgen_extra}"
            ).strip(),
        }
        _cargo_build(target, profile_flags, features, env)
        artifact = _cargo_target_dir(env) / target / profile_name / "libvole.so"
        destination = output / abi / "libvole.so"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifact, destination)
        # BoringSSL links the NDK shared C++ runtime. It is not supplied by
        # Android itself; distribute the matching ABI/runtime alongside Vole.
        shutil.copy2(cpp_runtime, destination.parent / cpp_runtime.name)

    print(output)
    return output


def build_apple_target(target: str) -> Path:
    if platform.system() != "Darwin":
        raise RuntimeError("Apple artifacts must be built on macOS")
    if target not in APPLE_TARGETS:
        raise ValueError("unsupported Apple Rust target")
    profile_name, profile_flags = _profile()
    features = _production_features(_env("VOLE_FEATURES", DEFAULT_FEATURES))
    env = os.environ.copy()
    env["IPHONEOS_DEPLOYMENT_TARGET"] = _env("VOLE_IOS_DEPLOYMENT_TARGET", "13.0")
    env["MACOSX_DEPLOYMENT_TARGET"] = _env("VOLE_MACOS_DEPLOYMENT_TARGET", "10.15")
    env["TVOS_DEPLOYMENT_TARGET"] = tvos_deployment_target()
    if profile_name == "release":
        env["CARGO_PROFILE_RELEASE_PANIC"] = "unwind"
    return _cargo_build(target, profile_flags, features, env) / "libvole.a"


def assemble_apple(artifacts: dict[str, Path]) -> Path:
    if platform.system() != "Darwin":
        raise RuntimeError("Apple artifacts must be assembled on macOS")
    env = os.environ.copy()
    dist = Path(_env("VOLE_APPLE_DIST_DIR", CORE_DIR / "dist" / "apple")).resolve()
    work = _cargo_target_dir(env) / "vole-apple"
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(dist / "LibVole.xcframework", ignore_errors=True)
    for directory in (
        "ios-device",
        "ios-simulator",
        "macos",
        "tvos-device",
        "tvos-simulator",
    ):
        (work / directory).mkdir(parents=True)
    headers = work / "include"
    headers.mkdir()
    for name in ("vole.h", "module.modulemap"):
        shutil.copy2(CORE_DIR / "include" / name, headers / name)
    dist.mkdir(parents=True, exist_ok=True)

    shutil.copy2(artifacts["aarch64-apple-ios"], work / "ios-device/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-ios-sim"], work / "ios-simulator/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-tvos"], work / "tvos-device/libvole.a")
    shutil.copy2(artifacts["aarch64-apple-tvos-sim"], work / "tvos-simulator/libvole.a")
    _run(
        [
            "xcrun",
            "lipo",
            "-create",
            artifacts["aarch64-apple-darwin"],
            artifacts["x86_64-apple-darwin"],
            "-output",
            work / "macos/libvole.a",
        ],
        env=env,
    )
    output = dist / "LibVole.xcframework"
    _run(
        [
            "xcodebuild",
            "-create-xcframework",
            "-library",
            work / "ios-device/libvole.a",
            "-headers",
            headers,
            "-library",
            work / "ios-simulator/libvole.a",
            "-headers",
            headers,
            "-library",
            work / "macos/libvole.a",
            "-headers",
            headers,
            "-library",
            work / "tvos-device/libvole.a",
            "-headers",
            headers,
            "-library",
            work / "tvos-simulator/libvole.a",
            "-headers",
            headers,
            "-output",
            output,
        ],
        env=env,
    )
    print(output)
    return dist


def build_apple() -> Path:
    artifacts = {target: build_apple_target(target) for target in APPLE_TARGETS}
    return assemble_apple(artifacts)


def _windows_architecture() -> str:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    ) as key:
        processor = str(winreg.QueryValueEx(key, "PROCESSOR_ARCHITECTURE")[0]).lower()
    try:
        architecture = {"amd64": "x64", "arm64": "arm64"}[processor]
    except KeyError as error:
        raise RuntimeError(
            f"unsupported native Windows processor architecture: {processor}"
        ) from error
    python_platform = {"x64": "win-amd64", "arm64": "win-arm64"}[architecture]
    if sysconfig.get_platform() != python_platform:
        raise RuntimeError(
            f"Windows {architecture} builds require native {architecture} Python"
        )
    return architecture


def _windows_msvc_environment(architecture: str) -> dict[str, str]:
    if architecture != _windows_architecture():
        raise ValueError("Windows builds require the native host architecture")
    component = "ARM64" if architecture == "arm64" else "x86.x64"
    program_files = os.environ.get("PROGRAMFILES(X86)")
    if not program_files:
        raise RuntimeError("ProgramFiles(x86) is unavailable")
    vswhere = (
        Path(program_files) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    )
    result = subprocess.run(
        [
            vswhere,
            "-latest",
            "-products",
            "*",
            "-requires",
            f"Microsoft.VisualStudio.Component.VC.Tools.{component}",
            "-find",
            r"VC\Auxiliary\Build\vcvarsall.bat",
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    vcvars = next((line.strip() for line in result.stdout.splitlines() if line), None)
    if not vcvars:
        raise RuntimeError("Visual Studio C++ tools were not found")
    vc_target = "arm64" if architecture == "arm64" else "amd64"
    with tempfile.TemporaryDirectory(prefix="vole-msvc-") as directory:
        command = Path(directory) / "environment.cmd"
        command.write_bytes(
            (
                "@echo off\r\n"
                f'call "{vcvars}" {vc_target} >nul\r\n'
                "if errorlevel 1 exit /b %errorlevel%\r\n"
                "set\r\n"
            ).encode(locale.getpreferredencoding(False))
        )
        configured = subprocess.run(
            [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", command],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
    env = {}
    for line in configured.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key:
            env[key] = value
    if architecture == "arm64":
        search_path = next(value for key, value in env.items() if key.upper() == "PATH")
        compilers = {
            name: shutil.which(name, path=search_path)
            for name in ("clang-cl", "clang", "ninja")
        }
        if not all(compilers.values()):
            raise RuntimeError(
                "native Windows ARM64 requires LLVM clang-cl/clang and Ninja"
            )
        # Visual Studio's generator does not assemble BoringSSL's preprocessed
        # .S inputs. Keep assembly enabled using LLVM + Ninja, still MSVC ABI,
        # the selected Windows SDK, and the same static CRT. No source patch.
        env.update(
            {
                "CC_aarch64_pc_windows_msvc": compilers["clang-cl"],
                "CXX_aarch64_pc_windows_msvc": compilers["clang-cl"],
                "VOLE_WINDOWS_ARM64_CLANG": compilers["clang"],
                "CMAKE_GENERATOR_aarch64_pc_windows_msvc": "Ninja",
                "CMAKE_TOOLCHAIN_FILE_aarch64_pc_windows_msvc": str(
                    CORE_DIR / "scripts/cmake/windows-arm64.toolchain.cmake"
                ),
            }
        )
    return env


def build_windows(backend: str = "uwp") -> Path:
    if platform.system() != "Windows":
        raise RuntimeError("Windows artifacts must be built on Windows")
    features = windows_features(backend)
    architecture = _windows_architecture()
    env = _windows_msvc_environment(architecture)
    output = CORE_DIR / "dist" / "windows" / architecture / backend
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True)
    targets = {
        "arm64": "aarch64-pc-windows-msvc",
        "x64": "x86_64-pc-windows-msvc",
    }
    target = targets[architecture]
    release = _cargo_build(
        target,
        ["--release"],
        features,
        env,
        ("--lib", "--bins") if backend == "uwp" else ("--lib",),
    )
    artifacts = ["vole.dll", "vole.dll.lib"]
    headers = ["vole.h"]
    if backend == "uwp":
        artifacts += ["vole-windows-vpn-host.exe", "vole-windows-session-host.exe"]
        headers.append("vole_windows_uwp.h")
    for name in artifacts:
        shutil.copy2(release / name, output / name)
    (output / "include").mkdir()
    for name in headers:
        shutil.copy2(CORE_DIR / "include" / name, output / "include" / name)
    print(output)

    return output
