"""Check platform outputs around the external compiler boundary."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vole_scripts import builds, cli


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("vole.h", "vole_windows_uwp.h", "module.modulemap"):
            self.write(
                Path("include") / name,
                (builds.CORE_DIR / "include" / name).read_bytes(),
            )
        self.enterContext(patch.object(builds, "CORE_DIR", self.root))
        self.enterContext(
            patch.dict(os.environ, {"CARGO_TARGET_DIR": "cache"}, clear=True)
        )
        self.commands = []
        self.enterContext(patch.object(builds, "_run", side_effect=self.compile))
        self.enterContext(
            patch.object(
                builds.blake3,
                "environment",
                side_effect=lambda target, host, env, backend: env,
            )
        )

    def write(self, relative, data=b"library"):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def compile(self, command, *, env):
        self.commands.append((command, env))
        if command[:2] == ["xcrun", "lipo"]:
            Path(command[-1]).write_bytes(b"universal library")
        elif command[:2] == ["cargo", "build"]:
            target = command[command.index("--target") + 1]
            for name in (
                "vole",
                "vole.exe",
                "vole.dll",
                "vole.dll.lib",
                "vole-windows-vpn-host.exe",
                "vole-windows-session-host.exe",
                "libvole.so",
                "libvole.a",
            ):
                self.write(f"cache/{target}/release/{name}")

    def test_windows_cli_and_ffi_select_their_backends(self):
        with (
            patch.object(builds.platform, "system", return_value="Windows"),
            patch.object(builds, "_windows_architecture", return_value="arm64"),
            patch.object(
                builds, "_windows_msvc_environment", return_value=dict(os.environ)
            ),
        ):
            binary = builds.build_cli()
            self.assertEqual(binary.read_bytes(), b"library")
            cli_command = self.commands[-1][0]
            self.assertEqual(
                cli_command[cli_command.index("--features") + 1], "cli,windows-wintun"
            )
            wintun = builds.build_windows("wintun")
            uwp = builds.build_windows("uwp")
        self.assertEqual(
            {
                p.relative_to(wintun).as_posix()
                for p in wintun.rglob("*")
                if p.is_file()
            },
            {"vole.dll", "vole.dll.lib", "include/vole.h"},
        )
        self.assertEqual(
            {p.relative_to(uwp).as_posix() for p in uwp.rglob("*") if p.is_file()},
            {
                "vole.dll",
                "vole.dll.lib",
                "include/vole.h",
                "include/vole_windows_uwp.h",
                "vole-windows-vpn-host.exe",
                "vole-windows-session-host.exe",
            },
        )
        for output in (wintun, uwp):
            for header in (output / "include").iterdir():
                self.assertEqual(
                    header.read_bytes(),
                    (self.root / "include" / header.name).read_bytes(),
                )
        for (command, _), backend in zip(
            self.commands[1:], ("wintun", "uwp"), strict=True
        ):
            self.assertEqual(
                command[command.index("--features") + 1], f"ffi,windows-{backend}"
            )
            self.assertEqual("--bins" in command, backend == "uwp")

    def test_linux_cli_and_ffi_preserve_transport_features(self):
        target = "aarch64-unknown-linux-gnu"
        with (
            patch.object(builds.platform, "system", return_value="Linux"),
            patch.object(builds, "native_target", return_value=target),
        ):
            builds.build_cli()
            builds.build_linux()
        self.assertEqual(
            [command[command.index("--features") + 1] for command, _ in self.commands],
            ["cli", "ffi"],
        )

    def test_windows_requires_native_python(self):
        registry = MagicMock()
        with patch.dict("sys.modules", {"winreg": registry}):
            for processor, architecture, native_python in (
                ("AMD64", "x64", "win-amd64"),
                ("ARM64", "arm64", "win-arm64"),
            ):
                registry.QueryValueEx.return_value = (processor, 0)
                for python_platform in ("win-amd64", "win-arm64", "win32"):
                    with (
                        self.subTest(host=processor, python=python_platform),
                        patch.object(
                            builds.sysconfig,
                            "get_platform",
                            return_value=python_platform,
                        ),
                    ):
                        if python_platform == native_python:
                            self.assertEqual(
                                builds._windows_architecture(), architecture
                            )
                        else:
                            with self.assertRaisesRegex(
                                RuntimeError, "native .* Python"
                            ):
                                builds._windows_architecture()

    def test_windows_cli_rejects_cross_architecture_before_compilation(self):
        for host, target in (
            ("arm64", "x86_64-pc-windows-msvc"),
            ("x64", "aarch64-pc-windows-msvc"),
        ):
            with (
                self.subTest(host=host),
                patch.object(builds.platform, "system", return_value="Windows"),
                patch.object(builds, "_windows_architecture", return_value=host),
                patch.object(builds.subprocess, "run") as run,
                self.assertRaisesRegex(ValueError, "native host architecture"),
            ):
                builds.build_cli(target)
            run.assert_not_called()
        self.assertEqual(self.commands, [])

    def test_windows_msvc_selects_native_host_tools(self):
        for architecture, vc_target, component in (
            ("x64", "amd64", "x86.x64"),
            ("arm64", "arm64", "ARM64"),
        ):

            def configure(
                command,
                *,
                architecture=architecture,
                vc_target=vc_target,
                component=component,
                **kwargs,
            ):
                if "-find" in command:
                    self.assertIn(
                        f"Microsoft.VisualStudio.Component.VC.Tools.{component}",
                        command,
                    )
                    output = "C:\\VS\\vcvarsall.bat\n"
                else:
                    script = Path(command[-1]).read_text()
                    self.assertIn(
                        f'call "C:\\VS\\vcvarsall.bat" {vc_target} >nul', script
                    )
                    output = f"Path=tools\nVSCMD_ARG_HOST_ARCH={architecture}\n"
                return builds.subprocess.CompletedProcess(command, 0, stdout=output)

            with (
                self.subTest(architecture=architecture),
                patch.dict(os.environ, {"PROGRAMFILES(X86)": str(self.root)}),
                patch.object(
                    builds, "_windows_architecture", return_value=architecture
                ),
                patch.object(builds.subprocess, "run", side_effect=configure),
                patch.object(
                    builds.shutil,
                    "which",
                    side_effect=lambda name, **kw: f"tools/{name}",
                ),
            ):
                env = builds._windows_msvc_environment(architecture)
            self.assertEqual(env["VSCMD_ARG_HOST_ARCH"], architecture)
            if architecture == "arm64":
                self.assertEqual(env["CC_aarch64_pc_windows_msvc"], "tools/clang-cl")

    def test_android_uses_matching_api_and_cpp_runtime(self):
        toolchain = self.root / "ndk/toolchain"
        for target, abi in (
            ("aarch64-linux-android", "arm64-v8a"),
            ("x86_64-linux-android", "x86_64"),
        ):
            for name in (target + "28-clang", target + "28-clang++", "llvm-ar"):
                self.write(toolchain / "bin" / name)
            self.write(
                toolchain / "sysroot/usr/lib" / target / "libc++_shared.so",
                abi.encode(),
            )
        with (
            patch.object(builds.platform, "system", return_value="Linux"),
            patch.object(builds, "_android_toolchain", return_value=toolchain),
            patch.dict(
                os.environ,
                {"ANDROID_NDK_HOME": str(self.root / "ndk"), "VOLE_ANDROID_API": "28"},
            ),
        ):
            output = builds.build_android()
        for command, env in self.commands:
            target = command[command.index("--target") + 1]
            abi = env["VOLE_CMAKE_ANDROID_ABI"]
            self.assertEqual(
                command[command.index("--features") + 1],
                "ffi",
            )
            self.assertEqual(
                env[f"BINDGEN_EXTRA_CLANG_ARGS_{target}"], f"--target={target}28"
            )
            self.assertEqual(env["VOLE_CMAKE_ANDROID_API"], "28")
            self.assertEqual((output / abi / "libvole.so").read_bytes(), b"library")
            self.assertEqual(
                (output / abi / "libc++_shared.so").read_bytes(), abi.encode()
            )

    def test_apple_build_stages_five_slices_from_six_targets(self):
        with patch.object(builds.platform, "system", return_value="Darwin"):
            builds.build_apple()
        work = self.root / "cache/vole-apple"
        self.assertEqual(
            {p.name for p in work.iterdir()},
            {
                "include",
                "ios-device",
                "ios-simulator",
                "macos",
                "tvos-device",
                "tvos-simulator",
            },
        )
        self.assertEqual((work / "macos/libvole.a").read_bytes(), b"universal library")
        self.assertEqual((work / "ios-simulator/libvole.a").read_bytes(), b"library")
        self.assertEqual(
            {p.name for p in (work / "include").iterdir()},
            {"vole.h", "module.modulemap"},
        )
        self.assertEqual(
            sum(command[:2] == ["cargo", "build"] for command, _ in self.commands), 6
        )
        self.assertTrue(
            all(
                command[command.index("--features") + 1] == "ffi"
                for command, _ in self.commands
                if command[:2] == ["cargo", "build"]
            )
        )
        self.assertEqual(
            self.commands[-1][0][:2], ["xcodebuild", "-create-xcframework"]
        )

        # A separate runner only has downloaded libraries, not Cargo outputs.
        downloaded = {
            target: self.write(f"incoming/{target}/libvole.a", target.encode())
            for target in builds.APPLE_TARGETS
        }
        self.commands.clear()
        with patch.object(builds.platform, "system", return_value="Darwin"):
            builds.assemble_apple(downloaded)
        self.assertEqual(
            [command[:2] for command, _ in self.commands],
            [["xcrun", "lipo"], ["xcodebuild", "-create-xcframework"]],
        )
        self.assertEqual(
            (work / "ios-simulator/libvole.a").read_bytes(), b"aarch64-apple-ios-sim"
        )

    def test_apple_preserves_production_override_and_rejects_test_features(self):
        with (
            patch.object(builds.platform, "system", return_value="Darwin"),
            patch.dict(os.environ, {"VOLE_FEATURES": "ffi,controller"}),
        ):
            builds.build_apple_target("aarch64-apple-ios")
        command = self.commands[-1][0]
        self.assertEqual(command[command.index("--features") + 1], "ffi,controller")
        self.commands.clear()
        with (
            patch.object(builds.platform, "system", return_value="Darwin"),
            patch.dict(os.environ, {"VOLE_FEATURES": "ffi,interop-test"}),
            self.assertRaisesRegex(RuntimeError, "test-only features"),
        ):
            builds.build_apple_target("aarch64-apple-ios")
        self.assertEqual(self.commands, [])

    def test_ndk_selection_uses_latest_installed_stable_revision(self):
        for version in ("30.2.9", "30.2.10", "30.10.1", "30.99.1-beta1"):
            folder = version.removesuffix("-beta1")
            self.write(
                f"sdk/ndk/{folder}/source.properties",
                f"Pkg.Revision = {version}\n".encode(),
            )
        with patch.dict(os.environ, {"ANDROID_HOME": str(self.root / "sdk")}):
            self.assertEqual(builds._android_ndk_home(), self.root / "sdk/ndk/30.10.1")


class BuildCliTests(unittest.TestCase):
    def test_arguments_reach_each_platform_builder(self):
        for platform in ("cli", "apple", "android", "windows", "linux"):
            args = ["build", platform]
            positional = ()
            if platform == "cli":
                args += ["--target", "aarch64-apple-darwin", "--profile", "debug"]
                positional = ("aarch64-apple-darwin", "debug")
            elif platform == "windows":
                args += ["--backend", "wintun"]
                positional = ("wintun",)
            with (
                self.subTest(platform=platform),
                patch.object(cli, "build_" + platform) as build,
            ):
                self.assertEqual(cli.main(args), 0)
            build.assert_called_once_with(*positional)
