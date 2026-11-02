"""Check target/SDK selection and package acquisition without native builds."""

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from vole_scripts import blake3


class Blake3DependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = "aarch64-unknown-linux-gnu"

    def package(self, root):
        for path in (root / "include/blake3.h", root / "lib/libblake3.a"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"native fixture")
        return str(root / "include"), str(root / "lib")

    def test_explicit_native_paths_do_not_install_packages(self):
        include, lib = self.package(self.root)
        env = dict(zip(blake3.DEPENDENCY_NAMES, (include, lib), strict=True))
        with patch.object(blake3, "_run") as run:
            prepared = blake3.environment(self.target, self.target, env)
        run.assert_not_called()
        suffix = "_AARCH64_UNKNOWN_LINUX_GNU"
        self.assertEqual(prepared[blake3.DEPENDENCY_NAMES[0] + suffix], include)
        self.assertEqual(prepared[blake3.DEPENDENCY_NAMES[1] + suffix], lib)

    def test_partial_or_missing_explicit_packages_fail_before_acquisition(self):
        for env in (
            {blake3.DEPENDENCY_NAMES[0]: str(self.root)},
            dict(zip(blake3.DEPENDENCY_NAMES, ("", ""), strict=True)),
            dict(
                zip(blake3.DEPENDENCY_NAMES, ("relative", str(self.root)), strict=True)
            ),
        ):
            with (
                self.subTest(env=env),
                patch.object(blake3, "_run") as run,
                self.assertRaises(RuntimeError),
            ):
                blake3.environment(self.target, self.target, env)
            run.assert_not_called()

    def test_cross_build_uses_scoped_paths_without_host_fallback(self):
        include, lib = self.package(self.root)
        env = dict(
            zip(blake3.DEPENDENCY_NAMES, ("invalid host", "invalid host"), strict=True)
        )
        suffix = "_AARCH64_UNKNOWN_LINUX_GNU"
        env.update(
            {
                name + suffix: value
                for name, value in zip(
                    blake3.DEPENDENCY_NAMES, (include, lib), strict=True
                )
            }
        )
        with patch.object(blake3, "_run") as run:
            prepared = blake3.environment(self.target, "x86_64-apple-darwin", env)
        run.assert_not_called()
        self.assertEqual(prepared[blake3.DEPENDENCY_NAMES[0] + suffix], include)

    def test_all_apple_targets_select_their_sdk_and_minimum(self):
        expected = (
            ("aarch64-apple-ios", "iOS", "iphoneos", "13.0"),
            ("aarch64-apple-ios-sim", "iOS", "iphonesimulator", "14.0"),
            ("aarch64-apple-darwin", "Darwin", "macosx", "11.0"),
            ("x86_64-apple-darwin", "Darwin", "macosx", "10.15"),
            ("aarch64-apple-tvos", "tvOS", "appletvos", "17.0"),
            ("aarch64-apple-tvos-sim", "tvOS", "appletvsimulator", "17.0"),
        )
        for target, system, sdk, minimum in expected:
            with (
                self.subTest(target=target),
                patch.object(
                    blake3.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "/SDK\n"),
                ) as run,
            ):
                text, tracked = blake3._triplet(target, {}, "wintun")
            self.assertEqual(
                run.call_args.args[0], ["xcrun", "--sdk", sdk, "--show-sdk-path"]
            )
            self.assertIn(f"set(VCPKG_CMAKE_SYSTEM_NAME {system})", text)
            self.assertIn(f"set(VCPKG_OSX_DEPLOYMENT_TARGET {minimum})", text)
            self.assertEqual(
                any(path.name == "tvos.cmake" for path in tracked), system == "tvOS"
            )

    def test_android_keeps_the_selected_ndk_api_and_abi(self):
        for target, abi in (
            ("aarch64-linux-android", "arm64-v8a"),
            ("x86_64-linux-android", "x86_64"),
        ):
            with self.subTest(target=target):
                text, _ = blake3._triplet(
                    target,
                    {
                        "ANDROID_NDK_HOME": str(self.root),
                        "VOLE_CMAKE_ANDROID_API": "28",
                    },
                    "wintun",
                )
                self.assertIn(f"-DANDROID_ABI={abi}", text)
                self.assertIn("set(VCPKG_CMAKE_SYSTEM_VERSION 28)", text)
                self.assertIn(str(self.root), text)
                self.assertIn("-DCMAKE_POSITION_INDEPENDENT_CODE=ON", text)

    def test_windows_static_library_matches_backend_crt_and_app_api_family(self):
        for architecture in ("aarch64", "x86_64"):
            for backend, system in (("wintun", '""'), ("uwp", "WindowsStore")):
                with self.subTest(architecture=architecture, backend=backend):
                    text, _ = blake3._triplet(
                        f"{architecture}-pc-windows-msvc", {}, backend
                    )
                    runtime = "dynamic" if backend == "uwp" else "static"
                    self.assertIn(f"set(VCPKG_CRT_LINKAGE {runtime})", text)
                    self.assertIn("set(VCPKG_LIBRARY_LINKAGE static)", text)
                    self.assertIn(f"set(VCPKG_CMAKE_SYSTEM_NAME {system})", text)
                    self.assertIn("set(VCPKG_LOAD_VCVARS_ENV ON)", text)
                    if backend == "uwp":
                        self.assertIn("-DCMAKE_TRY_COMPILE_CONFIGURATION=Release", text)
                        self.assertIn("-DVCPKG_MSVC_CXX_WINRT_EXTENSIONS=OFF", text)
                        self.assertIn(
                            "-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES="
                            "VCPKG_MSVC_CXX_WINRT_EXTENSIONS",
                            text,
                        )

    def test_failed_install_reports_target_cmake_log_and_preserves_failure(self):
        manifest = json.loads((blake3.CONFIG_DIR / "vcpkg.json").read_text())
        registry = manifest["builtin-baseline"]
        checkout = self.root / ("vcpkg-" + registry)
        (checkout / ".git").mkdir(parents=True)
        (checkout / "vcpkg.exe").touch()

        def fail_install(command, environment):
            triplet = next(
                item.split("=", 1)[1]
                for item in command
                if item.startswith("--triplet=")
            )
            logs = checkout / "buildtrees/detect_compiler"
            logs.mkdir(parents=True)
            (logs / f"config-{triplet}-out.log").write_text(
                "outside diagnostic tail\n" + "x" * 20_000 + "\nSDK rc.exe missing\n"
            )
            (logs / "config-other-triplet-out.log").write_text("unrelated build")
            raise subprocess.CalledProcessError(29, command)

        output = io.StringIO()
        with (
            patch.object(blake3.platform, "system", return_value="Windows"),
            patch.object(blake3, "_run", side_effect=fail_install),
            patch.object(
                blake3.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, registry + "\n"),
            ),
            redirect_stdout(output),
            self.assertRaises(subprocess.CalledProcessError) as caught,
        ):
            blake3.environment(
                "x86_64-pc-windows-msvc",
                "x86_64-pc-windows-msvc",
                {"VOLE_NATIVE_CACHE_DIR": str(self.root)},
            )
        self.assertEqual(caught.exception.returncode, 29)
        self.assertIn("SDK rc.exe missing", output.getvalue())
        self.assertNotIn("outside diagnostic tail", output.getvalue())
        self.assertNotIn("unrelated build", output.getvalue())

    def test_normal_install_uses_official_locked_registry_and_target_package(self):
        manifest = json.loads((blake3.CONFIG_DIR / "vcpkg.json").read_text())
        registry = manifest["builtin-baseline"]
        env = {"VOLE_NATIVE_CACHE_DIR": str(self.root)}
        commands = []

        def install(command, environment):
            commands.append(command)
            if command[:2] == ["git", "clone"]:
                checkout = Path(command[-1])
                (checkout / ".git").mkdir(parents=True)
                (checkout / "vcpkg").write_bytes(b"tool fixture")
            elif "install" in command:
                triplet = next(
                    item.split("=", 1)[1]
                    for item in command
                    if item.startswith("--triplet=")
                )
                installed = next(
                    item.split("=", 1)[1]
                    for item in command
                    if item.startswith("--x-install-root=")
                )
                self.package(Path(installed) / triplet)

        target = "x86_64-unknown-linux-gnu"
        with (
            patch.object(blake3.platform, "system", return_value="Linux"),
            patch.object(blake3, "_run", side_effect=install),
            patch.object(
                blake3.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, registry + "\n"),
            ),
        ):
            prepared = blake3.environment(target, target, env)
        self.assertEqual(commands[0][4], "https://github.com/microsoft/vcpkg.git")
        self.assertEqual(commands[1][-1], registry)
        self.assertIn("--host-triplet=x64-linux", commands[-1])
        triplet = next(
            item.split("=", 1)[1]
            for item in commands[-1]
            if item.startswith("--triplet=")
        )
        self.assertRegex(triplet, r"^[a-z0-9-]+$")
        self.assertIn("--x-wait-for-lock", commands[-1])
        self.assertIn("--x-manifest-root=" + str(blake3.CONFIG_DIR), commands[-1])
        include = prepared["VOLE_BLAKE3_INCLUDE_DIR_X86_64_UNKNOWN_LINUX_GNU"]
        self.assertTrue((Path(include) / "blake3.h").is_file())
