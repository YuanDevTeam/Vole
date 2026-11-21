# Android HTTP JS test host

Use the Core Android build from this checkout, Gradle 9.9.2, Android SDK
platform 37.2, and an emulator with a WebView provider that supports the JavaScriptEngine features
checked by the host. The application needs Android API 26 or later. It uses
a package-specific VpnService with a route for the emulator host alias
`10.0.2.2`, and allows only the test application into that tunnel.

Configure an isolated test origin published on the emulator host at ports
18080 (HTTP/1.1), 18443 (TLS HTTP/1.1), and 18444 (TLS HTTP/2). Use a
certificate for `js-rewrite.test` signed by the fixture CA. On POST
`/rewrite`, verify `x-vole-native: ready`, `x-vole-request: js` and body
`probe:js`. A successful origin response contains body `origin:probe:js`
and an `X-Origin-Protocol` header recording the origin connection's HTTP
version as `HTTP/1.1` or `HTTP/2.0`.

From Core, build and install the test APK using the existing Android build
and its ABI-specific `libvole.so` and `libc++_shared.so` artifacts:

```sh
VOLE_ANDROID_TARGETS=aarch64-linux-android uv run --project scripts --locked vole-scripts build android
gradle -p tests/android-http-js installDebug
```

Set `-PvoleJniLibs=/absolute/path/to/android` when the native build uses a
custom output directory. Set `ANDROID_SERIAL` for the selected emulator.
Copy only the temporary test CA and its private key to the debug app's
private data directory, then start its launcher activity:

```sh
probe=io.github.yuandevteam.vole.jsprobe
adb shell -T "run-as $probe sh -c 'mkdir -p files; umask 077; cat > files/ca.pem'" < ca.pem
adb shell -T "run-as $probe sh -c 'umask 077; cat > files/mitm-key.pem'" < mitm-key.pem
adb shell am start -n "$probe/.ProbeActivity"
adb logcat -s VoleJsProbe
```

Approve the emulator's VPN prompt on the first run. The host runs a
JavaScriptEngine termination/reopen probe, exercises `testHttp` before
startup, verifies each protocol over the raw-IP TUN, and confirms reconnect
and stop. Test code checks both TLS legs' negotiated protocols and the final
body. A separate offline sample checks a 256 KiB MessagePort round trip.
The terminal result is `PASS Android HTTP JS` or `FAIL Android HTTP JS`.
Uninstall the debug test package to remove its private fixture material.
