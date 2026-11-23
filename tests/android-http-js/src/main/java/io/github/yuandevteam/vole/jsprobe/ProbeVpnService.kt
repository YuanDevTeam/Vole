package io.github.yuandevteam.vole.jsprobe

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.system.Os
import android.system.OsConstants
import android.util.Base64
import android.util.Log
import io.github.yuandevteam.vole.NativeVole
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.Proxy
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class ProbeVpnService : VpnService() {
    private val running = AtomicBoolean()
    private val protectedSockets = AtomicInteger()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running.compareAndSet(false, true)) {
            Thread({ runProbe(startId) }, "vole-js-probe").start()
        }
        return START_NOT_STICKY
    }

    private fun runProbe(startId: Int) {
        try {
            runSuite()
            Log.i(TAG, "PASS Android HTTP JS")
        } catch (error: Throwable) {
            Log.e(TAG, "FAIL Android HTTP JS", error)
        } finally {
            running.set(false)
            stopSelf(startId)
        }
    }

    private fun runSuite() {
        Log.i(TAG, "API ${Build.VERSION.SDK_INT}, ABI ${Build.SUPPORTED_ABIS.first()}, " +
            "page bytes ${Os.sysconf(OsConstants._SC_PAGESIZE)}, QuickJS-NG")
        val plugin = assets.open("http-js-platform.yaml").bufferedReader().use { it.readText() }
        val certificate = filesDir.resolve("ca.pem").readText()
        val privateKey = filesDir.resolve("mitm-key.pem").readText()
        val settings = JSONObject().put("mitmEnabled", true)
        verifyOffline(plugin, settings)
        check(NativeVole.nativeRegisterProtectController(ProtectController())) { "register socket protector" }
        try {
            withTunnel { fd, sockets ->
                runNetwork(plugin, certificate, privateKey, settings, fd, sockets)
            }
        } finally {
            check(NativeVole.nativeUnregisterProtectController()) { "unregister socket protector" }
        }
        verifyOfflineLocal(plugin, settings)
        verifyBodyBoundary()
    }

    // JNI must call the actual VpnService protect before connecting physical
    // sockets, including when origin and captured traffic use the same IP.
    inner class ProtectController {
        fun protect(fd: Int): Boolean {
            val result = this@ProbeVpnService.protect(fd)
            if (result) protectedSockets.incrementAndGet()
            return result
        }
    }

    private fun withTunnel(operation: (Int, SocketFactory) -> Unit) {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val ready = CompletableFuture<Network>()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) {
                if (link.linkAddresses.any { it.address.hostAddress == TUN_ADDRESS } &&
                    link.routes.any {
                        it.destination.prefixLength == 32 &&
                            it.destination.address.hostAddress == ORIGIN_ADDRESS
                    }) {
                    ready.complete(network)
                }
            }
        }
        val request = NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .build()
        connectivity.registerNetworkCallback(request, callback)
        try {
            val vpn = Builder()
                .setSession("Vole HTTP JS Test")
                .setMtu(1500)
                .setBlocking(false)
                .addAddress(TUN_ADDRESS, 32)
                .addRoute(ORIGIN_ADDRESS, 32)
                .addAllowedApplication(packageName)
                .establish() ?: error("establish raw-IP VPN")
            vpn.use {
                operation(it.fd, ready.get(5, TimeUnit.SECONDS).socketFactory)
            }
        } finally {
            connectivity.unregisterNetworkCallback(callback)
        }
    }

    private fun runNetwork(
        plugin: String,
        certificate: String,
        key: String,
        settings: JSONObject,
        fd: Int,
        sockets: SocketFactory
    ) {
        val pem = certificate.trim().lines().joinToString("\n") { "      $it" }
        val config = """
            mode: rule
            tun:
              enable: true
              mtu: 1500
              file-descriptor: $fd
            hosts:
              $ORIGIN_NAME: $ORIGIN_ADDRESS
            sniffer:
              enable: true
              parse-pure-ip: true
              override-destination: true
              sniff:
                HTTP: {ports: [18080]}
                TLS: {ports: [18443, 18444]}
            tls:
              custom-certifactes:
                - |-
        """.trimIndent() + "\n$pem\nrules: ['MATCH,DIRECT']\n"
        val start = JSONObject().put("configYaml", config).put("httpConfigYaml", plugin)
            .put("httpContext", JSONObject(settings.toString()).put(
                "ca", JSONObject().put("certificate", certificate).put("privateKey", key)
            ))
        invoke("initialize", JSONObject().put("dataDir", filesDir.resolve("core").absolutePath))
        val id = invoke("createInstance").getString("instanceId")
        try {
            invoke("start", start, id)
            val protectedBefore = protectedSockets.get()
            verifyNetwork(sockets, certificate, "http", 18080, Protocol.HTTP_1_1, "HTTP/1.1")
            verifyNetwork(sockets, certificate, "https", 18443, Protocol.HTTP_1_1, "HTTP/1.1")
            verifyNetwork(sockets, certificate, "https", 18444, Protocol.HTTP_2, "HTTP/2.0")
            check(protectedSockets.get() >= protectedBefore + 3) { "traffic did not dial protected sockets" }
            invoke("reconnect", start, id)
            verifyNetwork(sockets, certificate, "https", 18444, Protocol.HTTP_2, "HTTP/2.0")
            invoke("stop", instance = id)
            check(invoke("getState", instance = id).getString("state") == "stopped")
            Log.i(TAG, "PASS TUN reconnect and stop")
        } finally {
            invoke("destroyInstance", instance = id)
        }
    }

    private fun verifyNetwork(
        sockets: SocketFactory,
        certificate: String,
        scheme: String,
        port: Int,
        protocol: Protocol,
        origin: String
    ) {
        val trust = trustFixtureCa(certificate)
        val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        val protocols = if (protocol == Protocol.HTTP_2) listOf(Protocol.HTTP_2, Protocol.HTTP_1_1)
            else listOf(Protocol.HTTP_1_1)
        val client = OkHttpClient.Builder()
            .proxy(Proxy.NO_PROXY)
            .socketFactory(sockets)
            .dns(Dns { name ->
                require(name == ORIGIN_NAME)
                listOf(InetAddress.getByName(ORIGIN_ADDRESS))
            })
            .sslSocketFactory(tls.socketFactory, trust)
            .protocols(protocols)
            .callTimeout(10, TimeUnit.SECONDS)
            .build()
        try {
            val request = Request.Builder().url("$scheme://$ORIGIN_NAME:$port/rewrite")
                .post("probe".toRequestBody("application/octet-stream".toMediaType()))
                .build()
            val before = protectedSockets.get()
            client.newCall(request).execute().use { response ->
                val delta = protectedSockets.get() - before
                check(response.code == 200) { "$scheme/$protocol status ${response.code}, protect=$delta" }
                check(delta > 0) { "request did not dial a protected origin socket" }
                check(response.protocol == protocol) { "negotiated ${response.protocol}, expected $protocol" }
                check(response.header("X-Origin-Protocol") == origin) { "wrong origin ALPN" }
                check(response.header("x-vole-response") == "js") { "response script header absent" }
                check(response.body.string() == "origin:probe:js:改写") { "incorrect response body" }
            }
            Log.i(TAG, "PASS TUN $scheme/$protocol origin=$origin")
        } finally {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }

    private fun verifyOffline(plugin: String, settings: JSONObject) {
        val upload = JSONArray().put(JSONArray().put("Content-Type").put("application/octet-stream"))
        val download = JSONArray().put(JSONArray().put("Content-Type").put("text/plain; charset=utf-8"))
        val result = invoke("testHttp", JSONObject()
            .put("httpConfigYaml", plugin).put("httpContext", settings)
            .put("url", "https://$ORIGIN_NAME:18444/rewrite").put("executeScripts", true)
            .put("request", JSONObject().put("method", "POST").put("headers", upload)
                .put("bodyBase64", encode("probe")))
            .put("response", JSONObject().put("status", 200).put("headers", download)
                .put("bodyBase64", encode("origin:probe:js"))))
        check(result.isNull("terminal")) { "testHttp ${result.opt("terminal")}" }
        val stages = result.getJSONArray("stages")
        val request = stages.getJSONObject(0)
        val response = stages.getJSONObject(1)
        check(request.getString("bodyBase64") == encode("probe:js")) { "request rewrite missing: $request" }
        check(response.getString("bodyBase64") == encode("origin:probe:js:改写")) { "response rewrite missing: $response" }
        check(response.getJSONArray("scripts").getJSONObject(1).getString("outcome") == "rolled-back")
        verifyOfflineLocal(plugin, settings)
        Log.i(TAG, "PASS testHttp request bytes, Unicode response and rollback")
    }

    private fun verifyOfflineLocal(plugin: String, settings: JSONObject) {
        val result = invoke("testHttp", JSONObject()
            .put("httpConfigYaml", plugin).put("httpContext", settings)
            .put("url", "https://$ORIGIN_NAME:18444/local").put("executeScripts", true)
            .put("request", JSONObject().put("method", "GET")))
        val terminal = result.getJSONObject("terminal")
        check(terminal.getInt("status") == 202 && terminal.getString("bodyBase64") == encode("local-js"))
        Log.i(TAG, "PASS testHttp local response")
    }

    private fun verifyBodyBoundary() {
        val input = ByteArray(256 * 1024) { it.toByte() }
        val plugin = """
            targets:
              - origins: [http://js-rewrite.test:18080]
                rules:
                  - request:
                      js:
                        body: bytes
                        source: |
                          function rewrite(input) {
                            const bytes = Vole.copyBytes(input.body.data);
                            bytes[0] = 9;
                            return {type: "modify", body: {kind: "bytes", data: bytes}};
                          }
        """.trimIndent()
        val result = invoke("testHttp", JSONObject()
            .put("httpConfigYaml", plugin).put("executeScripts", true)
            .put("url", "http://$ORIGIN_NAME:18080/boundary")
            .put("request", JSONObject().put("method", "POST")
                .put("bodyBase64", Base64.encodeToString(input, Base64.NO_WRAP))))
        check(result.isNull("terminal")) { "256 KiB testHttp ${result.opt("terminal")}" }
        val stage = result.getJSONArray("stages").getJSONObject(0)
        input[0] = 9
        check(Base64.decode(stage.getString("bodyBase64"), Base64.DEFAULT).contentEquals(input)) {
            "256 KiB binary output did not match"
        }
        Log.i(TAG, "PASS testHttp 256 KiB binary round trip")
    }

    private fun trustFixtureCa(pem: String): X509TrustManager {
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(pem.byteInputStream())
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("fixture", certificate)
        }
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
            init(roots)
            trustManagers.filterIsInstance<X509TrustManager>().single()
        }
    }

    private fun invoke(method: String, payload: JSONObject = JSONObject(), instance: String? = null): JSONObject {
        val input = JSONObject().put("method", method).put("payload", payload)
        if (instance != null) input.put("instanceId", instance)
        val result = JSONObject(String(NativeVole.nativeInvoke(input.toString().toByteArray()), Charsets.UTF_8))
        check(result.getBoolean("success")) { "$method: ${result.getString("error")}" }
        return result.getJSONObject("data")
    }

    private fun encode(value: String): String = Base64.encodeToString(value.toByteArray(), Base64.NO_WRAP)

    companion object {
        const val TAG = "VoleJsProbe"
        private const val ORIGIN_NAME = "js-rewrite.test"
        private const val ORIGIN_ADDRESS = "10.0.2.2"
        private const val TUN_ADDRESS = "198.18.0.1"
    }
}
