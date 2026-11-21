package io.github.yuandevteam.vole

import android.content.Context
import androidx.javascriptengine.IsolateStartupParameters
import androidx.javascriptengine.IsolateTerminatedException
import androidx.javascriptengine.JavaScriptException
import androidx.javascriptengine.JavaScriptIsolate
import androidx.javascriptengine.JavaScriptSandbox
import androidx.javascriptengine.Message
import androidx.javascriptengine.MessagePort
import androidx.javascriptengine.SandboxUnsupportedException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

// The JavaScriptSandbox, message port, Future and invocation are owned by one
// executor. JNI calls prepare/close from blocking workers and never the UI thread.
class AndroidJsController(context: Context) : AutoCloseable {
    private val context = context.applicationContext
    private val owner = Executors.newSingleThreadExecutor { Thread(it, "vole-android-js") }
    private var sandbox: JavaScriptSandbox? = null
    private var connection: CompletableFuture<Int>? = null
    private var connected: CompletableFuture<Int>? = null
    private var retireConnection = false
    private var active: Call? = null

    private class Call(val id: Long, var input: ByteArray?, val outputMax: Int) {
        var isolate: JavaScriptIsolate? = null
        var port: MessagePort? = null
        var metadata: ByteArray? = null
        var body: ByteArray? = null
        var status = SUCCESS

        fun release() {
            input = null
            metadata = null
            body = null
            val oldPort = port
            val oldIsolate = isolate
            port = null
            isolate = null
            try {
                oldPort?.close()
            } finally {
                oldIsolate?.close()
            }
        }
    }

    fun prepare(): Int {
        val attempt = owner.submit<CompletableFuture<Int>> { connect() }
        return try {
            attempt.get().get(BIND_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (_: TimeoutException) {
            owner.submit { retirePreparationOnOwner(attempt.get()) }.get()
            PREPARE_FAILED
        } catch (_: ExecutionException) {
            PREPARE_FAILED
        } catch (_: InterruptedException) {
            owner.execute { retirePreparationOnOwner(attempt.get()) }
            Thread.currentThread().interrupt()
            PREPARE_FAILED
        }
    }

    private fun retirePreparationOnOwner(attempt: CompletableFuture<Int>) {
        if (connection === attempt) retireConnection = true
        if (connected === attempt && active == null) resetSandbox()
    }

    private fun connect(): CompletableFuture<Int> {
        connected?.let { return it }
        connection?.let { return it }
        if (!JavaScriptSandbox.isSupported()) {
            return CompletableFuture.completedFuture(PREPARE_UNSUPPORTED)
        }
        val future = try {
            JavaScriptSandbox.createConnectedInstanceAsync(context)
        } catch (_: SandboxUnsupportedException) {
            return CompletableFuture.completedFuture(PREPARE_UNSUPPORTED)
        } catch (_: RuntimeException) {
            return CompletableFuture.completedFuture(PREPARE_FAILED)
        }
        val ready = CompletableFuture<Int>()
        connection = ready
        future.addListener({
            connection = null
            val result = try {
                val bound = future.get()
                when {
                    retireConnection -> {
                        bound.close()
                        PREPARE_FAILED
                    }
                    !REQUIRED_FEATURES.all(bound::isFeatureSupported) -> {
                        bound.close()
                        PREPARE_UNSUPPORTED
                    }
                    else -> {
                        sandbox = bound
                        connected = ready
                        SUCCESS
                    }
                }
            } catch (_: Exception) {
                PREPARE_FAILED
            } finally {
                retireConnection = false
            }
            ready.complete(result)
        }, owner)
        return ready
    }

    fun start(id: Long, script: ByteArray, input: ByteArray, outputMax: Int): Boolean {
        if (input.size > ENTITY_MAX || outputMax !in 0..ENTITY_MAX) return false
        return try {
            owner.execute { startOnOwner(id, script, input, outputMax) }
            true
        } catch (_: RejectedExecutionException) {
            false
        }
    }

    private fun startOnOwner(id: Long, script: ByteArray, input: ByteArray, outputMax: Int) {
        val bound = sandbox
        if (bound == null) {
            // Reconnect in the background. The current script still has its
            // original deadline and owns no resources in the pending sandbox.
            connect()
        }
        if (bound == null || active != null) {
            NativeVole.nativeCompleteJs(id, ENGINE_FAILED, null, null)
            return
        }
        val call = Call(id, input, outputMax)
        active = call
        try {
            val limits = IsolateStartupParameters().apply {
                setMaxHeapSizeBytes(ISOLATE_HEAP_MAX)
                setMaxEvaluationReturnSizeBytes(ENTITY_MAX)
            }
            val isolate = bound.createIsolate(limits)
            call.isolate = isolate
            call.port = isolate.createMessageChannel("vole", owner) { message ->
                onMessage(call, message)
            }
            val evaluated = isolate.evaluateJavaScriptAsync(script.toString(Charsets.UTF_8))
            evaluated.addListener({
                if (active !== call) return@addListener
                try {
                    val result = evaluated.get()
                    if (result == "vole:timed-out") call.status = TIMED_OUT
                    if (result.length > ENTITY_MAX) {
                        finish(call, INVALID_RESULT)
                    } else {
                        val bytes = result.toByteArray(Charsets.UTF_8)
                        if (bytes.size > ENTITY_MAX) {
                            finish(call, INVALID_RESULT)
                        } else {
                            call.metadata = bytes
                            finishWhenReady(call)
                        }
                    }
                } catch (error: ExecutionException) {
                    val cause = error.cause
                    val invalid = cause is JavaScriptException && cause !is IsolateTerminatedException
                    finish(call, if (invalid) INVALID_RESULT else ENGINE_FAILED)
                } catch (_: RuntimeException) {
                    finish(call, ENGINE_FAILED)
                }
            }, owner)
        } catch (_: RuntimeException) {
            finish(call, ENGINE_FAILED)
        }
    }

    private fun onMessage(call: Call, message: Message) {
        if (active !== call) return
        try {
            when (message.type) {
                Message.TYPE_STRING -> {
                    val input = call.input
                    if (message.string != "ready" || input == null) {
                        finish(call, INVALID_RESULT, retire = true)
                        return
                    }
                    call.input = null
                    checkNotNull(call.port).postMessage(Message.createArrayBufferMessage(input))
                }
                Message.TYPE_ARRAY_BUFFER -> {
                    val body = message.arrayBuffer
                    if (call.input != null || call.body != null || body.size > call.outputMax) {
                        finish(call, INVALID_RESULT, retire = true)
                        return
                    }
                    call.body = body
                    finishWhenReady(call)
                }
                else -> finish(call, INVALID_RESULT, retire = true)
            }
        } catch (_: RuntimeException) {
            finish(call, ENGINE_FAILED)
        }
    }

    private fun finishWhenReady(call: Call) {
        if (call.metadata != null && call.body != null) finish(call, call.status)
    }

    private fun finish(call: Call, result: Int, retire: Boolean = result == ENGINE_FAILED) {
        if (active !== call) return
        active = null
        val metadata = call.metadata
        val body = call.body
        var status = result
        try {
            try {
                if (retire) resetSandbox()
            } finally {
                call.release()
            }
        } catch (_: RuntimeException) {
            status = ENGINE_FAILED
            resetSandbox()
        }
        NativeVole.nativeCompleteJs(
            call.id, status,
            metadata.takeIf { status == SUCCESS },
            body.takeIf { status == SUCCESS }
        )
    }

    fun cancel(id: Long) {
        owner.submit {
            val call = active ?: return@submit
            if (call.id == id) {
                active = null
                try {
                    resetSandbox()
                } finally {
                    call.release()
                }
            }
        }.get()
    }

    fun stop() {
        val pending = owner.submit<CompletableFuture<Int>?> {
            val call = active
            active = null
            try {
                resetSandbox()
            } finally {
                call?.release()
            }
            connection
        }.get()
        // Canceling JavaScriptSandbox's raw connection future cannot retire an
        // already connecting provider. Let it settle and close the generation.
        pending?.get(BIND_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    }

    private fun resetSandbox() {
        retireConnection = connection != null
        val old = sandbox
        sandbox = null
        connected = null
        old?.close()
    }

    override fun close() {
        try {
            stop()
        } finally {
            owner.shutdown()
            check(owner.awaitTermination(BIND_TIMEOUT_SECONDS, TimeUnit.SECONDS))
        }
    }

    companion object {
        private const val SUCCESS = 0
        private const val PREPARE_UNSUPPORTED = 1
        private const val PREPARE_FAILED = 2
        private const val INVALID_RESULT = 1
        private const val TIMED_OUT = 2
        private const val ENGINE_FAILED = 3
        private const val BIND_TIMEOUT_SECONDS = 5L
        private const val ENTITY_MAX = 256 * 1024
        private const val ISOLATE_HEAP_MAX = 16L * 1024 * 1024

        val REQUIRED_FEATURES = listOf(
            JavaScriptSandbox.JS_FEATURE_ISOLATE_TERMINATION,
            JavaScriptSandbox.JS_FEATURE_ISOLATE_MAX_HEAP_SIZE,
            JavaScriptSandbox.JS_FEATURE_MESSAGE_PORTS,
            JavaScriptSandbox.JS_FEATURE_PROMISE_RETURN,
            JavaScriptSandbox.JS_FEATURE_EVALUATE_WITHOUT_TRANSACTION_LIMIT
        )
    }
}
