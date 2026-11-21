package io.github.yuandevteam.vole

object NativeVole {
    init {
        System.loadLibrary("vole")
    }

    @JvmStatic external fun nativeInvoke(request: ByteArray): ByteArray
    @JvmStatic external fun nativeRegisterProtectController(controller: Any): Boolean
    @JvmStatic external fun nativeUnregisterProtectController(): Boolean
    @JvmStatic external fun nativeRegisterJsController(controller: Any): Boolean
    @JvmStatic external fun nativeUnregisterJsController(): Boolean
    @JvmStatic external fun nativeCompleteJs(
        id: Long, status: Int, metadata: ByteArray?, body: ByteArray?
    )
}
