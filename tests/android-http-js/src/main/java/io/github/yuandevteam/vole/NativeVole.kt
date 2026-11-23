package io.github.yuandevteam.vole

object NativeVole {
    init {
        System.loadLibrary("vole")
    }

    @JvmStatic external fun nativeInvoke(request: ByteArray): ByteArray
    @JvmStatic external fun nativeRegisterProtectController(controller: Any): Boolean
    @JvmStatic external fun nativeUnregisterProtectController(): Boolean
}
