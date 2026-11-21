package io.github.yuandevteam.vole.jsprobe

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log

class ProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return
        val permission = VpnService.prepare(this)
        if (permission == null) launchProbe() else startActivityForResult(permission, VPN_PERMISSION)
    }

    @Deprecated("The isolated test host has no AndroidX Activity dependency")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION && resultCode == RESULT_OK) {
            launchProbe()
        } else {
            Log.e(ProbeVpnService.TAG, "FAIL VPN permission declined")
        }
    }

    private fun launchProbe() {
        startService(Intent(this, ProbeVpnService::class.java))
    }

    private companion object {
        const val VPN_PERMISSION = 1
    }
}
