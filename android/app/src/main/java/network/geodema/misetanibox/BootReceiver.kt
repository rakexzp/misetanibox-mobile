package network.geodema.misetanibox

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Автозапуск туннеля после перезагрузки, если включён в настройках (VpnPrefs.KEY_AUTOSTART).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!VpnPrefs.isAutostart(context)) return
        VpnPrefs.startFromPrefs(context)
    }
}
