package network.geodema.misetanibox

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import org.json.JSONArray

/**
 * Нативное хранилище параметров запуска VPN + хелперы для плитки в шторке,
 * виджета на рабочем столе и автозапуска после перезагрузки.
 *
 * Смысл: основной UI хранит подписку/split в localStorage (JS), но плитке/виджету/
 * BootReceiver нужно поднять туннель БЕЗ открытия WebView — поэтому VpnPlugin.start
 * дублирует параметры сюда (saveLaunchState), а эти компоненты стартуют из prefs.
 */
object VpnPrefs {
    const val PREFS = "misetanibox"
    const val KEY_AUTOSTART = "autostart"
    const val KEY_SUB_URL = "sub_url"
    const val KEY_HWID = "hwid"
    /** off | bypass | only (см. MihomoVpnService.applySplitTunnel) */
    const val KEY_SPLIT_MODE = "split_mode"
    /** JSON-массив имён пакетов */
    const val KEY_SPLIT_APPS = "split_apps"

    fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun hasSubscription(ctx: Context): Boolean =
        (prefs(ctx).getString(KEY_SUB_URL, "") ?: "").isNotBlank()

    fun splitMode(ctx: Context): String {
        val m = prefs(ctx).getString(KEY_SPLIT_MODE, "off") ?: "off"
        return if (m == "bypass" || m == "only") m else "off"
    }

    fun splitAppsArray(ctx: Context): Array<String> {
        val raw = prefs(ctx).getString(KEY_SPLIT_APPS, "[]") ?: "[]"
        return try {
            val arr = JSONArray(raw)
            val out = ArrayList<String>()
            for (i in 0 until arr.length()) {
                val p = arr.optString(i, "").trim()
                if (p.isNotEmpty()) out.add(p)
            }
            out.toTypedArray()
        } catch (_: Exception) {
            arrayOf()
        }
    }

    fun isAutostart(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_AUTOSTART, false)

    fun setAutostart(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_AUTOSTART, on).apply()
    }

    /** Сохранить то, чем стартует туннель, чтобы плитка/виджет/бут могли поднять его сами. */
    fun saveLaunchState(ctx: Context, subUrl: String, hwid: String, splitMode: String, splitApps: Array<String>) {
        val sm = if (splitMode == "bypass" || splitMode == "only") splitMode else "off"
        prefs(ctx).edit()
            .putString(KEY_SUB_URL, subUrl)
            .putString(KEY_HWID, hwid)
            .putString(KEY_SPLIT_MODE, sm)
            .putString(KEY_SPLIT_APPS, JSONArray(splitApps.toList()).toString())
            .apply()
    }

    /**
     * Поднять VPN из сохранённых prefs.
     * @return null если запущено, иначе строка-причина.
     */
    fun startFromPrefs(ctx: Context): String? {
        if (!hasSubscription(ctx)) return "нет подписки"
        if (VpnService.prepare(ctx) != null) return "нужно разрешение VPN"
        val p = prefs(ctx)
        val i = Intent(ctx, MihomoVpnService::class.java).apply {
            action = MihomoVpnService.ACTION_START
            putExtra(MihomoVpnService.EXTRA_SUB_URL, p.getString(KEY_SUB_URL, "") ?: "")
            putExtra(MihomoVpnService.EXTRA_HWID, p.getString(KEY_HWID, "") ?: "")
            putExtra(MihomoVpnService.EXTRA_SPLIT_MODE, splitMode(ctx))
            putExtra(MihomoVpnService.EXTRA_SPLIT_APPS, splitAppsArray(ctx))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i) else ctx.startService(i)
        return null
    }

    fun stopVpn(ctx: Context) {
        val i = Intent(ctx, MihomoVpnService::class.java).apply { action = MihomoVpnService.ACTION_STOP }
        ctx.startService(i)
    }
}
