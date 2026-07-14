package network.geodema.misetanibox

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import androidx.activity.result.ActivityResult
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.ActivityCallback
import com.getcapacitor.annotation.CapacitorPlugin

@CapacitorPlugin(name = "Vpn")
class VpnPlugin : Plugin() {

    private var pendingSubUrl = ""
    private var pendingHwid = ""
    private var pendingSplitMode = "off"
    private var pendingSplitApps = arrayOf<String>()
    private var receiver: BroadcastReceiver? = null

    override fun load() {
        val filter = IntentFilter("network.geodema.misetanibox.VPN_STATE")
        receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                val ret = JSObject()
                ret.put("state", i?.getStringExtra("state") ?: "")
                ret.put("message", i?.getStringExtra("message") ?: "")
                notifyListeners("vpnState", ret)
            }
        }
        if (Build.VERSION.SDK_INT >= 34) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
    }

    override fun handleOnDestroy() {
        receiver?.let { try { context.unregisterReceiver(it) } catch (_: Exception) {} }
    }

    @PluginMethod
    fun start(call: PluginCall) {
        pendingSubUrl = call.getString("subUrl") ?: ""
        pendingHwid = call.getString("hwid") ?: ""
        pendingSplitMode = call.getString("splitMode") ?: "off"
        val appsArr = call.getArray("splitApps", com.getcapacitor.JSArray())
        val appsList = ArrayList<String>()
        for (i in 0 until (appsArr?.length() ?: 0)) {
            appsArr?.optString(i)?.let { if (it.isNotEmpty()) appsList.add(it) }
        }
        pendingSplitApps = appsList.toTypedArray()
        if (pendingSubUrl.isEmpty()) {
            call.reject("нет URL подписки")
            return
        }
        val prepare = VpnService.prepare(context)
        if (prepare != null) {
            startActivityForResult(call, prepare, "vpnPermCallback")
        } else {
            launchService()
            call.resolve()
        }
    }

    @ActivityCallback
    private fun vpnPermCallback(call: PluginCall, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK) {
            launchService()
            call.resolve()
        } else {
            call.reject("пользователь отклонил разрешение VPN")
        }
    }

    private fun launchService() {
        // дублируем параметры в prefs, чтобы плитка/виджет/автозапуск могли поднять туннель без WebView
        VpnPrefs.saveLaunchState(context, pendingSubUrl, pendingHwid, pendingSplitMode, pendingSplitApps)
        val i = Intent(context, MihomoVpnService::class.java)
        i.action = MihomoVpnService.ACTION_START
        i.putExtra(MihomoVpnService.EXTRA_SUB_URL, pendingSubUrl)
        i.putExtra(MihomoVpnService.EXTRA_HWID, pendingHwid)
        i.putExtra(MihomoVpnService.EXTRA_SPLIT_MODE, pendingSplitMode)
        i.putExtra(MihomoVpnService.EXTRA_SPLIT_APPS, pendingSplitApps)
        context.startForegroundService(i)
    }

    @PluginMethod
    fun setAutostart(call: PluginCall) {
        VpnPrefs.setAutostart(context, call.getBoolean("on", false) ?: false)
        call.resolve()
    }

    @PluginMethod
    fun getAutostart(call: PluginCall) {
        val ret = JSObject()
        ret.put("on", VpnPrefs.isAutostart(context))
        call.resolve(ret)
    }

    @PluginMethod
    fun stop(call: PluginCall) {
        val i = Intent(context, MihomoVpnService::class.java)
        i.action = MihomoVpnService.ACTION_STOP
        context.startService(i)
        call.resolve()
    }

    @PluginMethod
    fun status(call: PluginCall) {
        val ret = JSObject()
        ret.put("running", MihomoVpnService.isRunning)
        call.resolve(ret)
    }

    // Список установленных приложений с иконкой запуска (для раздельного туннелирования).
    // Берём только приложения с LAUNCHER-активностью (пользовательские), своё исключаем.
    @PluginMethod
    fun listApps(call: PluginCall) {
        Thread {
            val ret = JSObject()
            val arr = com.getcapacitor.JSArray()
            try {
                val pm = context.packageManager
                val self = context.packageName
                val q = Intent(Intent.ACTION_MAIN, null).addCategory(Intent.CATEGORY_LAUNCHER)
                val resolved = pm.queryIntentActivities(q, 0)
                val seen = HashSet<String>()
                for (ri in resolved) {
                    val pkg = ri.activityInfo?.packageName ?: continue
                    if (pkg == self) continue
                    if (!seen.add(pkg)) continue
                    val label = ri.loadLabel(pm)?.toString() ?: pkg
                    val o = JSObject()
                    o.put("package", pkg)
                    o.put("label", label)
                    arr.put(o)
                }
            } catch (_: Exception) {}
            ret.put("apps", arr)
            call.resolve(ret)
        }.start()
    }

    // Скачать подписку (для превью серверов до подключения) через нативный HTTP,
    // с clash-UA (панели отдают конфиг по UA) и HWID-заголовками.
    @PluginMethod
    fun fetchSub(call: PluginCall) {
        val url = call.getString("url") ?: ""
        val hwid = call.getString("hwid") ?: ""
        Thread {
            val ret = JSObject()
            try {
                val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 8000
                conn.readTimeout = 15000
                conn.instanceFollowRedirects = true
                conn.setRequestProperty("User-Agent", "clash-meta/mihomo")
                if (hwid.isNotEmpty()) {
                    conn.setRequestProperty("x-hwid", hwid)
                    conn.setRequestProperty("x-device-os", "Android")
                    conn.setRequestProperty("x-ver-os", Build.VERSION.RELEASE)
                    conn.setRequestProperty("x-device-model", Build.MODEL)
                }
                val code = conn.responseCode
                val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                    ?.bufferedReader()?.use { it.readText() } ?: ""
                conn.disconnect()
                ret.put("status", code)
                ret.put("body", text)
            } catch (e: Exception) {
                ret.put("status", 0)
                ret.put("body", "")
                ret.put("error", e.message ?: "fetch failed")
            }
            call.resolve(ret)
        }.start()
    }

    // Прокси к API ядра mihomo (external-controller) через нативный HTTP,
    // чтобы обойти CORS/mixed-content ограничения WebView.
    @PluginMethod
    fun coreRequest(call: PluginCall) {
        val method = (call.getString("method") ?: "GET").uppercase()
        val path = call.getString("path") ?: "/"
        val body = call.getString("body")
        Thread {
            try {
                val url = java.net.URL("http://127.0.0.1:9090$path")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.requestMethod = method
                conn.connectTimeout = 5000
                conn.readTimeout = 10000
                if (body != null) {
                    conn.doOutput = true
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                }
                val code = conn.responseCode
                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
                conn.disconnect()
                val ret = JSObject()
                ret.put("status", code)
                ret.put("body", text)
                call.resolve(ret)
            } catch (e: Exception) {
                val ret = JSObject()
                ret.put("status", 0)
                ret.put("body", "")
                ret.put("error", e.message ?: "core unreachable")
                call.resolve(ret)
            }
        }.start()
    }
}
