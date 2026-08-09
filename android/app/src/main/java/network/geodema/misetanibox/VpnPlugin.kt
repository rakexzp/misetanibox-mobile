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
    private var pendingUserAgent = Subscription.DEFAULT_USER_AGENT
    private var pendingSplitMode = "off"
    private var pendingSplitApps = arrayOf<String>()
    private var pendingRules = arrayOf<String>()
    private var pendingChains = "[]"
    private var pendingServiceGroups = arrayOf<String>()
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
        pendingUserAgent = Subscription.userAgentOr(call.getString("userAgent"))
        pendingSplitMode = call.getString("splitMode") ?: "off"
        val appsArr = call.getArray("splitApps", com.getcapacitor.JSArray())
        val appsList = ArrayList<String>()
        for (i in 0 until (appsArr?.length() ?: 0)) {
            appsArr?.optString(i)?.let { if (it.isNotEmpty()) appsList.add(it) }
        }
        pendingSplitApps = appsList.toTypedArray()

        val rulesArr = call.getArray("rules", com.getcapacitor.JSArray())
        val rulesList = ArrayList<String>()
        for (i in 0 until (rulesArr?.length() ?: 0)) {
            rulesArr?.optString(i)?.let { if (it.isNotBlank()) rulesList.add(it) }
        }
        pendingRules = rulesList.toTypedArray()
        // цепочки приходят готовым JSON-массивом [{name, entry}]
        pendingChains = call.getArray("chains", com.getcapacitor.JSArray())?.toString() ?: "[]"
        // имена select-групп сервисов из конфигуратора селекторов
        val sgArr = call.getArray("serviceGroups", com.getcapacitor.JSArray())
        val sgList = ArrayList<String>()
        for (i in 0 until (sgArr?.length() ?: 0)) {
            sgArr?.optString(i)?.let { if (it.isNotBlank()) sgList.add(it) }
        }
        pendingServiceGroups = sgList.toTypedArray()
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
        VpnPrefs.saveLaunchState(
            context, pendingSubUrl, pendingHwid, pendingUserAgent, pendingSplitMode, pendingSplitApps,
            pendingRules, pendingChains, pendingServiceGroups,
        )
        val i = Intent(context, MihomoVpnService::class.java)
        i.action = MihomoVpnService.ACTION_START
        i.putExtra(MihomoVpnService.EXTRA_SUB_URL, pendingSubUrl)
        i.putExtra(MihomoVpnService.EXTRA_HWID, pendingHwid)
        i.putExtra(MihomoVpnService.EXTRA_USER_AGENT, pendingUserAgent)
        i.putExtra(MihomoVpnService.EXTRA_SPLIT_MODE, pendingSplitMode)
        i.putExtra(MihomoVpnService.EXTRA_SPLIT_APPS, pendingSplitApps)
        i.putExtra(MihomoVpnService.EXTRA_RULES, pendingRules)
        i.putExtra(MihomoVpnService.EXTRA_CHAINS, pendingChains)
        i.putExtra(MihomoVpnService.EXTRA_SERVICE_GROUPS, pendingServiceGroups)
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
    // с настраиваемым UA (панели отдают формат конфига по UA) и HWID-заголовками.
    //
    // Наружу отдаём УЖЕ сконвертированный YAML: интерфейсу не нужно знать, что
    // панель прислала — Xray JSON, список ссылок или готовый mihomo-конфиг. Формат
    // и счётчики уходят рядом, чтобы их было видно в подписках и в диагностике.
    @PluginMethod
    fun fetchSub(call: PluginCall) {
        val url = call.getString("url") ?: ""
        val hwid = call.getString("hwid") ?: ""
        val userAgent = Subscription.userAgentOr(call.getString("userAgent"))
        Thread {
            val ret = JSObject()
            val fetched = Subscription.fetch(url, hwid, userAgent)
            ret.put("status", fetched.status)
            if (fetched.body.isBlank()) {
                ret.put("body", "")
                ret.put("error", fetched.error ?: "пустой ответ")
                call.resolve(ret)
                return@Thread
            }
            try {
                val converted = Subscription.convert(fetched.body)
                ret.put("body", converted.config)
                ret.put("format", converted.format)
                ret.put("formatLabel", Subscription.formatLabel(converted.format))
                ret.put("proxies", converted.proxies)
                ret.put("groups", converted.groups)
                ret.put("notes", converted.notes)
                val names = com.getcapacitor.JSArray()
                for (n in converted.names) names.put(n)
                ret.put("names", names)
            } catch (e: Exception) {
                // Формат не разобрался — отдаём тело как есть, чтобы превью могло
                // хотя бы попробовать вытащить имена, и говорим почему.
                ret.put("body", fetched.body)
                ret.put("error", e.message ?: "формат подписки не распознан")
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
