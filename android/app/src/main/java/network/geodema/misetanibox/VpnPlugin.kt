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
    private var pendingWarp = ""
    private var pendingFallbacks = arrayOf<String>()
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
        // цепочки приходят готовым JSON-массивом [{name, nodes:[...]}], WARP — JSON кредов или ""
        pendingChains = call.getArray("chains", com.getcapacitor.JSArray())?.toString() ?: "[]"
        pendingWarp = call.getString("warp") ?: ""
        val fbArr = call.getArray("fallbacks", com.getcapacitor.JSArray()); val fbList = ArrayList<String>()
        for (i in 0 until (fbArr?.length() ?: 0)) fbArr?.optString(i)?.let { if (it.isNotBlank()) fbList.add(it) }
        pendingFallbacks = fbList.toTypedArray()
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
            pendingRules, pendingChains, pendingServiceGroups, pendingWarp, pendingFallbacks,
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
        i.putExtra(MihomoVpnService.EXTRA_WARP, pendingWarp)
        i.putExtra(MihomoVpnService.EXTRA_FALLBACKS, pendingFallbacks)
        i.putExtra(MihomoVpnService.EXTRA_SERVICE_GROUPS, pendingServiceGroups)
        context.startForegroundService(i)
    }

    // Регистрация WARP-устройства в Cloudflare (один раз); ключи — из ядра, HTTP — здесь,
    // потому что Go-резолвер на Android не умеет системный DNS. Креды хранит JS.
    @PluginMethod
    fun warpRegister(call: PluginCall) {
        Thread {
            try {
                val keys = mobilecore.Mobilecore.warpKeypair().split("\n")
                val priv = keys[0]; val pub = keys[1]
                val tos = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
                    .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }.format(java.util.Date())
                val payload = org.json.JSONObject()
                    .put("key", pub).put("install_id", "").put("fcm_token", "").put("tos", tos)
                    .put("model", "PC").put("type", "Android").put("locale", "en_US").toString()
                // напрямую из РФ Cloudflare-API не отвечает; своё приложение вне туннеля,
                // поэтому при поднятом ядре идём через его локальный mixed-port
                val port = coreMixedPort()
                val url = java.net.URL("https://api.cloudflareclient.com/v0a2158/reg")
                val conn = (if (port > 0) url.openConnection(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", port))) else url.openConnection()) as java.net.HttpURLConnection
                conn.requestMethod = "POST"
                conn.connectTimeout = 15000
                conn.readTimeout = 20000
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("User-Agent", "okhttp/3.12.1")
                conn.setRequestProperty("CF-Client-Version", "a-6.30-2158")
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                val text = (if (code in 200..299) conn.inputStream else conn.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
                conn.disconnect()
                if (code !in 200..299) throw Exception("Cloudflare вернул HTTP $code")
                val cfg = org.json.JSONObject(text).getJSONObject("config")
                val peerKey = cfg.getJSONArray("peers").getJSONObject(0).getString("public_key")
                val addr = cfg.getJSONObject("interface").getJSONObject("addresses")
                val clientId = cfg.optString("client_id", "")
                val reserved = org.json.JSONArray()
                try {
                    val cid = android.util.Base64.decode(clientId, android.util.Base64.DEFAULT)
                    if (cid.size >= 3) for (i in 0 until 3) reserved.put(cid[i].toInt() and 0xff)
                } catch (_: Exception) {}
                if (reserved.length() < 3) { reserved.put(0); reserved.put(0); reserved.put(0) }
                val creds = org.json.JSONObject()
                    .put("private_key", priv).put("public_key", peerKey)
                    .put("address4", addr.optString("v4").substringBefore("/"))
                    .put("address6", addr.optString("v6").substringBefore("/"))
                    .put("reserved", reserved)
                val ret = JSObject()
                ret.put("creds", creds.toString())
                call.resolve(ret)
            } catch (e: Exception) {
                call.reject(e.message ?: "регистрация WARP не удалась")
            }
        }.start()
    }

    private fun coreMixedPort(): Int {
        if (!MihomoVpnService.isRunning) return 0
        return try {
            val c = java.net.URL("http://127.0.0.1:9090/configs").openConnection() as java.net.HttpURLConnection
            c.connectTimeout = 2000; c.readTimeout = 3000
            val t = c.inputStream.bufferedReader().use { it.readText() }
            c.disconnect()
            org.json.JSONObject(t).optInt("mixed-port", 0)
        } catch (_: Exception) { 0 }
    }

    // тактильный отклик: heavy = защёлкнулась панель, tick = закрылась.
    // usage=TOUCH система глушит при выключенном «виброотклике при касании» → PHYSICAL_EMULATION
    @PluginMethod
    fun haptic(call: PluginCall) {
        try {
            val kind = call.getString("kind") ?: "tick"
            val vib = if (Build.VERSION.SDK_INT >= 31) {
                (context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as android.os.VibratorManager).defaultVibrator
            } else {
                @Suppress("DEPRECATION") context.getSystemService(Context.VIBRATOR_SERVICE) as android.os.Vibrator
            }
            val effect = if (Build.VERSION.SDK_INT >= 29) {
                android.os.VibrationEffect.createPredefined(if (kind == "heavy") android.os.VibrationEffect.EFFECT_HEAVY_CLICK else android.os.VibrationEffect.EFFECT_TICK)
            } else {
                android.os.VibrationEffect.createOneShot(if (kind == "heavy") 30 else 10, android.os.VibrationEffect.DEFAULT_AMPLITUDE)
            }
            if (Build.VERSION.SDK_INT >= 30) {
                val attrs = android.os.VibrationAttributes.Builder().setUsage(android.os.VibrationAttributes.USAGE_PHYSICAL_EMULATION).build()
                vib.vibrate(effect, attrs)
            } else {
                vib.vibrate(effect)
            }
        } catch (_: Exception) {}
        call.resolve()
    }

    // открыть ссылку во внешнем браузере (оплата, поддержка, скачать обновление)
    @PluginMethod
    fun openUrl(call: PluginCall) {
        val url = call.getString("url") ?: ""
        try {
            val i = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(i)
            call.resolve()
        } catch (e: Exception) { call.reject(e.message ?: "не открылось") }
    }

    // GET текстового ресурса мимо CORS WebView (манифест обновлений)
    @PluginMethod
    fun httpGet(call: PluginCall) {
        val url = call.getString("url") ?: ""
        Thread {
            val ret = JSObject()
            try {
                val c = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                c.connectTimeout = 8000; c.readTimeout = 10000
                c.setRequestProperty("User-Agent", "Misetanibox-Android")
                val code = c.responseCode
                val text = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
                c.disconnect()
                ret.put("status", code); ret.put("body", text)
            } catch (e: Exception) { ret.put("status", 0); ret.put("body", ""); ret.put("error", e.message ?: "") }
            call.resolve(ret)
        }.start()
    }

    // tcp-пинг: время TCP-коннекта до host:port узла, мс (или -1)
    @PluginMethod
    fun tcpPing(call: PluginCall) {
        val host = call.getString("host") ?: ""; val port = call.getInt("port") ?: 443
        Thread {
            val ret = JSObject()
            val t0 = System.nanoTime()
            try {
                java.net.Socket().use { it.connect(java.net.InetSocketAddress(host, port), 3000) }
                ret.put("ms", ((System.nanoTime() - t0) / 1_000_000).toInt())
            } catch (_: Exception) { ret.put("ms", -1) }
            call.resolve(ret)
        }.start()
    }

    // icmp-пинг через системный /system/bin/ping (raw-сокет приложению не дают)
    @PluginMethod
    fun icmpPing(call: PluginCall) {
        val host = call.getString("host") ?: ""
        Thread {
            val ret = JSObject()
            try {
                val pr = ProcessBuilder("/system/bin/ping", "-c", "1", "-W", "2", host).redirectErrorStream(true).start()
                val out = pr.inputStream.bufferedReader().use { it.readText() }; pr.waitFor()
                val m = Regex("time=([0-9.]+)").find(out)
                ret.put("ms", if (m != null) m.groupValues[1].toDouble().toInt() else -1)
            } catch (_: Exception) { ret.put("ms", -1) }
            call.resolve(ret)
        }.start()
    }

    // напоминания об окончании подписки (notification-subs-expire): за 3/2/1 день
    @PluginMethod
    fun scheduleExpiryReminder(call: PluginCall) {
        ExpiryReminder.save(context, call.getString("name") ?: "", (call.getDouble("expireAt") ?: 0.0).toLong(), call.getBoolean("enabled", false) ?: false, call.getInt("days") ?: 3)
        ExpiryReminder.schedule(context)
        call.resolve()
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
        val fbArr = call.getArray("fallbacks", com.getcapacitor.JSArray()); val fbs = ArrayList<String>()
        for (i in 0 until (fbArr?.length() ?: 0)) fbArr?.optString(i)?.let { if (it.isNotBlank()) fbs.add(it) }
        val viaProxy = call.getBoolean("viaProxy", false) ?: false
        Thread {
            val ret = JSObject()
            var fetched = Subscription.fetchAny(url, hwid, userAgent, fbs, if (viaProxy) coreMixedPort() else 0)
            if (fetched.status in 200..299 && fetched.body.isNotBlank()) {
                Subscription.saveCache(context, url, fetched.body)
            } else {
                val cached = Subscription.loadCache(context, url)
                if (cached.isNotBlank()) { fetched = Subscription.Fetched(200, cached, null); ret.put("cached", true) }
            }
            ret.put("status", fetched.status)
            ret.put("title", fetched.title)
            for ((k, x) in fetched.meta) ret.put(k, x)
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
                ret.put("sheet", converted.sheet)
                ret.put("nodes", converted.nodes)
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
