package network.geodema.misetanibox

import android.os.Build
import mobilecore.Mobilecore

/**
 * Загрузка подписки и приведение её к YAML-конфигу mihomo.
 *
 * Панель выбирает формат ответа по User-Agent: на clash-UA приходит YAML, на
 * v2rayNG/xray-UA — JSON Xray или список ссылок vless://…. Раньше клиент умел
 * только YAML, поэтому UA был прибит гвоздями. Теперь конвертер внутри ядра
 * (Mobilecore.convertSubscription) разбирает все три формата, и UA стал
 * настройкой: подписку можно взять в том виде, в котором её отдаёт панель.
 *
 * Загрузка и конвертация лежат вместе, потому что нужны в двух местах сразу —
 * при запуске туннеля (MihomoVpnService) и при превью серверов (VpnPlugin).
 */
object Subscription {

    /** UA по умолчанию: на него панели отдают clash-YAML. */
    const val DEFAULT_USER_AGENT = "clash-meta/mihomo"

    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 15000

    /** Ответ подписки как есть, до разбора формата. */
    data class Fetched(val status: Int, val body: String, val error: String?, val title: String = "", val meta: Map<String, String> = emptyMap())

    /** Готовый к запуску конфиг плюс то, что стоит показать пользователю. */
    data class Converted(
        val config: String,
        /** mihomo | xray | uri — см. Mobilecore.FormatMihomo и соседей. */
        val format: String,
        val proxies: Int,
        val groups: Int,
        /**
         * Что предлагать пользователю в списке серверов. Узлы, которые собраны в
         * группу-балансировщик, сюда не попадают — они выбираются через группу.
         * Пусто для сквозного mihomo-конфига: там группы читаются из живого ядра.
         */
        val names: List<String>,
        /** Настройки, которые не удалось перенести; пусто, если всё перенеслось. */
        val notes: String,
        /** JSON {main, auto, members[]} главного селектора для листа до подключения (mihomo) */
        val sheet: String = "",
        /** JSON {имя: "host:port"} узлов для tcp/icmp-пинга (mihomo) */
        val nodes: String = "",
    )

    /** Пустой/пробельный UA означает «настройка не трогалась». */
    fun userAgentOr(value: String?): String {
        val ua = value?.trim() ?: ""
        return if (ua.isEmpty()) DEFAULT_USER_AGENT else ua
    }

    /**
     * Скачать тело подписки. Сеть — нативная, а не из WebView: там CORS и
     * mixed-content, да и заголовки панели требуют своих.
     */
    // заголовок panel'и: "base64:<...>" или открытый текст
    private fun profileTitle(raw: String?): String {
        val v = raw?.trim() ?: return ""
        if (v.startsWith("base64:", ignoreCase = true)) {
            return try { String(android.util.Base64.decode(v.substring(7), android.util.Base64.DEFAULT), Charsets.UTF_8).trim() } catch (_: Exception) { "" }
        }
        return v
    }

    // запасной адрес: голый хост → путь/query основной ссылки, иначе как есть (как в ПК-клиенте)
    // офлайн-копия последнего удачного конфига (белые списки оператора: домен панели недоступен с мобильного)
    private fun cacheFile(ctx: android.content.Context, url: String): java.io.File {
        val d = java.io.File(ctx.filesDir, "subcache").apply { mkdirs() }
        val h = java.security.MessageDigest.getInstance("SHA-1").digest(url.toByteArray()).joinToString("") { "%02x".format(it) }
        return java.io.File(d, "$h.yaml")
    }
    fun saveCache(ctx: android.content.Context, url: String, body: String) { try { if (body.isNotBlank()) cacheFile(ctx, url).writeText(body) } catch (_: Exception) {} }
    fun loadCache(ctx: android.content.Context, url: String): String = try { val f = cacheFile(ctx, url); if (f.exists()) f.readText() else "" } catch (_: Exception) { "" }

    fun resolveFallbackUrl(primary: String, fb: String): String {
        return try {
            val f = java.net.URI(fb); if (f.host.isNullOrEmpty()) return ""
            if (f.path.trim('/').isNotEmpty() || !f.query.isNullOrEmpty()) return fb
            val p = java.net.URI(primary)
            java.net.URI(f.scheme ?: "https", f.authority, p.path, p.query, null).toString()
        } catch (_: Exception) { "" }
    }

    /** Основная ссылка, потом запасные по очереди; первая с 2xx выигрывает. */
    fun fetchAny(url: String, hwid: String, userAgent: String, fallbacks: List<String>, proxyPort: Int = 0): Fetched {
        var last = fetch(url, hwid, userAgent, proxyPort)
        if (last.status in 200..299 && last.body.isNotBlank()) return last
        val seen = HashSet<String>(); seen.add(url)
        for (fb in fallbacks) {
            val u = resolveFallbackUrl(url, fb.trim()); if (u.isEmpty() || !seen.add(u)) continue
            val r = fetch(u, hwid, userAgent, proxyPort)
            if (r.status in 200..299 && r.body.isNotBlank()) return r
            last = r
        }
        return last
    }

    fun fetch(url: String, hwid: String, userAgent: String, proxyPort: Int = 0): Fetched {
        return try {
            val u = java.net.URL(url)
            val conn = (if (proxyPort > 0) u.openConnection(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", proxyPort))) else u.openConnection()) as java.net.HttpURLConnection
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", userAgentOr(userAgent))
            if (hwid.isNotEmpty()) {
                conn.setRequestProperty("x-hwid", hwid)
                conn.setRequestProperty("x-device-os", "Android")
                conn.setRequestProperty("x-ver-os", Build.VERSION.RELEASE)
                conn.setRequestProperty("x-device-model", Build.MODEL)
            }
            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: ""
            val title = profileTitle(conn.getHeaderField("profile-title"))
            // заголовки панели: логотип, страница оплаты, поддержка, объявление, трафик/срок
            val meta = HashMap<String, String>()
            meta["title"] = title
            meta["logo"] = conn.getHeaderField("profile-logo")?.trim() ?: ""
            meta["webPage"] = conn.getHeaderField("profile-web-page-url")?.trim() ?: ""
            meta["supportUrl"] = conn.getHeaderField("support-url")?.trim() ?: ""
            meta["announce"] = profileTitle(conn.getHeaderField("announce"))
            meta["userinfo"] = conn.getHeaderField("subscription-userinfo")?.trim() ?: ""
            meta["updateInterval"] = conn.getHeaderField("profile-update-interval")?.trim() ?: ""
            // запасные адреса подписки (Happ: fallback-url; ПК-клиент: x-sub-fallback / x-fallback-url / profile-fallback-url)
            val fbs = ArrayList<String>()
            for (h in listOf("fallback-url", "x-sub-fallback", "x-fallback-url", "profile-fallback-url")) {
                for (v in conn.headerFields[h] ?: emptyList()) for (part in v.split(',', ';', '\n', ' ', '\t')) {
                    val u = part.trim(); if (u.isNotEmpty() && !fbs.contains(u)) fbs.add(u)
                }
            }
            meta["fallbacks"] = fbs.joinToString("\n")
            meta["notifExpire"] = conn.getHeaderField("notification-subs-expire")?.trim() ?: ""
            meta["pingType"] = conn.getHeaderField("ping-type")?.trim() ?: ""
            meta["checkUrl"] = conn.getHeaderField("check-url-via-proxy")?.trim() ?: ""
            meta["pingResult"] = conn.getHeaderField("ping-result")?.trim() ?: ""
            meta["updateOnOpen"] = conn.getHeaderField("update-on-open")?.trim() ?: ""
            meta["usedUrl"] = url
            conn.disconnect()
            Fetched(code, if (code in 200..299) text else "", if (code in 200..299) null else "HTTP $code", title, meta)
        } catch (e: Exception) {
            Fetched(0, "", e.message ?: "не удалось загрузить подписку")
        }
    }

    /**
     * Привести тело подписки к YAML-конфигу mihomo.
     *
     * Формат определяет ядро: YAML отдаётся как есть (подписка запускается
     * ровно такой, какой её написал автор), Xray JSON и список ссылок
     * конвертируются. Бросает исключение с человеческим текстом, если формат
     * не разобрался — иначе туннель поднимется мёртвым.
     */
    fun convert(body: String): Converted {
        val r = Mobilecore.convertSubscription(body)
        return Converted(
            config = r.config,
            format = r.format,
            proxies = r.proxies.toInt(),
            groups = r.groups.toInt(),
            // имена приходят одной строкой: список строк gomobile через JNI не носит
            names = r.names.split('\n').map { it.trim() }.filter { it.isNotEmpty() },
            notes = r.notes,
            sheet = r.sheet,
            nodes = r.nodes,
        )
    }

    /** Читаемое имя формата для интерфейса. */
    fun formatLabel(format: String): String = when (format) {
        Mobilecore.FormatXray -> "Xray JSON"
        Mobilecore.FormatURI -> "список ссылок"
        else -> "mihomo YAML"
    }
}
