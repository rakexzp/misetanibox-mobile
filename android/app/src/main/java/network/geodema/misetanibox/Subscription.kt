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
    data class Fetched(val status: Int, val body: String, val error: String?)

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
    fun fetch(url: String, hwid: String, userAgent: String): Fetched {
        return try {
            val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
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
            conn.disconnect()
            Fetched(code, if (code in 200..299) text else "", if (code in 200..299) null else "HTTP $code")
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
        )
    }

    /** Читаемое имя формата для интерфейса. */
    fun formatLabel(format: String): String = when (format) {
        Mobilecore.FormatXray -> "Xray JSON"
        Mobilecore.FormatURI -> "список ссылок"
        else -> "mihomo YAML"
    }
}
