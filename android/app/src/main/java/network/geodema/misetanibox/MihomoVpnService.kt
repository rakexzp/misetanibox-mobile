package network.geodema.misetanibox

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobilecore.Mobilecore
import mobilecore.SocketProtector
import java.io.File

class MihomoVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    // Сырой дескриптор TUN, пока ИМ ВЛАДЕЕМ МЫ. После успешного старта владение переходит
    // ядру (sing-tun закрывает его сам при Stop), и здесь снова -1 — чтобы не закрыть дважды.
    @Volatile private var ownedTunFd = -1
    // Запуск/остановка ядра блокирующие (парсинг конфига + загрузка подписки + shutdown),
    // на главном потоке они вешают интерфейс — тогда кнопка «отключить» не реагирует.
    private val worker = java.util.concurrent.Executors.newSingleThreadExecutor()
    private var netCallback: android.net.ConnectivityManager.NetworkCallback? = null
    @Volatile private var running = false

    companion object {
        const val ACTION_START = "network.geodema.misetanibox.START"
        const val ACTION_STOP = "network.geodema.misetanibox.STOP"
        const val EXTRA_SUB_URL = "sub_url"
        const val EXTRA_HWID = "hwid"
        const val EXTRA_USER_AGENT = "user_agent"
        const val EXTRA_SPLIT_MODE = "split_mode"
        const val EXTRA_SPLIT_APPS = "split_apps"
        const val EXTRA_RULES = "rules"
        const val EXTRA_CHAINS = "chains" // JSON: [{"name":"...","entry":"..."}]
        const val EXTRA_SERVICE_GROUPS = "service_groups" // имена select-групп сервисов (use: main)
        // префикс имени группы-цепочки в списке серверов
        const val CHAIN_PREFIX = "🔗 "
        const val CHANNEL_ID = "misetanibox_vpn"
        const val NOTIF_ID = 7

        @Volatile var isRunning = false
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                worker.execute { stopTunnel() }
            }
            else -> {
                val subUrl = intent?.getStringExtra(EXTRA_SUB_URL) ?: ""
                val hwid = intent?.getStringExtra(EXTRA_HWID) ?: ""
                val userAgent = intent?.getStringExtra(EXTRA_USER_AGENT) ?: ""
                val splitMode = intent?.getStringExtra(EXTRA_SPLIT_MODE) ?: "off"
                val splitApps = intent?.getStringArrayExtra(EXTRA_SPLIT_APPS) ?: arrayOf()
                val rules = intent?.getStringArrayExtra(EXTRA_RULES) ?: arrayOf()
                val chains = parseChains(intent?.getStringExtra(EXTRA_CHAINS))
                val serviceGroups = intent?.getStringArrayExtra(EXTRA_SERVICE_GROUPS) ?: arrayOf()
                if (subUrl.isEmpty()) {
                    // сюда попадаем при рестарте сервиса системой с пустым intent
                    stopSelf()
                    return START_NOT_STICKY
                }
                // Уведомление обязано появиться сразу после startForegroundService,
                // поэтому показываем его на главном потоке, а запуск ядра уводим в фон.
                startForegroundNotif()
                worker.execute { startTunnel(subUrl, hwid, userAgent, splitMode, splitApps, rules, chains, serviceGroups) }
            }
        }
        // не START_STICKY: иначе система переподнимет сервис с пустым intent и без подписки
        return START_NOT_STICKY
    }

    // Разбор цепочек из JSON: [{"name":"NL→DE","entry":"🇳🇱 NL #1"}]
    private fun parseChains(json: String?): List<Pair<String, String>> {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = org.json.JSONArray(json)
            val out = ArrayList<Pair<String, String>>()
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val name = o.optString("name").trim()
                val entry = o.optString("entry").trim()
                if (name.isNotEmpty() && entry.isNotEmpty()) out.add(name to entry)
            }
            out
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun startTunnel(
        subUrl: String,
        hwid: String,
        userAgent: String,
        splitMode: String,
        splitApps: Array<String>,
        rules: Array<String>,
        chains: List<Pair<String, String>>,
        serviceGroups: Array<String>,
    ) {
        if (running) return
        try {
            // Классика: сперва тянем конфиг подписки (со всеми селекторами автора). Если не
            // удалось — не поднимаем TUN, иначе интернет пропадёт при мёртвом туннеле.
            val fetched = Subscription.fetch(subUrl, hwid, userAgent)
            if (fetched.body.isBlank()) {
                val reason = fetched.error ?: "пустой ответ"
                broadcast("error", "не удалось загрузить конфиг подписки ($reason) — проверьте ссылку и интернет")
                return
            }
            // Подписка может прийти YAML-ом mihomo, JSON-ом Xray или списком ссылок:
            // формат определяет и приводит к YAML ядро. Ошибка здесь — это «формат не
            // разобрался», и с ней туннель поднимать нельзя.
            val config = try {
                Subscription.convert(fetched.body).config
            } catch (e: Exception) {
                broadcast("error", "конфиг подписки не разобран: " + (e.message ?: "неизвестный формат"))
                return
            }
            val builder = Builder()
                .setSession("Misetanibox")
                .setMtu(9000)
                .addAddress("172.19.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("172.19.0.2")
                .setBlocking(false)
            // раздельное туннелирование по приложениям (см. applySplitTunnel)
            applySplitTunnel(builder, splitMode, splitApps)

            val pfd = builder.establish() ?: run {
                broadcast("error", "establish() вернул null — нет разрешения VPN или активен другой VPN")
                return
            }
            tunFd = pfd
            val fd = pfd.detachFd()
            ownedTunFd = fd // пока ядро не стартовало — дескриптор наш

            val homeDir = File(filesDir, "clash").apply { mkdirs() }.absolutePath
            // config уже получен фетчем выше (классический режим)

            // защита исходящих сокетов ядра (иначе петля через TUN)
            Mobilecore.setProtect(object : SocketProtector {
                override fun protect(fd: Long): Boolean = protect(fd.toInt())
            })

            val err = Mobilecore.start(homeDir, config, fd.toLong())
            if (err.isNotEmpty()) {
                broadcast("error", err)
                stopTunnel() // закроет дескриптор: иначе интерфейс останется поднятым и весь трафик уйдёт в никуда
                return
            }
            // старт удался — дескриптор теперь у ядра, оно закроет его при остановке
            ownedTunFd = -1
            watchNetworkChanges()
            running = true
            isRunning = true
            broadcast("connected", "")

            // Через несколько секунд снимаем отчёт ядра: поднялся ли TUN и загрузилась ли
            // подписка. hub.ApplyConfig ошибок не возвращает, без этого «нет трафика»
            // выглядит как «всё в порядке».
            worker.execute {
                try {
                    Thread.sleep(6000)
                    if (running) broadcast("diag", Mobilecore.diagnose())
                } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            broadcast("error", e.message ?: "неизвестная ошибка запуска")
            stopTunnel()
        }
    }

    // Раздельное туннелирование. В Android addAllowedApplication и addDisallowedApplication
    // взаимоисключающие — нельзя смешивать в одном Builder, поэтому режимы разведены.
    //  off    — весь трафик в туннель, кроме самого приложения (обычный режим);
    //  bypass — выбранные приложения идут МИМО VPN (напрямую), остальное в туннель;
    //  only   — в туннель идут ТОЛЬКО выбранные приложения, остальное напрямую.
    // Собственное приложение всегда вне туннеля (иначе петля fetch/ядро через TUN):
    //  в off/bypass — через addDisallowedApplication, в only — оно просто не в allowed-списке.
    private fun applySplitTunnel(builder: Builder, mode: String, apps: Array<String>) {
        when (mode) {
            "only" -> {
                var added = 0
                for (p in apps) {
                    try { builder.addAllowedApplication(p); added++ } catch (_: Exception) {}
                }
                // пустой/битый список в режиме «только» = мёртвый туннель → откатываемся к обычному
                if (added == 0) {
                    try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                }
            }
            "bypass" -> {
                for (p in apps) {
                    try { builder.addDisallowedApplication(p) } catch (_: Exception) {}
                }
                try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
            }
            else -> {
                try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
            }
        }
    }

    private fun stopTunnel() {
        unwatchNetworkChanges()
        try { Mobilecore.stop() } catch (_: Exception) {}
        try { Mobilecore.setProtect(null) } catch (_: Exception) {}
        closeOwnedTunFd()
        tunFd = null
        running = false
        isRunning = false
        broadcast("disconnected", "")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // Смена сети (Wi-Fi ↔ мобильный интернет) рвёт установленные соединения: сокеты
    // остаются привязанными к пропавшему интерфейсу. Без реакции ядро продолжает
    // держать мёртвые соединения, и связь «висит», пока пользователь не переподключится.
    // Поэтому сообщаем системе актуальную сеть и просим ядро сбросить старые соединения —
    // новые установятся уже через новый интерфейс.
    private fun watchNetworkChanges() {
        if (netCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager ?: return
        val cb = object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                onNetworkSwitched(network)
            }
            override fun onCapabilitiesChanged(
                network: android.net.Network,
                caps: android.net.NetworkCapabilities,
            ) {
                if (caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    onNetworkSwitched(network)
                }
            }
            override fun onLost(network: android.net.Network) {
                // сеть пропала — ждём появления новой, соединения сбросим тогда
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
        } catch (_: Exception) {}
    }

    private fun unwatchNetworkChanges() {
        val cb = netCallback ?: return
        netCallback = null
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
        } catch (_: Exception) {}
    }

    @Volatile private var lastNetSwitch = 0L
    private fun onNetworkSwitched(network: android.net.Network) {
        if (!running) return
        // защита от шторма событий при переключении
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lastNetSwitch < 1500) return
        lastNetSwitch = now

        // система должна знать, поверх какой сети работает туннель
        try { setUnderlyingNetworks(arrayOf(network)) } catch (_: Exception) {}

        worker.execute {
            try {
                val u = java.net.URL("http://127.0.0.1:9090/connections")
                val c = u.openConnection() as java.net.HttpURLConnection
                c.requestMethod = "DELETE"
                c.connectTimeout = 2000
                c.readTimeout = 3000
                c.responseCode
                c.disconnect()
            } catch (_: Exception) {}
        }
    }

    // Закрывает дескриптор TUN, только если он всё ещё наш.
    // После detachFd() у ParcelFileDescriptor владения нет, и его close() ничего не закрывал:
    // интерфейс оставался поднятым, а трафик уходил в никуда даже после «отключить».
    private fun closeOwnedTunFd() {
        val raw = ownedTunFd
        ownedTunFd = -1
        if (raw >= 0) {
            try { ParcelFileDescriptor.adoptFd(raw).close() } catch (_: Exception) {}
        }
    }

    override fun onDestroy() {
        stopTunnel()
        worker.shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        // система отозвала разрешение VPN — гасим ядро в фоне, чтобы не блокировать поток
        worker.execute { stopTunnel() }
        super.onRevoke()
    }

    // Экранирование строки в YAML: имена узлов приходят из подписки и содержат
    // эмодзи, кавычки и двоеточия — без экранирования конфиг ломается.
    private fun yamlStr(v: String): String =
        "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    // (провайдер-режим, оставлен как справка; классический режим его не использует)
    private fun buildConfig(
        subUrl: String,
        hwid: String,
        userAgent: String,
        rules: Array<String>,
        chains: List<Pair<String, String>>, // имя цепочки → входной узел
        serviceGroups: Array<String>,       // имена select-групп сервисов (конфигуратор селекторов)
    ): String {
        // Заголовки запроса подписки. User-Agent определяет формат ответа панели: на
        // clash-UA приходит YAML, на v2ray/xray-UA — JSON или список ссылок. Провайдер
        // mihomo умеет только первое, поэтому здесь UA обязан быть clash-совместимым
        // (в классическом режиме формат разбирает Subscription.convert, и UA свободен).
        // Отступы без маркера "|": строка встраивается в шаблон как |$header,
        // маркер добавляет сам шаблон — иначе в YAML попадут литеральные палки.
        val header = buildString {
            append("    header:\n")
            append("      User-Agent: [${yamlStr(userAgent)}]")
            if (hwid.isNotEmpty()) {
                append("\n      x-hwid: [\"$hwid\"]")
                append("\n      x-device-os: [\"Android\"]")
                append("\n      x-ver-os: [\"${Build.VERSION.RELEASE}\"]")
                append("\n      x-device-model: [\"${Build.MODEL}\"]")
            }
        }

        // Цепочки: узлы приходят из провайдера подписки, поэтому dialer-proxy нельзя
        // повесить ни на группу (mihomo это запрещает), ни на конкретный узел.
        // Решение — ещё один провайдер с той же подпиской и override: все его узлы
        // ходят через входной узел, а префикс разводит имена с основными.
        val chainProviders = StringBuilder()
        val chainGroups = StringBuilder()
        val chainNames = mutableListOf<String>()
        chains.forEachIndexed { i, (name, entry) ->
            val groupName = "$CHAIN_PREFIX$name"
            chainNames += groupName
            chainProviders.append(
                """
                |  chain$i:
                |    type: http
                |    url: ${yamlStr(subUrl)}
                |    interval: 21600
                |    path: ./providers/chain$i.yaml
                |    override:
                |      dialer-proxy: ${yamlStr(entry)}
                |      additional-prefix: ${yamlStr("$name · ")}
                |$header
                """.trimMargin()
            ).append("\n")
            chainGroups.append(
                """
                |  - name: ${yamlStr(groupName)}
                |    type: select
                |    use:
                |      - chain$i
                """.trimMargin()
            ).append("\n")
        }

        // Цепочки добавляем в главный селектор, чтобы их можно было выбрать как обычный сервер
        val proxyGroupChains = if (chainNames.isEmpty()) "" else
            "\n    proxies:\n" + chainNames.joinToString("\n") { "      - ${yamlStr(it)}" }

        // Конфигуратор селекторов: на каждый сервис «свой выбор» — своя select-группа
        // поверх той же подписки (use: main). Правила GEOSITE,<geo>,<имя группы> приходят
        // в rules и ссылаются на эти группы; узел в группе юзер выбирает во вкладке СЕРВЕРЫ.
        val serviceGroupsBlock = StringBuilder()
        for (g in serviceGroups) {
            if (g.isBlank()) continue
            serviceGroupsBlock.append(
                """
                |  - name: ${yamlStr(g)}
                |    type: select
                |    use:
                |      - main
                """.trimMargin()
            ).append("\n")
        }

        val rulesBlock = buildString {
            for (r in rules) {
                val line = r.trim()
                if (line.isNotEmpty()) append("  - ").append(yamlStr(line)).append("\n")
            }
            append("  - MATCH,PROXY")
        }

        return """
            |mixed-port: 7890
            |mode: rule
            |log-level: warning
            |ipv6: false
            |unified-delay: true
            |# поиск процесса-владельца соединения нам не нужен (раздельный туннель делает
            |# VpnService), а на Android это сканирование /proc на каждое соединение — батарея
            |find-process-mode: "off"
            |# запоминать выбранный сервер между запусками
            |profile:
            |  store-selected: true
            |external-controller: 127.0.0.1:9090
            |dns:
            |  enable: true
            |  listen: 0.0.0.0:1053
            |  ipv6: false
            |  enhanced-mode: fake-ip
            |  fake-ip-range: 198.18.0.1/16
            |  fake-ip-filter:
            |    - "*.lan"
            |    - "*.local"
            |    - "localhost.ptlogin2.qq.com"
            |  default-nameserver:
            |    - 77.88.8.8
            |    - 223.5.5.5
            |  nameserver:
            |    - 77.88.8.8
            |    - 223.5.5.5
            |  proxy-server-nameserver:
            |    - 77.88.8.8
            |    - 223.5.5.5
            |proxy-providers:
            |  main:
            |    type: http
            |    url: ${yamlStr(subUrl)}
            |    interval: 3600
            |    path: ./providers/main.yaml
            |$header
            |$chainProviders
            |proxy-groups:
            |  - name: PROXY
            |    type: select$proxyGroupChains
            |    use:
            |      - main
            |$chainGroups
            |$serviceGroupsBlock
            |rules:
            |$rulesBlock
        """.trimMargin()
    }

    private fun startForegroundNotif() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW)
            nm.createNotificationChannel(ch)
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val notif: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Misetanibox")
            .setContentText("Туннель активен")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, notif, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun broadcast(state: String, message: String) {
        val i = Intent("network.geodema.misetanibox.VPN_STATE")
        i.setPackage(packageName)
        i.putExtra("state", state)
        i.putExtra("message", message)
        sendBroadcast(i)
        // держим плитку в шторке и виджет в актуальном состоянии
        try { VpnAppWidget.requestUpdate(this) } catch (_: Exception) {}
        try { VpnTileService.requestUpdate(this) } catch (_: Exception) {}
    }
}
