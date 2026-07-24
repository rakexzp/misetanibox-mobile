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
    @Volatile private var running = false

    companion object {
        const val ACTION_START = "network.geodema.misetanibox.START"
        const val ACTION_STOP = "network.geodema.misetanibox.STOP"
        const val EXTRA_SUB_URL = "sub_url"
        const val EXTRA_HWID = "hwid"
        const val EXTRA_SPLIT_MODE = "split_mode"
        const val EXTRA_SPLIT_APPS = "split_apps"
        const val EXTRA_RULES = "rules"
        const val EXTRA_CHAINS = "chains" // JSON: [{"name":"...","entry":"..."}]
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
                val splitMode = intent?.getStringExtra(EXTRA_SPLIT_MODE) ?: "off"
                val splitApps = intent?.getStringArrayExtra(EXTRA_SPLIT_APPS) ?: arrayOf()
                val rules = intent?.getStringArrayExtra(EXTRA_RULES) ?: arrayOf()
                val chains = parseChains(intent?.getStringExtra(EXTRA_CHAINS))
                if (subUrl.isEmpty()) {
                    // сюда попадаем при рестарте сервиса системой с пустым intent
                    stopSelf()
                    return START_NOT_STICKY
                }
                // Уведомление обязано появиться сразу после startForegroundService,
                // поэтому показываем его на главном потоке, а запуск ядра уводим в фон.
                startForegroundNotif()
                worker.execute { startTunnel(subUrl, hwid, splitMode, splitApps, rules, chains) }
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
        splitMode: String,
        splitApps: Array<String>,
        rules: Array<String>,
        chains: List<Pair<String, String>>,
    ) {
        if (running) return
        try {
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
            val config = buildConfig(subUrl, hwid, rules, chains)

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
            running = true
            isRunning = true
            broadcast("connected", "")
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

    private fun buildConfig(
        subUrl: String,
        hwid: String,
        rules: Array<String>,
        chains: List<Pair<String, String>>, // имя цепочки → входной узел
    ): String {
        val header = if (hwid.isNotEmpty())
            """
            |    header:
            |      x-hwid: ["$hwid"]
            |      x-device-os: ["Android"]
            |      x-ver-os: ["${Build.VERSION.RELEASE}"]
            |      x-device-model: ["${Build.MODEL}"]
            """.trimMargin()
        else ""

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
                |    interval: 3600
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
            |log-level: info
            |ipv6: false
            |unified-delay: true
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
