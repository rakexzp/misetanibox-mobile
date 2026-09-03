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
        const val EXTRA_CHAINS = "chains" // JSON: [{"name":"...","nodes":["..."]}]
        const val EXTRA_WARP = "warp"     // JSON кредов WARP или ""
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
                val chains = intent?.getStringExtra(EXTRA_CHAINS) ?: "[]"
                val warp = intent?.getStringExtra(EXTRA_WARP) ?: ""
                val serviceGroups = intent?.getStringArrayExtra(EXTRA_SERVICE_GROUPS) ?: arrayOf()
                if (subUrl.isEmpty()) {
                    // сюда попадаем при рестарте сервиса системой с пустым intent
                    stopSelf()
                    return START_NOT_STICKY
                }
                // Уведомление обязано появиться сразу после startForegroundService,
                // поэтому показываем его на главном потоке, а запуск ядра уводим в фон.
                startForegroundNotif()
                worker.execute { startTunnel(subUrl, hwid, userAgent, splitMode, splitApps, rules, chains, warp, serviceGroups) }
            }
        }
        // не START_STICKY: иначе система переподнимет сервис с пустым intent и без подписки
        return START_NOT_STICKY
    }

    private fun startTunnel(
        subUrl: String,
        hwid: String,
        userAgent: String,
        splitMode: String,
        splitApps: Array<String>,
        rules: Array<String>,
        chains: String,
        warp: String,
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

            // цепочки и WARP ядро вшивает в конфиг подписки перед стартом
            Mobilecore.setChains(chains)
            Mobilecore.setWarp(warp)
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
            .setSmallIcon(R.drawable.ic_notif)
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
