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
    @Volatile private var running = false

    companion object {
        const val ACTION_START = "network.geodema.misetanibox.START"
        const val ACTION_STOP = "network.geodema.misetanibox.STOP"
        const val EXTRA_SUB_URL = "sub_url"
        const val EXTRA_HWID = "hwid"
        const val CHANNEL_ID = "misetanibox_vpn"
        const val NOTIF_ID = 7

        @Volatile var isRunning = false
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            else -> {
                val subUrl = intent?.getStringExtra(EXTRA_SUB_URL) ?: ""
                val hwid = intent?.getStringExtra(EXTRA_HWID) ?: ""
                startTunnel(subUrl, hwid)
            }
        }
        return START_STICKY
    }

    private fun startTunnel(subUrl: String, hwid: String) {
        if (running) return
        try {
            val builder = Builder()
                .setSession("Misetanibox")
                .setMtu(9000)
                .addAddress("172.19.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("172.19.0.2")
                .setBlocking(false)
            // не заворачиваем собственный трафик приложения в туннель
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            val pfd = builder.establish() ?: run {
                broadcast("error", "establish() вернул null — нет разрешения VPN или активен другой VPN")
                return
            }
            tunFd = pfd
            val fd = pfd.detachFd()

            val homeDir = File(filesDir, "clash").apply { mkdirs() }.absolutePath
            val config = buildConfig(subUrl, hwid)

            // защита исходящих сокетов ядра (иначе петля через TUN)
            Mobilecore.setProtect(object : SocketProtector {
                override fun protect(fd: Long): Boolean = protect(fd.toInt())
            })

            startForegroundNotif()
            val err = Mobilecore.start(homeDir, config, fd.toLong())
            if (err.isNotEmpty()) {
                broadcast("error", err)
                stopTunnel()
                return
            }
            running = true
            isRunning = true
            broadcast("connected", "")
        } catch (e: Exception) {
            broadcast("error", e.message ?: "неизвестная ошибка запуска")
            stopTunnel()
        }
    }

    private fun stopTunnel() {
        try { Mobilecore.stop() } catch (_: Exception) {}
        try { Mobilecore.setProtect(null) } catch (_: Exception) {}
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        running = false
        isRunning = false
        broadcast("disconnected", "")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    private fun buildConfig(subUrl: String, hwid: String): String {
        val header = if (hwid.isNotEmpty())
            """
            |    header:
            |      x-hwid: ["$hwid"]
            |      x-device-os: ["Android"]
            |      x-ver-os: ["${Build.VERSION.RELEASE}"]
            |      x-device-model: ["${Build.MODEL}"]
            """.trimMargin()
        else ""
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
            |    - "localhost.ptlogin2.qq.com"
            |  nameserver:
            |    - https://1.1.1.1/dns-query
            |    - https://8.8.8.8/dns-query
            |  default-nameserver:
            |    - 1.1.1.1
            |    - 8.8.8.8
            |proxy-providers:
            |  main:
            |    type: http
            |    url: "$subUrl"
            |    interval: 3600
            |    path: ./providers/main.yaml
            |$header
            |proxy-groups:
            |  - name: PROXY
            |    type: select
            |    use:
            |      - main
            |rules:
            |  - MATCH,PROXY
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
    }
}
