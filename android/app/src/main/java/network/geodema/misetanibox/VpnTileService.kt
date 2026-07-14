package network.geodema.misetanibox

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast

/**
 * Плитка в шторке (Quick Settings) — тап включает/выключает VPN, как у Happ / ByeByeDPI.
 * Стартует из сохранённых VpnPrefs, без открытия окна приложения.
 */
class VpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        handleToggle()
    }

    private fun handleToggle() {
        if (MihomoVpnService.isRunning) {
            VpnPrefs.stopVpn(this)
            qsTile?.apply {
                state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) subtitle = "Выкл"
                updateTile()
            }
            return
        }

        if (!VpnPrefs.hasSubscription(this)) {
            toast("Сначала добавьте подписку в Misetanibox")
            openApp()
            return
        }

        if (VpnService.prepare(this) != null) {
            toast("Откройте Misetanibox и разрешите VPN")
            openApp()
            return
        }

        val err = VpnPrefs.startFromPrefs(this)
        if (err != null) {
            toast(err)
            openApp()
            return
        }
        qsTile?.apply {
            state = Tile.STATE_ACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) subtitle = "Вкл…"
            updateTile()
        }
    }

    private fun refreshTile() {
        val tile = qsTile ?: return
        tile.label = getString(R.string.app_name)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_qs_tile)
        if (MihomoVpnService.isRunning) {
            tile.state = Tile.STATE_ACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) tile.subtitle = "VPN"
        } else {
            tile.state = Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = if (VpnPrefs.hasSubscription(this)) "Выкл" else "Нет подписки"
            }
        }
        tile.updateTile()
    }

    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        if (Build.VERSION.SDK_INT >= 34) {
            val pi = PendingIntent.getActivity(
                this, 0, i,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }

    private fun toast(msg: String) {
        Toast.makeText(applicationContext, msg, Toast.LENGTH_SHORT).show()
    }

    companion object {
        fun requestUpdate(ctx: Context) {
            try {
                val cn = ComponentName(ctx, VpnTileService::class.java)
                TileService.requestListeningState(ctx, cn)
            } catch (_: Exception) {
            }
        }
    }
}
