package network.geodema.misetanibox

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

/**
 * Виджет на рабочем столе: статус VPN + тап по кнопке вкл/выкл, тап по телу — открыть приложение.
 * Работает через VpnPrefs (стартует из сохранённых параметров, без открытия окна).
 */
class VpnAppWidget : AppWidgetProvider() {

    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        for (id in ids) updateWidget(context, manager, id)
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        when (intent.action) {
            ACTION_TOGGLE -> {
                if (MihomoVpnService.isRunning) {
                    VpnPrefs.stopVpn(context)
                } else {
                    val err = VpnPrefs.startFromPrefs(context)
                    if (err != null) {
                        val open = Intent(context, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(open)
                    }
                }
                requestUpdate(context)
            }
            VPN_STATE_ACTION, Intent.ACTION_BOOT_COMPLETED -> requestUpdate(context)
        }
    }

    companion object {
        const val ACTION_TOGGLE = "network.geodema.misetanibox.WIDGET_TOGGLE"
        const val VPN_STATE_ACTION = "network.geodema.misetanibox.VPN_STATE"

        fun requestUpdate(ctx: Context) {
            try {
                val mgr = AppWidgetManager.getInstance(ctx)
                val cn = ComponentName(ctx, VpnAppWidget::class.java)
                val ids = mgr.getAppWidgetIds(cn)
                if (ids.isEmpty()) return
                val intent = Intent(ctx, VpnAppWidget::class.java).apply {
                    action = AppWidgetManager.ACTION_APPWIDGET_UPDATE
                    putExtra(AppWidgetManager.EXTRA_APPWIDGET_IDS, ids)
                }
                ctx.sendBroadcast(intent)
            } catch (_: Exception) {
            }
        }

        fun updateWidget(context: Context, manager: AppWidgetManager, id: Int) {
            val views = RemoteViews(context.packageName, R.layout.widget_vpn)
            val on = MihomoVpnService.isRunning
            views.setTextViewText(R.id.widget_status, if (on) "VPN ON" else "VPN OFF")
            views.setTextViewText(R.id.widget_mode, if (on) "туннель активен" else "тап — вкл/выкл")
            val openPi = PendingIntent.getActivity(
                context, 10,
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val togglePi = PendingIntent.getBroadcast(
                context, 11,
                Intent(context, VpnAppWidget::class.java).setAction(ACTION_TOGGLE),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            views.setOnClickPendingIntent(R.id.widget_root, openPi)
            views.setOnClickPendingIntent(R.id.widget_toggle, togglePi)
            manager.updateAppWidget(id, views)
        }
    }
}
