package network.geodema.misetanibox

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import java.util.Calendar

/** Напоминания «подписка скоро истечёт» за 3/2/1 день до срока, раз в день (заголовок notification-subs-expire). */
object ExpiryReminder {
    private const val CHANNEL = "misetanibox_sub"
    private const val K_NAME = "rem_name"; private const val K_EXPIRE = "rem_expire"; private const val K_ON = "rem_on"

    fun save(ctx: Context, name: String, expireAt: Long, enabled: Boolean) {
        VpnPrefs.prefs(ctx).edit().putString(K_NAME, name).putLong(K_EXPIRE, expireAt).putBoolean(K_ON, enabled).apply()
    }

    fun schedule(ctx: Context) {
        val p = VpnPrefs.prefs(ctx); val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val expire = p.getLong(K_EXPIRE, 0L); val on = p.getBoolean(K_ON, false)
        for (d in 1..3) am.cancel(pending(ctx, d))
        if (!on || expire <= 0) return
        val now = System.currentTimeMillis()
        for (d in 3 downTo 1) {
            val c = Calendar.getInstance().apply { timeInMillis = (expire - d * 86400L) * 1000L; set(Calendar.HOUR_OF_DAY, 11); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0) }
            if (c.timeInMillis <= now) continue
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, c.timeInMillis, pending(ctx, d))
        }
    }

    private fun pending(ctx: Context, d: Int): PendingIntent {
        val i = Intent(ctx, ExpiryReminderReceiver::class.java).setAction("network.geodema.misetanibox.SUB_EXPIRE").putExtra("day", d)
        return PendingIntent.getBroadcast(ctx, 7000 + d, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    fun notify(ctx: Context) {
        val name = VpnPrefs.prefs(ctx).getString(K_NAME, "") ?: ""
        val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) nm.createNotificationChannel(NotificationChannel(CHANNEL, "Подписка", NotificationManager.IMPORTANCE_DEFAULT))
        val pi = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val text = "У вашей подписки $name скоро истечёт срок действия, не забудьте продлить её."
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(ctx, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(ctx)
        val n = b.setContentTitle("Misetanibox").setContentText(text).setStyle(Notification.BigTextStyle().bigText(text))
            .setSmallIcon(R.drawable.ic_notif).setContentIntent(pi).setAutoCancel(true).build()
        try { nm.notify(7100, n) } catch (_: Exception) {}
    }
}

class ExpiryReminderReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) { ExpiryReminder.notify(context) }
}
