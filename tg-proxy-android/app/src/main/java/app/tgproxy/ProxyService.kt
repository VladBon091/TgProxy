package app.tgproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.os.Build
import android.os.IBinder
import app.tgproxy.core.ProxyServer

class ProxyService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxy()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                enterForeground("Перезапуск…")
                Thread { stopProxy(); startProxy() }.start()
                return START_STICKY
            }
            else -> {
                enterForeground("Запуск…")
                Thread { startProxy() }.start()
                return START_STICKY
            }
        }
    }

    private fun startProxy() {
        synchronized(LOCK) {
            if (Controller.running) {
                updateNotification()
                Controller.notifyState()
                return
            }
            val prefs = Prefs(this)
            try {
                val s = ProxyServer(prefs.toConfig()) { Controller.log(it) }
                s.start()
                Controller.server = s
                prefs.wasRunning = true
                Controller.log("Ссылка для Telegram: ${prefs.toConfig().tgLink()}")
            } catch (e: Exception) {
                Controller.log("Не удалось запустить: ${e.message} (возможно, порт занят — смените порт в настройках)")
                Controller.server = null
                prefs.wasRunning = false
                stopSelf()
            }
        }
        updateNotification()
        Controller.notifyState()
    }

    private fun stopProxy() {
        synchronized(LOCK) {
            Controller.server?.stop()
            Controller.server = null
            Prefs(this).wasRunning = false
        }
        Controller.notifyState()
    }

    override fun onDestroy() {
        synchronized(LOCK) {
            Controller.server?.stop()
            Controller.server = null
        }
        Controller.notifyState()
        super.onDestroy()
    }

    // ---- уведомление -----------------------------------------------------------------------

    private fun enterForeground(text: String) {
        val n = buildNotification(text)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    private fun updateNotification() {
        val port = Controller.server?.port
        val text = if (port != null) "Работает на 127.0.0.1:$port" else "Остановлен"
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "Работа прокси", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopAction = Notification.Action.Builder(
            Icon.createWithResource(this, R.drawable.ic_notification), "Остановить", stopIntent
        ).build()
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("TG Proxy")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(stopAction)
            .build()
    }

    companion object {
        const val ACTION_START = "app.tgproxy.START"
        const val ACTION_STOP = "app.tgproxy.STOP"
        const val ACTION_RESTART = "app.tgproxy.RESTART"
        private const val CHANNEL = "proxy"
        private const val NOTIF_ID = 1
        private val LOCK = Any()
    }
}
