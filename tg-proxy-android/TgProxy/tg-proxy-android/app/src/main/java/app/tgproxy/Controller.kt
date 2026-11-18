package app.tgproxy

import android.os.Handler
import android.os.Looper
import app.tgproxy.core.ProxyServer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/** Общее состояние между сервисом и экраном. */
object Controller {
    interface Listener {
        fun onLog(line: String)
        fun onState()
    }

    val listeners = CopyOnWriteArrayList<Listener>()

    @Volatile var server: ProxyServer? = null

    private val main = Handler(Looper.getMainLooper())
    private val lines = ArrayList<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    val running: Boolean get() = server?.isRunning == true

    fun log(msg: String) {
        val line = fmt.format(Date()) + "  " + msg
        synchronized(lines) {
            lines.add(line)
            while (lines.size > 400) lines.removeAt(0)
        }
        main.post { for (l in listeners) l.onLog(line) }
    }

    fun snapshot(): List<String> = synchronized(lines) { ArrayList(lines) }

    fun notifyState() {
        main.post { for (l in listeners) l.onState() }
    }
}
