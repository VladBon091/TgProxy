package app.tgproxy

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import app.tgproxy.core.Diagnostics
import app.tgproxy.core.Parse
import app.tgproxy.core.explain

class MainActivity : Activity(), Controller.Listener {

    private lateinit var prefs: Prefs
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var toggle: Button
    private lateinit var logView: TextView
    private lateinit var etPort: EditText
    private lateinit var etSecret: EditText
    private lateinit var etDcIps: EditText
    private lateinit var etWorkers: EditText
    private lateinit var etDomains: EditText
    private lateinit var cbNoTls: CheckBox
    private lateinit var cbWs: CheckBox
    private lateinit var cbTcp: CheckBox
    private lateinit var btnDiag: Button

    private val ui = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            refreshStatus()
            ui.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        setContentView(buildUi())
        loadFields()
    }

    override fun onStart() {
        super.onStart()
        Controller.listeners.add(this)
        logView.text = Controller.snapshot().joinToString("\n")
        refreshStatus()
        ui.post(ticker)
    }

    override fun onStop() {
        super.onStop()
        Controller.listeners.remove(this)
        ui.removeCallbacks(ticker)
    }

    override fun onLog(line: String) {
        if (logView.length() > 30000) {
            logView.text = Controller.snapshot().joinToString("\n")
        } else {
            logView.append("\n" + line)
        }
    }

    override fun onState() = refreshStatus()

    // ---- действия --------------------------------------------------------------------------

    private fun refreshStatus() {
        val s = Controller.server
        if (s != null && s.isRunning) {
            status.text = "● Работает: 127.0.0.1:${s.port}"
            status.setTextColor(Color.parseColor("#4ADE80"))
            toggle.text = "Остановить"
            val st = s.stats
            stats.text = "Соединений: ${st.active.get()} (всего ${st.total.get()})   ↑ ${fmt(st.bytesUp.get())}   ↓ ${fmt(st.bytesDown.get())}"
        } else {
            status.text = "● Остановлен"
            status.setTextColor(Color.parseColor("#F87171"))
            toggle.text = "Запустить"
            stats.text = ""
        }
    }

    private fun fmt(b: Long): String = when {
        b < 1024 -> "$b Б"
        b < 1024 * 1024 -> "${b / 1024} КБ"
        else -> String.format("%.1f МБ", b / 1048576.0)
    }

    private fun onToggle() {
        if (Controller.running) {
            startService(Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_STOP))
            return
        }
        if (!saveFields()) return
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        startForegroundService(Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_START))
    }

    private fun onSave() {
        if (!saveFields()) return
        if (Controller.running) {
            startForegroundService(Intent(this, ProxyService::class.java).setAction(ProxyService.ACTION_RESTART))
            toast("Сохранено, прокси перезапускается")
        } else {
            toast("Сохранено")
        }
    }

    private fun link(): String? = try {
        prefs.toConfig().tgLink()
    } catch (e: Exception) {
        null
    }

    private fun onApply() {
        if (!saveFields()) return
        val l = link() ?: return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(l)))
        } catch (e: ActivityNotFoundException) {
            toast("Telegram не найден. Ссылка скопирована — откройте её вручную")
            copy(l)
        }
    }

    private fun onDiagnose() {
        if (!saveFields()) return
        btnDiag.isEnabled = false
        btnDiag.text = "Проверяю…"
        Controller.log("— Диагностика: проверяю маршруты до DC2 и DC4 (до ~1 мин) —")
        Thread {
            var ok = 0
            var total = 0
            try {
                val cfg = prefs.toConfig()
                for (dc in intArrayOf(2, 4)) {
                    Diagnostics.run(cfg, dc = dc) { r ->
                        total++
                        if (r.ok) ok++
                        Controller.log("DC$dc ${if (r.ok) "✔" else "✘"} ${r.route.label} — ${r.detail} (${r.ms} мс)")
                    }
                }
            } catch (e: Exception) {
                Controller.log("Диагностика: ${explain(e)}")
            }
            val okF = ok
            val totalF = total
            runOnUiThread {
                btnDiag.isEnabled = true
                btnDiag.text = "Диагностика сети"
                val msg = if (okF > 0) {
                    "Рабочих маршрутов: $okF из $totalF. Прокси будет использовать их автоматически."
                } else {
                    "Ни один маршрут не ответил.\n\n" +
                        "• Прямой WS/TCP к Telegram у вашего оператора заблокирован.\n" +
                        "• Разверните свой Cloudflare Worker (кнопка «Скопировать код Worker») и впишите его домен в настройках.\n" +
                        "• Проверьте, что есть интернет и не включён другой VPN/прокси."
                }
                AlertDialog.Builder(this).setTitle("Результат диагностики").setMessage(msg)
                    .setPositiveButton("OK", null).show()
            }
        }.start()
    }

    private fun onCopyWorker() {
        try {
            val code = assets.open("cf-worker.js").bufferedReader().use { it.readText() }
            copy(code)
            toast("Код Worker скопирован: вставьте его в Cloudflare → Workers")
        } catch (e: Exception) {
            toast("Не удалось прочитать код: ${e.message}")
        }
    }

    private fun onBattery() {
        try {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        } catch (e: Exception) {
            toast("Откройте настройки батареи вручную")
        }
    }

    private fun copy(text: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("tgproxy", text))
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    // ---- поля настроек ---------------------------------------------------------------------

    private fun loadFields() {
        etPort.setText(prefs.port.toString())
        etSecret.setText(prefs.secretHex)
        etDcIps.setText(prefs.dcIps)
        etWorkers.setText(prefs.cfWorkers)
        etDomains.setText(prefs.cfDomains)
        cbNoTls.isChecked = prefs.cfNoTls
        cbWs.isChecked = prefs.wsDirect
        cbTcp.isChecked = prefs.tcpFallback
    }

    private fun saveFields(): Boolean {
        val port = etPort.text.toString().trim().toIntOrNull()
        if (port == null || port !in 1024..65535) {
            toast("Порт должен быть числом от 1024 до 65535")
            return false
        }
        val secret = etSecret.text.toString().trim()
        if (!Parse.isValidSecretHex(secret)) {
            toast("Секрет — ровно 32 hex-символа (0-9, a-f)")
            return false
        }
        prefs.port = port
        prefs.secretHex = secret
        prefs.dcIps = etDcIps.text.toString()
        prefs.cfWorkers = etWorkers.text.toString()
        prefs.cfDomains = etDomains.text.toString()
        prefs.cfNoTls = cbNoTls.isChecked
        prefs.wsDirect = cbWs.isChecked
        prefs.tcpFallback = cbTcp.isChecked
        return true
    }

    // ---- интерфейс -------------------------------------------------------------------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun lp(top: Int = 8) = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = dp(top) }

    private fun text(t: String, sp: Float = 14f, color: String = "#E5E7EB", bold: Boolean = false) =
        TextView(this).apply {
            text = t
            textSize = sp
            setTextColor(Color.parseColor(color))
            if (bold) setTypeface(typeface, Typeface.BOLD)
        }

    private fun button(t: String, onClick: () -> Unit) = Button(this).apply {
        text = t
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    private fun edit(hint: String, lines: Int = 1, number: Boolean = false) = EditText(this).apply {
        this.hint = hint
        setHintTextColor(Color.parseColor("#6B7280"))
        setTextColor(Color.WHITE)
        textSize = 14f
        if (number) inputType = InputType.TYPE_CLASS_NUMBER
        else if (lines > 1) {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = lines
        } else {
            inputType = InputType.TYPE_CLASS_TEXT
        }
        if (lines == 1) setSingleLine(true)
    }

    private fun check(t: String) = CheckBox(this).apply {
        text = t
        setTextColor(Color.parseColor("#E5E7EB"))
    }

    private fun buildUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(32))
            setBackgroundColor(Color.parseColor("#0F1419"))
        }
        root.addView(text("TG Proxy", 24f, "#FFFFFF", true))
        root.addView(text("Локальный MTProto-прокси: Telegram → WebSocket / Cloudflare → датацентр", 12f, "#9CA3AF"), lp(4))

        status = text("", 18f, "#F87171", true)
        root.addView(status, lp(20))
        stats = text("", 12f, "#9CA3AF")
        root.addView(stats, lp(2))

        toggle = button("Запустить") { onToggle() }
        root.addView(toggle, lp(12))
        root.addView(button("Применить в Telegram") { onApply() }, lp(4))
        root.addView(button("Скопировать ссылку tg://proxy") {
            if (saveFields()) link()?.let { copy(it); toast("Ссылка скопирована") }
        }, lp(4))
        btnDiag = button("Диагностика сети") { onDiagnose() }
        root.addView(btnDiag, lp(4))

        root.addView(text("Настройки", 18f, "#FFFFFF", true), lp(24))
        root.addView(text("Порт", 12f, "#9CA3AF"), lp(8))
        etPort = edit("1443", number = true)
        root.addView(etPort, lp(0))

        root.addView(text("Секрет (32 hex)", 12f, "#9CA3AF"), lp(8))
        etSecret = edit("32 hex-символа")
        root.addView(etSecret, lp(0))
        root.addView(button("Сгенерировать новый секрет") {
            etSecret.setText(Parse.randomSecretHex())
            toast("Не забудьте «Сохранить» и заново применить прокси в Telegram")
        }, lp(0))

        root.addView(text("IP для прямого WS (DC:IP, по одному в строке). По умолчанию для DC2/DC4 — 149.154.167.220", 12f, "#9CA3AF"), lp(8))
        etDcIps = edit("2:149.154.167.220", lines = 2)
        root.addView(etDcIps, lp(0))

        root.addView(text("Cloudflare Worker — домены через запятую", 12f, "#9CA3AF"), lp(8))
        etWorkers = edit("my-proxy.name.workers.dev")
        root.addView(etWorkers, lp(0))

        root.addView(text("Свои домены на Cloudflare (kwsN.<домен>) через запятую", 12f, "#9CA3AF"), lp(8))
        etDomains = edit("example.com")
        root.addView(etDomains, lp(0))

        cbNoTls = check("К Cloudflare без TLS (ws://, порт 80)")
        root.addView(cbNoTls, lp(8))
        cbWs = check("Прямой WebSocket к Telegram")
        root.addView(cbWs, lp(0))
        cbTcp = check("Резерв: прямой TCP к датацентру")
        root.addView(cbTcp, lp(0))

        root.addView(button("Сохранить") { onSave() }, lp(8))
        root.addView(button("Скопировать код Cloudflare Worker") { onCopyWorker() }, lp(4))
        root.addView(button("Отключить оптимизацию батареи") { onBattery() }, lp(4))

        root.addView(text("Журнал", 18f, "#FFFFFF", true), lp(24))
        logView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextColor(Color.parseColor("#D1D5DB"))
            setTextIsSelectable(true)
        }
        root.addView(logView, lp(8))
        root.addView(button("Скопировать журнал") {
            copy(Controller.snapshot().joinToString("\n")); toast("Журнал скопирован")
        }, lp(8))

        return ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0F1419"))
            addView(root)
        }
    }
}
