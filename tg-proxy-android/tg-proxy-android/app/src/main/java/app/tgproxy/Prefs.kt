package app.tgproxy

import android.content.Context
import app.tgproxy.core.Parse
import app.tgproxy.core.ProxyConfig

class Prefs(ctx: Context) {
    private val p = ctx.applicationContext.getSharedPreferences("tgproxy", Context.MODE_PRIVATE)

    var port: Int
        get() = p.getInt("port", 1443)
        set(v) { p.edit().putInt("port", v).apply() }

    var secretHex: String
        get() {
            var s = p.getString("secret", null)
            if (s == null || !Parse.isValidSecretHex(s)) {
                s = Parse.randomSecretHex()
                p.edit().putString("secret", s).apply()
            }
            return s
        }
        set(v) { p.edit().putString("secret", v.lowercase()).apply() }

    var dcIps: String
        get() = p.getString("dcIps", "") ?: ""
        set(v) { p.edit().putString("dcIps", v).apply() }

    var cfWorkers: String
        get() = p.getString("cfWorkers", "") ?: ""
        set(v) { p.edit().putString("cfWorkers", v).apply() }

    var cfDomains: String
        get() = p.getString("cfDomains", "") ?: ""
        set(v) { p.edit().putString("cfDomains", v).apply() }

    var cfNoTls: Boolean
        get() = p.getBoolean("cfNoTls", false)
        set(v) { p.edit().putBoolean("cfNoTls", v).apply() }

    var wsDirect: Boolean
        get() = p.getBoolean("wsDirect", true)
        set(v) { p.edit().putBoolean("wsDirect", v).apply() }

    var tcpFallback: Boolean
        get() = p.getBoolean("tcpFallback", true)
        set(v) { p.edit().putBoolean("tcpFallback", v).apply() }

    var wasRunning: Boolean
        get() = p.getBoolean("wasRunning", false)
        set(v) { p.edit().putBoolean("wasRunning", v).apply() }

    fun toConfig(): ProxyConfig = ProxyConfig(
        port = port,
        secret = Parse.hexToBytes(secretHex),
        dcIps = Parse.dcIps(dcIps),
        cfWorkers = Parse.domains(cfWorkers),
        cfDomains = Parse.domains(cfDomains),
        cfNoTls = cfNoTls,
        wsDirect = wsDirect,
        tcpFallback = tcpFallback,
    )
}
