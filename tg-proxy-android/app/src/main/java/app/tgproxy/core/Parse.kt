package app.tgproxy.core

import java.security.SecureRandom

/** Разбор пользовательских настроек. Чистый Kotlin, чтобы можно было тестировать без Android. */
object Parse {
    private val IP_RE = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
    private val HEX32 = Regex("^[0-9a-fA-F]{32}$")
    private val DOMAIN_RE = Regex("""^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$""")

    fun isValidIp(s: String): Boolean {
        val m = IP_RE.matchEntire(s) ?: return false
        return m.groupValues.drop(1).all { it.toInt() in 0..255 }
    }

    /** "2:149.154.167.220, 4:149.154.167.220" (запятые/пробелы/переводы строк) -> {2: ..., 4: ...} */
    fun dcIps(text: String): Map<Int, String> {
        val out = LinkedHashMap<Int, String>()
        for (tok in text.split('\n', '\r', ',', ';', ' ', '\t')) {
            val t = tok.trim()
            val i = t.indexOf(':')
            if (i <= 0) continue
            val dc = t.substring(0, i).toIntOrNull() ?: continue
            val ip = t.substring(i + 1).trim()
            if (isValidIp(ip)) out[dc] = ip
        }
        return out
    }

    /** Домены через запятую/пробел/перенос строки; схема и путь отбрасываются. */
    fun domains(text: String): List<String> {
        val out = ArrayList<String>()
        for (tok in text.split('\n', '\r', ',', ';', ' ', '\t')) {
            var t = tok.trim().lowercase()
            if (t.isEmpty()) continue
            t = t.removePrefix("https://").removePrefix("http://").removePrefix("wss://").removePrefix("ws://")
            t = t.substringBefore('/').substringBefore('?')
            if ((DOMAIN_RE.matches(t) || isValidIp(t)) && t !in out) out.add(t)
        }
        return out
    }

    fun isValidSecretHex(s: String) = HEX32.matches(s)

    fun hexToBytes(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun randomSecretHex(): String {
        val b = ByteArray(16)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }
}
