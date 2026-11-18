package app.tgproxy.core

import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSocketFactory

/** Известные IP датацентров Telegram и вспомогательные имена. */
object Dc {
    /** Адреса DC для прямого TCP и для Cloudflare Worker (?dst=). */
    val DEFAULT_IP: Map<Int, String> = mapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    /**
     * IP, который обслуживает WebSocket-эндпоинты DC2/DC4 и (по данным автора tg-ws-proxy)
     * находится в белом списке у части провайдеров.
     */
    const val WS_WHITELISTED_IP = "149.154.167.220"

    /** Через этот IP отвечают только kws2/kws4; для остальных DC он отдаёт 302/чужой сертификат. */
    val WS_WHITELISTED_DCS = setOf(2, 4)

    fun wsHosts(dc: Int, media: Boolean): List<String> {
        val plain = "kws$dc.web.telegram.org"
        val mediaHost = "kws$dc-1.web.telegram.org"
        return if (media) listOf(mediaHost, plain) else listOf(plain, mediaHost)
    }
}

class ProxyConfig(
    val port: Int = 1443,
    /** 16 байт секрета (без префикса dd). */
    val secret: ByteArray,
    /** Переопределения IP для прямого WS: dc -> ip. */
    val dcIps: Map<Int, String> = emptyMap(),
    /** Домены Cloudflare Worker (xxx.workers.dev). */
    val cfWorkers: List<String> = emptyList(),
    /** Свои домены на Cloudflare (kwsN.<домен> -> DC). */
    val cfDomains: List<String> = emptyList(),
    /** Подключаться к CF по ws:// (порт 80), без TLS. */
    val cfNoTls: Boolean = false,
    val wsDirect: Boolean = true,
    val tcpFallback: Boolean = true,
    val poolSize: Int = 1,
    val bindHost: String = "127.0.0.1",
    /** Сколько ждать первый ответ DC, прежде чем переключиться на следующий маршрут. */
    val firstByteTimeoutMs: Int = 4000,
) {
    init {
        require(secret.size == 16) { "secret must be 16 bytes" }
    }

    val secretHex: String get() = secret.joinToString("") { "%02x".format(it) }

    /** Ссылка для Telegram (режим "secure" — префикс dd). */
    fun tgLink(host: String = "127.0.0.1"): String = "tg://proxy?server=$host&port=$port&secret=dd$secretHex"
}

/** Подмены сети — нужны только тестам; в приложении используются значения по умолчанию. */
class NetEnv(
    val wsPortOverride: Int? = null,
    val tcpPortOverride: Int? = null,
    val sslFactory: SSLSocketFactory? = null,
    val hostnameVerifier: HostnameVerifier? = null,
    val connectTimeoutMs: Int = 5000,
    val handshakeTimeoutMs: Int = 5000,
    val tcpIpOverride: String? = null,
)
