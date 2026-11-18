package app.tgproxy.core

import java.security.SecureRandom
import java.util.concurrent.Executors

class DiagResult(val route: Route, val ok: Boolean, val ms: Long, val detail: String)

/**
 * Реальная проверка каждого маршрута: открываем канал к DC, отправляем настоящий
 * запрос req_pq_multi и ждём ответ resPQ. Так видно, какой маршрут работает
 * именно в вашей сети прямо сейчас.
 */
object Diagnostics {
    private const val READ_TIMEOUT_MS = 7000

    fun run(
        cfg: ProxyConfig,
        env: NetEnv = NetEnv(),
        dc: Int = 2,
        media: Boolean = false,
        onResult: (DiagResult) -> Unit = {},
    ): List<DiagResult> {
        val executor = Executors.newCachedThreadPool { r -> Thread(r, "tgproxy-diag").also { it.isDaemon = true } }
        val connector = Connector(cfg, env.copyForDiag(), executor, {})
        val results = ArrayList<DiagResult>()
        try {
            for (route in connector.routes(dc, media)) {
                val r = probe(connector, route, dc)
                results.add(r)
                onResult(r)
            }
        } finally {
            connector.shutdown()
            executor.shutdownNow()
        }
        return results
    }

    private fun NetEnv.copyForDiag() = NetEnv(
        wsPortOverride, tcpPortOverride, sslFactory, hostnameVerifier,
        connectTimeoutMs = minOf(connectTimeoutMs, 6000),
        handshakeTimeoutMs = minOf(handshakeTimeoutMs, 6000),
        tcpIpOverride = tcpIpOverride,
    )

    private fun probe(connector: Connector, route: Route, dc: Int): DiagResult {
        val t0 = System.currentTimeMillis()
        var up: Upstream? = null
        try {
            up = connector.openFresh(route)
            val relay = Obf2.makeRelayInit(Tag.ABRIDGED, dc)
            up.write(relay.initWire)

            val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
            up.write(relay.enc.apply(reqPqMulti(nonce)))

            up.setReadTimeout(READ_TIMEOUT_MS)
            val acc = java.io.ByteArrayOutputStream()
            while (acc.size() < RESPONSE_MIN) {
                val data = up.read() ?: return fail(route, t0, "сервер закрыл соединение, не ответив")
                acc.write(relay.dec.apply(data))
            }
            val resp = acc.toByteArray()
            // abridged: [len/4] + auth_key_id(8) + msg_id(8) + len(4) + constructor(4) + nonce(16) ...
            val ctor = readIntLE(resp, 21)
            val nonceBack = resp.copyOfRange(25, 41)
            if (ctor != RES_PQ) return fail(route, t0, "неожиданный ответ DC (не resPQ)")
            if (!nonceBack.contentEquals(nonce)) return fail(route, t0, "nonce не совпал")
            return DiagResult(route, true, System.currentTimeMillis() - t0, "ответ DC получен")
        } catch (e: Throwable) {
            return fail(route, t0, explain(e))
        } finally {
            try { up?.close() } catch (_: Throwable) {}
        }
    }

    private fun fail(route: Route, t0: Long, msg: String) =
        DiagResult(route, false, System.currentTimeMillis() - t0, msg)

    private const val RESPONSE_MIN = 41
    private val RES_PQ = 0x05162463
    private val REQ_PQ_MULTI = 0xbe7e8ef1.toInt()

    /** Незашифрованный MTProto-запрос req_pq_multi в abridged-транспорте. */
    internal fun reqPqMulti(nonce: ByteArray): ByteArray {
        val payload = ByteArray(40)
        // auth_key_id = 0 (8 байт), message_id (8), message_length (4), constructor (4), nonce (16)
        val msgId = (System.currentTimeMillis() / 1000L) shl 32
        for (i in 0 until 8) payload[8 + i] = (msgId ushr (8 * i)).toByte()
        writeIntLE(payload, 16, 20)
        writeIntLE(payload, 20, REQ_PQ_MULTI)
        System.arraycopy(nonce, 0, payload, 24, 16)
        return byteArrayOf((payload.size / 4).toByte()) + payload
    }
}
