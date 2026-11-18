package app.tgproxy.core

import java.io.Closeable
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executor

/** Канал к датацентру Telegram (WebSocket или чистый TCP). */
interface Upstream : Closeable {
    /** true — одна запись = одно WS-сообщение, границы пакетов MTProto важны. */
    val framed: Boolean
    fun write(data: ByteArray)

    /** Следующий кусок данных или null при закрытии. */
    fun read(): ByteArray?
    fun setReadTimeout(ms: Int)
}

class WsUpstream(val ws: WsClient) : Upstream {
    override val framed = true
    override fun write(data: ByteArray) = ws.sendBinary(data)
    override fun read(): ByteArray? = ws.readMessage()
    override fun setReadTimeout(ms: Int) = ws.setReadTimeout(ms)
    override fun close() = ws.close()
}

class TcpUpstream(private val sock: Socket) : Upstream {
    override val framed = false
    private val input = sock.getInputStream()
    private val output = sock.getOutputStream()
    private val buf = ByteArray(64 * 1024)
    override fun write(data: ByteArray) {
        output.write(data)
        output.flush()
    }

    override fun read(): ByteArray? {
        val n = input.read(buf)
        return if (n < 0) null else buf.copyOf(n)
    }

    override fun setReadTimeout(ms: Int) {
        sock.soTimeout = ms
    }

    override fun close() {
        try { sock.close() } catch (_: IOException) {}
    }
}

/** Один из способов добраться до DC. */
sealed class Route {
    abstract val key: String
    abstract val label: String

    /** wss://<host>/apiws, но TCP-соединение идёт на [ip] (SNI = host). */
    data class DirectWs(val ip: String, val host: String) : Route() {
        override val key get() = "ws|$ip|$host"
        override val label get() = "WS напрямую: $host → $ip"
    }

    /** Cloudflare Worker: wss://<domain>/apiws?dst=<ip>, воркер открывает TCP до DC. */
    data class CfWorker(val domain: String, val dstIp: String) : Route() {
        override val key get() = "cfw|$domain|$dstIp"
        override val label get() = "CF Worker: $domain"
    }

    /** Свой домен на Cloudflare: wss://kwsN.<domain>/apiws. */
    data class CfDomain(val domain: String, val host: String) : Route() {
        override val key get() = "cfd|$host"
        override val label get() = "CF-домен: $host"
    }

    /** Обычное TCP-подключение к DC (работает, только если IP не заблокирован). */
    data class Tcp(val ip: String) : Route() {
        override val key get() = "tcp|$ip"
        override val label get() = "TCP напрямую: $ip:443"
    }
}

/** Строит список маршрутов под конкретный DC и открывает соединения. */
class Connector(
    private val cfg: ProxyConfig,
    private val env: NetEnv,
    private val executor: Executor,
    private val log: (String) -> Unit,
) {
    val lastGood = ConcurrentHashMap<String, Route>()
    val failedAt = ConcurrentHashMap<String, Long>()

    private class Pooled(val ws: WsClient, val at: Long)

    private val pool = ConcurrentHashMap<String, ConcurrentLinkedDeque<Pooled>>()
    private val refilling = ConcurrentHashMap<String, Boolean>()

    @Volatile private var stopped = false

    fun routes(dc: Int, media: Boolean): List<Route> {
        val defaultIp = Dc.DEFAULT_IP[dc]
        val out = ArrayList<Route>()
        if (cfg.wsDirect && defaultIp != null) {
            val ip = cfg.dcIps[dc] ?: (if (dc == 2 || dc == 4) Dc.WS_WHITELISTED_IP else defaultIp)
            for (h in Dc.wsHosts(dc, media)) out.add(Route.DirectWs(ip, h))
        }
        if (defaultIp != null) {
            for (w in cfg.cfWorkers) out.add(Route.CfWorker(w, cfg.dcIps[dc] ?: defaultIp))
        }
        for (d in cfg.cfDomains) out.add(Route.CfDomain(d, "kws$dc.$d"))
        if (cfg.tcpFallback && defaultIp != null) out.add(Route.Tcp(defaultIp))
        return out
    }

    class Opened(val up: Upstream, val pooled: Boolean)

    /** Открывает соединение (с использованием пула для прямого WS). init пока не отправлен. */
    fun open(route: Route, allowPool: Boolean = true): Opened {
        val usePool = allowPool && route is Route.DirectWs && cfg.poolSize > 0
        if (usePool) {
            val pooled = takePooled(route.key)
            if (pooled != null) {
                scheduleRefill(route as Route.DirectWs)
                return Opened(WsUpstream(pooled), true)
            }
        }
        val up = openFresh(route)
        if (usePool) scheduleRefill(route as Route.DirectWs)
        return Opened(up, false)
    }

    fun openFresh(route: Route): Upstream = when (route) {
        is Route.DirectWs -> WsUpstream(
            WsClient.connect(
                WsOptions(
                    connectIp = route.ip, host = route.host,
                    port = env.wsPortOverride ?: 443, path = "/apiws", tls = true,
                    connectTimeoutMs = env.connectTimeoutMs, handshakeTimeoutMs = env.handshakeTimeoutMs,
                    sslFactory = env.sslFactory, hostnameVerifier = env.hostnameVerifier,
                )
            )
        )
        is Route.CfWorker -> WsUpstream(
            WsClient.connect(cfOptions(route.domain, "/apiws?dst=${route.dstIp}"))
        )
        is Route.CfDomain -> WsUpstream(
            WsClient.connect(cfOptions(route.host, "/apiws"))
        )
        is Route.Tcp -> {
            val s = Socket()
            try {
                s.tcpNoDelay = true
                s.keepAlive = true
                s.connect(InetSocketAddress(env.tcpIpOverride ?: route.ip, env.tcpPortOverride ?: 443), env.connectTimeoutMs)
                TcpUpstream(s)
            } catch (t: Throwable) {
                try { s.close() } catch (_: IOException) {}
                throw t
            }
        }
    }

    private fun cfOptions(host: String, path: String): WsOptions {
        val tls = !cfg.cfNoTls
        return WsOptions(
            connectIp = null, host = host,
            port = env.wsPortOverride ?: (if (tls) 443 else 80), path = path, tls = tls,
            connectTimeoutMs = env.connectTimeoutMs, handshakeTimeoutMs = env.handshakeTimeoutMs,
            sslFactory = env.sslFactory, hostnameVerifier = env.hostnameVerifier,
        )
    }

    private fun takePooled(key: String): WsClient? {
        val q = pool[key] ?: return null
        val now = System.currentTimeMillis()
        while (true) {
            val p = q.pollFirst() ?: return null
            if (now - p.at <= POOL_MAX_AGE_MS) return p.ws
            p.ws.close()
        }
    }

    private fun scheduleRefill(route: Route.DirectWs) {
        if (stopped) return
        if (refilling.putIfAbsent(route.key, true) != null) return
        executor.execute {
            try {
                val q = pool.getOrPut(route.key) { ConcurrentLinkedDeque() }
                val now = System.currentTimeMillis()
                q.removeAll { p ->
                    val stale = now - p.at > POOL_MAX_AGE_MS
                    if (stale) p.ws.close()
                    stale
                }
                while (!stopped && q.size < cfg.poolSize) {
                    val ws = (openFresh(route) as WsUpstream).ws
                    q.add(Pooled(ws, System.currentTimeMillis()))
                    if (stopped) break
                }
            } catch (_: Throwable) {
                // пул — только оптимизация; ошибки не важны
            } finally {
                refilling.remove(route.key)
            }
        }
    }

    fun markGood(dcKey: String, route: Route) {
        lastGood[dcKey] = route
        failedAt.remove(route.key)
    }

    fun markFailed(route: Route) {
        failedAt[route.key] = System.currentTimeMillis()
    }

    fun shutdown() {
        stopped = true
        for (q in pool.values) {
            while (true) {
                val p = q.pollFirst() ?: break
                p.ws.close()
            }
        }
        pool.clear()
    }

    companion object {
        private const val POOL_MAX_AGE_MS = 20_000L
    }
}
