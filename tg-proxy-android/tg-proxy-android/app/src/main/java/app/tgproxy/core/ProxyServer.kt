package app.tgproxy.core

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs

class ProxyStats {
    val active = AtomicInteger()
    val total = AtomicLong()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    val accepted = AtomicLong()
    val rejected = AtomicLong()
}

/**
 * Локальный MTProto-прокси: принимает подключения Telegram (obfuscated2 + секрет)
 * и пересылает трафик в датацентры через WebSocket / Cloudflare / TCP.
 */
class ProxyServer(
    val cfg: ProxyConfig,
    private val env: NetEnv = NetEnv(),
    private val log: (String) -> Unit,
) {
    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "tgproxy").also { it.isDaemon = true }
    }
    private val connector = Connector(cfg, env, executor, log)

    @Volatile private var server: ServerSocket? = null
    val stats = ProxyStats()

    // Отклонённые подключения сворачиваем в одну сводку, чтобы журнал не забивался.
    private val rej = HashMap<String, Int>()
    private var rejTimerOn = false
    private val timer = java.util.Timer("tgproxy-rej", true)

    private fun rejected(kind: String) {
        stats.rejected.incrementAndGet()
        synchronized(rej) {
            val first = rej.isEmpty() && !rejTimerOn
            rej.merge(kind, 1, Int::plus)
            if (first) {
                log("Отклонено подключение: $kind")
                rejTimerOn = true
                try {
                    timer.schedule(object : java.util.TimerTask() {
                        override fun run() = flushRejected()
                    }, 3000)
                } catch (_: IllegalStateException) {
                }
            }
        }
    }

    private fun flushRejected() {
        synchronized(rej) {
            val total = rej.values.sum()
            if (total > 1) {
                log("Отклонено ещё ${total - 1} за 3 с: " + rej.entries.joinToString("; ") { "${it.key} ×${it.value}" })
            }
            rej.clear()
            rejTimerOn = false
        }
    }

    val port: Int get() = server?.localPort ?: cfg.port
    val isRunning: Boolean get() = server?.isClosed == false

    fun start() {
        check(server == null) { "already started" }
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(cfg.bindHost, cfg.port), 128)
        server = ss
        executor.execute {
            while (!ss.isClosed) {
                val c = try { ss.accept() } catch (_: IOException) { break }
                executor.execute { ClientConn(c).run() }
            }
        }
        log("Версия ядра: 1.1 (диагностика отказов, 167.220 для всех DC)")
        log("Прокси слушает ${cfg.bindHost}:${ss.localPort}")
    }

    fun stop() {
        try { server?.close() } catch (_: IOException) {}
        connector.shutdown()
        timer.cancel()
        executor.shutdownNow()
        log("Прокси остановлен")
    }

    // ---------------------------------------------------------------------------------------

    private class Attempt(val route: Route, val up: Upstream, val relay: RelaySession, val pooled: Boolean)

    /** attempt == null — клиент закрыл соединение. */
    private class Event(val attempt: Attempt?, val reason: String)

    private val deadDc = java.util.concurrent.ConcurrentHashMap<String, Long>()

    private fun order(routes: List<Route>, dcKey: String): List<Route> {
        val now = System.currentTimeMillis()
        val good = connector.lastGood[dcKey]?.key
        val (bad, ok) = routes.partition { (connector.failedAt[it.key] ?: 0L) + FAIL_PENALTY_MS > now }
        return ok.sortedByDescending { if (it.key == good) 1 else 0 } + bad
    }

    private inner class ClientConn(private val client: Socket) {
        private val stateLock = Any()
        private val writeLock = Any()
        private val pending = ArrayList<ByteArray>()
        private var pendingBytes = 0
        private var pendingSince = 0L
        private var replayable = true
        private var delivered = false

        @Volatile private var current: Attempt? = null
        @Volatile private var clientClosed = false
        private val events = LinkedBlockingQueue<Event>()
        private val firstAttempt = CountDownLatch(1)

        private lateinit var cs: ClientSession
        private lateinit var splitter: PacketSplitter
        private lateinit var clientOut: OutputStream
        private var dcKey = ""
        private var dcLabel = ""

        fun run() {
            stats.active.incrementAndGet()
            stats.total.incrementAndGet()
            try {
                client.tcpNoDelay = true
                client.soTimeout = 10_000
                val inp = client.getInputStream()
                clientOut = client.getOutputStream()

                val init = ByteArray(64)
                readFully(inp, init)
                val sess = Obf2.parseClientInit(init, cfg.secret)
                if (sess == null) {
                    rejected(Obf2.classify(init, cfg.secret))
                    return
                }
                stats.accepted.incrementAndGet()
                cs = sess
                splitter = PacketSplitter(sess.protoTag)
                client.soTimeout = 0

                val dc = abs(sess.dcRaw)
                val media = sess.dcRaw < 0
                dcKey = "$dc/$media"
                dcLabel = "DC$dc" + (if (media) " media" else "")
                if (dc > 1000) {
                    log("$dcLabel: тестовые DC не поддерживаются")
                    return
                }
                val routes = order(connector.routes(dc, media), dcKey)
                if (routes.isEmpty()) {
                    log("$dcLabel: нет доступных маршрутов (неизвестный DC)")
                    return
                }

                executor.execute { clientLoop(inp) }
                supervise(routes)
            } catch (_: EOFException) {
                // клиент закрылся до init — обычное дело
            } catch (e: Exception) {
                if (!clientClosed) log("Соединение: ${explain(e)}")
            } finally {
                clientClosed = true
                firstAttempt.countDown()
                current?.let { closeQuiet(it.up) }
                try { client.close() } catch (_: IOException) {}
                stats.active.decrementAndGet()
            }
        }

        // ---- клиент -> DC -----------------------------------------------------------------

        private fun clientLoop(inp: InputStream) {
            val buf = ByteArray(64 * 1024)
            try {
                while (!clientClosed) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    stats.bytesUp.addAndGet(n.toLong())
                    val plain = cs.dec.apply(buf, 0, n)
                    for (pkt in splitter.feed(plain)) sendPacket(pkt)
                    // пока нет первого подключения к DC, дальше не читаем
                    if (current == null) firstAttempt.await(15, TimeUnit.SECONDS)
                }
            } catch (_: IOException) {
            } finally {
                clientClosed = true
                events.add(Event(null, "client closed"))
            }
        }

        private fun sendPacket(p: ByteArray) {
            synchronized(writeLock) {
                val att: Attempt?
                synchronized(stateLock) {
                    if (!delivered && replayable) {
                        if (pendingBytes + p.size > MAX_PENDING) {
                            replayable = false
                            pending.clear()
                            pendingBytes = 0
                        } else {
                            pending.add(p)
                            pendingBytes += p.size
                            if (pendingSince == 0L) pendingSince = System.currentTimeMillis()
                        }
                    }
                    att = current
                }
                if (att != null) {
                    try {
                        att.up.write(att.relay.enc.apply(p))
                    } catch (e: IOException) {
                        events.add(Event(att, "запись: ${explain(e)}"))
                    }
                }
            }
        }

        // ---- DC -> клиент -----------------------------------------------------------------

        private fun upstreamLoop(a: Attempt) {
            try {
                while (true) {
                    val data = a.up.read()
                    if (data == null) {
                        events.add(Event(a, "соединение закрыто сервером"))
                        return
                    }
                    if (data.isEmpty()) continue
                    val plain = a.relay.dec.apply(data)
                    val out: ByteArray
                    synchronized(stateLock) {
                        if (current !== a) return
                        if (!delivered) {
                            delivered = true
                            pending.clear()
                            pendingBytes = 0
                            pendingSince = 0L
                            if (connector.lastGood[dcKey]?.key != a.route.key) {
                                log("$dcLabel: работает через «${a.route.label}»")
                            }
                            connector.markGood(dcKey, a.route)
                        }
                        out = cs.enc.apply(plain)
                    }
                    try {
                        clientOut.write(out)
                        clientOut.flush()
                    } catch (_: IOException) {
                        clientClosed = true
                        events.add(Event(null, "client write failed"))
                        return
                    }
                    stats.bytesDown.addAndGet(out.size.toLong())
                }
            } catch (e: Exception) {
                if (!clientClosed) events.add(Event(a, explain(e)))
            }
        }

        // ---- управление маршрутами ---------------------------------------------------------

        private fun connectAttempt(route: Route, fresh: Boolean): Attempt {
            val opened = connector.open(route, allowPool = !fresh)
            val relay = Obf2.makeRelayInit(cs.protoTag, cs.dcRaw)
            try {
                opened.up.write(relay.initWire)
            } catch (t: Throwable) {
                closeQuiet(opened.up)
                throw t
            }
            return Attempt(route, opened.up, relay, opened.pooled)
        }

        private fun supervise(routes: List<Route>) {
            // DC, к которому только что не достучались ни по одному маршруту: не держим клиента
            // ещё 15–20 с на заведомо мёртвых маршрутах (это забивает потоки и вешает приложение).
            val deadAt = deadDc[dcKey]
            if (deadAt != null && System.currentTimeMillis() - deadAt < DEAD_DC_MS) return
            var idx = 0
            var retryFresh: Route? = null
            while (!clientClosed) {
                var attempt: Attempt? = null
                while (attempt == null && !clientClosed) {
                    val fresh = retryFresh != null
                    val r = retryFresh ?: (if (idx < routes.size) routes[idx++] else break)
                    retryFresh = null
                    attempt = try {
                        connectAttempt(r, fresh)
                    } catch (e: Exception) {
                        connector.markFailed(r)
                        log("$dcLabel · ${r.label}: ${explain(e)}")
                        null
                    }
                }
                if (attempt == null) {
                    if (!clientClosed) {
                        deadDc[dcKey] = System.currentTimeMillis()
                        log("$dcLabel: все маршруты недоступны (пауза ${DEAD_DC_MS / 1000} с)")
                    }
                    return
                }
                val att: Attempt = attempt

                val switched = synchronized(writeLock) {
                    try {
                        val snapshot = synchronized(stateLock) { ArrayList(pending) }
                        for (p in snapshot) att.up.write(att.relay.enc.apply(p))
                        synchronized(stateLock) {
                            current = att
                            pendingSince = if (pending.isEmpty()) 0L else System.currentTimeMillis()
                        }
                        true
                    } catch (e: IOException) {
                        false
                    }
                }
                firstAttempt.countDown()
                if (!switched) {
                    closeQuiet(att.up)
                    if (att.pooled) {
                        retryFresh = att.route
                    } else {
                        connector.markFailed(att.route)
                        log("$dcLabel · ${att.route.label}: не удалось отправить данные")
                    }
                    continue
                }

                executor.execute { upstreamLoop(att) }

                val reason = waitFailure(att) ?: return
                if (synchronized(stateLock) { delivered }) {
                    // соединение отработало и закрылось штатно — это не сбой маршрута
                    return
                }
                if (att.pooled) {
                    // скорее всего, просто протухло заранее открытое соединение — пробуем тот же маршрут заново
                    retryFresh = att.route
                } else {
                    connector.markFailed(att.route)
                    log("$dcLabel · ${att.route.label}: $reason")
                }
                synchronized(stateLock) { current = null }
                closeQuiet(att.up)
                val canRetry = synchronized(stateLock) { replayable && !delivered }
                if (!canRetry) return
            }
        }

        /** Ждёт сбоя текущего маршрута. null — клиент отключился. */
        private fun waitFailure(a: Attempt): String? {
            while (true) {
                val ev = events.poll(400, TimeUnit.MILLISECONDS)
                if (ev != null) {
                    if (ev.attempt == null) return null
                    if (ev.attempt === a) return ev.reason
                    continue
                }
                if (clientClosed) return null
                synchronized(stateLock) {
                    if (!delivered && pending.isNotEmpty() && pendingSince != 0L &&
                        System.currentTimeMillis() - pendingSince > cfg.firstByteTimeoutMs
                    ) {
                        return "нет ответа за ${cfg.firstByteTimeoutMs / 1000} с"
                    }
                }
            }
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = inp.read(buf, off, buf.size - off)
            if (n < 0) throw EOFException()
            off += n
        }
    }

    private fun closeQuiet(c: java.io.Closeable) {
        try { c.close() } catch (_: Throwable) {}
    }

    companion object {
        private const val MAX_PENDING = 1 shl 20
        private const val FAIL_PENALTY_MS = 60_000L
        private const val DEAD_DC_MS = 30_000L
    }
}
