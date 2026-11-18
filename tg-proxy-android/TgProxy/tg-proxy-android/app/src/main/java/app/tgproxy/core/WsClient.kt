package app.tgproxy.core

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class WsHandshakeException(message: String, val status: Int, val location: String? = null) : IOException(message)

class WsOptions(
    /** IP, к которому реально подключаемся. null — обычный DNS по [host]. */
    val connectIp: String?,
    /** Host-заголовок (и SNI, если не задан [sni]). */
    val host: String,
    val port: Int,
    val path: String,
    val tls: Boolean,
    val sni: String = host,
    val connectTimeoutMs: Int = 5000,
    val handshakeTimeoutMs: Int = 5000,
    val sslFactory: SSLSocketFactory? = null,
    val hostnameVerifier: HostnameVerifier? = null,
)

/**
 * Минимальный WebSocket-клиент (RFC 6455) поверх обычного сокета.
 * Нужен, чтобы полностью контролировать, к какому IP мы подключаемся и какой SNI отправляем.
 */
class WsClient private constructor(
    private val sock: Socket,
    private val input: InputStream,
    private val output: OutputStream,
) : Closeable {

    private val writeLock = Any()
    private val rnd = SecureRandom()
    @Volatile private var closed = false

    val createdAt: Long = System.currentTimeMillis()

    fun setReadTimeout(ms: Int) {
        sock.soTimeout = ms
    }

    fun sendBinary(data: ByteArray) = sendFrame(0x2, data)

    fun sendPing() = sendFrame(0x9, ByteArray(0))

    private fun sendFrame(opcode: Int, payload: ByteArray) {
        val n = payload.size
        val headerLen = 2 + (if (n < 126) 0 else if (n <= 0xffff) 2 else 8) + 4
        val frame = ByteArray(headerLen + n)
        var p = 0
        frame[p++] = (0x80 or opcode).toByte()
        when {
            n < 126 -> frame[p++] = (0x80 or n).toByte()
            n <= 0xffff -> {
                frame[p++] = (0x80 or 126).toByte()
                frame[p++] = (n ushr 8).toByte()
                frame[p++] = n.toByte()
            }
            else -> {
                frame[p++] = (0x80 or 127).toByte()
                val l = n.toLong()
                for (i in 7 downTo 0) frame[p++] = (l ushr (8 * i)).toByte()
            }
        }
        val mask = ByteArray(4)
        rnd.nextBytes(mask)
        System.arraycopy(mask, 0, frame, p, 4)
        p += 4
        for (i in 0 until n) frame[p + i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    /** Следующее бинарное/текстовое сообщение целиком, или null, если соединение закрыто сервером. */
    fun readMessage(): ByteArray? {
        var assembled: ByteArrayOutputStream? = null
        while (true) {
            val b0 = input.read()
            if (b0 < 0) return null
            val b1 = input.read()
            if (b1 < 0) throw EOFException("ws: truncated frame header")
            val fin = (b0 and 0x80) != 0
            val opcode = b0 and 0x0f
            val masked = (b1 and 0x80) != 0
            var len = (b1 and 0x7f).toLong()
            if (len == 126L) {
                len = ((readU8() shl 8) or readU8()).toLong()
            } else if (len == 127L) {
                len = 0
                for (i in 0 until 8) len = (len shl 8) or readU8().toLong()
            }
            if (len < 0 || len > MAX_MESSAGE) throw IOException("ws: frame too large ($len)")
            val mask = if (masked) ByteArray(4).also { readFully(it) } else null
            val payload = ByteArray(len.toInt())
            readFully(payload)
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i and 3].toInt()).toByte()

            when (opcode) {
                0x8 -> { // close
                    try { sendFrame(0x8, payload.copyOf(minOf(payload.size, 2))) } catch (_: IOException) {}
                    return null
                }
                0x9 -> { // ping
                    try { sendFrame(0xA, payload) } catch (_: IOException) {}
                    continue
                }
                0xA -> continue // pong
                0x1, 0x2 -> {
                    if (fin) return payload
                    assembled = ByteArrayOutputStream().also { it.write(payload) }
                }
                0x0 -> {
                    val a = assembled ?: throw IOException("ws: unexpected continuation frame")
                    a.write(payload)
                    if (a.size() > MAX_MESSAGE) throw IOException("ws: message too large")
                    if (fin) return a.toByteArray()
                }
                else -> throw IOException("ws: unknown opcode $opcode")
            }
        }
    }

    private fun readU8(): Int {
        val v = input.read()
        if (v < 0) throw EOFException("ws: unexpected EOF")
        return v
    }

    private fun readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw EOFException("ws: unexpected EOF")
            off += n
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            // вежливое закрытие, но без ожидания ответа
            sock.soTimeout = 300
            sendFrame(0x8, byteArrayOf(0x03, 0xE8.toByte()))
        } catch (_: Throwable) {
        }
        try { sock.close() } catch (_: Throwable) {}
    }

    companion object {
        private const val MAX_MESSAGE = 8L * 1024 * 1024
        private const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        private const val USER_AGENT =
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"

        fun connect(o: WsOptions): WsClient {
            val addr = if (o.connectIp != null) InetAddress.getByName(o.connectIp) else InetAddress.getByName(o.host)
            val raw = Socket()
            var sock: Socket = raw
            try {
                raw.tcpNoDelay = true
                raw.keepAlive = true
                raw.connect(InetSocketAddress(addr, o.port), o.connectTimeoutMs)
                raw.soTimeout = o.handshakeTimeoutMs

                if (o.tls) {
                    val factory = o.sslFactory ?: (SSLSocketFactory.getDefault() as SSLSocketFactory)
                    val ssl = factory.createSocket(raw, o.sni, o.port, true) as SSLSocket
                    sock = ssl
                    val params = ssl.sslParameters
                    params.serverNames = listOf(SNIHostName(o.sni))
                    params.endpointIdentificationAlgorithm = "HTTPS"
                    ssl.sslParameters = params
                    ssl.startHandshake()
                    val v = o.hostnameVerifier
                    if (v != null && !v.verify(o.sni, ssl.session)) {
                        throw SSLPeerUnverifiedException("hostname verification failed for ${o.sni}")
                    }
                }

                val input = BufferedInputStream(sock.getInputStream(), 16 * 1024)
                val output = sock.getOutputStream()

                val keyBytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val key = Base64.getEncoder().encodeToString(keyBytes)
                val hostHeader = if ((o.tls && o.port == 443) || (!o.tls && o.port == 80)) o.host else "${o.host}:${o.port}"
                val req = buildString {
                    append("GET ").append(o.path).append(" HTTP/1.1\r\n")
                    append("Host: ").append(hostHeader).append("\r\n")
                    append("Upgrade: websocket\r\n")
                    append("Connection: Upgrade\r\n")
                    append("Sec-WebSocket-Key: ").append(key).append("\r\n")
                    append("Sec-WebSocket-Version: 13\r\n")
                    append("Sec-WebSocket-Protocol: binary\r\n")
                    append("Origin: https://web.telegram.org\r\n")
                    append("User-Agent: ").append(USER_AGENT).append("\r\n")
                    append("\r\n")
                }
                output.write(req.toByteArray(Charsets.ISO_8859_1))
                output.flush()

                val status = readLine(input) ?: throw IOException("ws: empty handshake response")
                val parts = status.split(' ', limit = 3)
                val code = parts.getOrNull(1)?.toIntOrNull() ?: throw IOException("ws: bad status line: $status")
                val headers = HashMap<String, String>()
                var total = status.length
                while (true) {
                    val line = readLine(input) ?: throw IOException("ws: truncated handshake")
                    if (line.isEmpty()) break
                    total += line.length
                    if (total > 32 * 1024) throw IOException("ws: handshake headers too large")
                    val i = line.indexOf(':')
                    if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
                }
                if (code != 101) {
                    throw WsHandshakeException("HTTP $code", code, headers["location"])
                }
                val expect = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.ISO_8859_1))
                )
                if (headers["sec-websocket-accept"] != expect) throw IOException("ws: bad Sec-WebSocket-Accept")

                sock.soTimeout = 0
                return WsClient(sock, input, output)
            } catch (t: Throwable) {
                try { sock.close() } catch (_: Throwable) {}
                try { raw.close() } catch (_: Throwable) {}
                throw t
            }
        }

        private fun readLine(input: InputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val c = input.read()
                if (c < 0) return if (sb.isEmpty()) null else sb.toString()
                if (c == '\n'.code) {
                    if (sb.isNotEmpty() && sb[sb.length - 1] == '\r') sb.setLength(sb.length - 1)
                    return sb.toString()
                }
                sb.append(c.toChar())
                if (sb.length > 16 * 1024) throw IOException("ws: header line too long")
            }
        }
    }
}
