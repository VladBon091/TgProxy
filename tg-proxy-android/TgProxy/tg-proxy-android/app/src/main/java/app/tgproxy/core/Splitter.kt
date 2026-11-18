package app.tgproxy.core

/**
 * Режет расшифрованный поток клиента на отдельные пакеты MTProto-транспорта,
 * чтобы каждый уходил в WebSocket отдельным фреймом (так делает web.telegram.org).
 */
class PacketSplitter(private val tag: Int) {
    private var buf = ByteArray(4096)
    private var len = 0
    private var passthrough = false

    fun feed(data: ByteArray): List<ByteArray> {
        if (data.isEmpty()) return emptyList()
        if (passthrough) return listOf(data)
        ensure(len + data.size)
        System.arraycopy(data, 0, buf, len, data.size)
        len += data.size

        val out = ArrayList<ByteArray>()
        var pos = 0
        while (true) {
            val avail = len - pos
            if (avail <= 0) break
            val total = packetSize(pos, avail)
            if (total == NEED_MORE) break
            if (total < 0 || total > MAX_PACKET) {
                // Поток не похож на валидный транспорт — отдаём как есть, дальше не режем.
                out.add(buf.copyOfRange(pos, len))
                pos = len
                passthrough = true
                break
            }
            if (avail < total) break
            out.add(buf.copyOfRange(pos, pos + total))
            pos += total
        }
        if (pos > 0) {
            System.arraycopy(buf, pos, buf, 0, len - pos)
            len -= pos
        }
        return out
    }

    /** Полный размер пакета (с заголовком) или NEED_MORE, если заголовок ещё неполный. */
    private fun packetSize(pos: Int, avail: Int): Int {
        if (tag == Tag.ABRIDGED) {
            val first = buf[pos].toInt() and 0xff
            val f = first and 0x7f
            return if (f == 0x7f) {
                if (avail < 4) return NEED_MORE
                val words = (buf[pos + 1].toInt() and 0xff) or
                    ((buf[pos + 2].toInt() and 0xff) shl 8) or
                    ((buf[pos + 3].toInt() and 0xff) shl 16)
                4 + words * 4
            } else {
                1 + f * 4
            }
        }
        // intermediate / padded intermediate: 4 байта длины (старший бит — quick ack)
        if (avail < 4) return NEED_MORE
        val l = readIntLE(buf, pos) and 0x7fffffff
        return 4 + l
    }

    private fun ensure(cap: Int) {
        if (cap <= buf.size) return
        var n = buf.size
        while (n < cap) n *= 2
        buf = buf.copyOf(n)
    }

    companion object {
        private const val NEED_MORE = Int.MIN_VALUE
        private const val MAX_PACKET = 1 shl 24
    }
}
