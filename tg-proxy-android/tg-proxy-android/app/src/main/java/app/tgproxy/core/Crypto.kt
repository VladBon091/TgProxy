package app.tgproxy.core

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Теги транспорта MTProto (последние 4 байта расшифрованного init-пакета). */
object Tag {
    val ABRIDGED: Int = 0xefefefef.toInt()
    val INTERMEDIATE: Int = 0xeeeeeeee.toInt()
    val PADDED: Int = 0xdddddddd.toInt()
}

internal fun readIntLE(b: ByteArray, o: Int): Int =
    (b[o].toInt() and 0xff) or
        ((b[o + 1].toInt() and 0xff) shl 8) or
        ((b[o + 2].toInt() and 0xff) shl 16) or
        ((b[o + 3].toInt() and 0xff) shl 24)

internal fun writeIntLE(b: ByteArray, o: Int, v: Int) {
    b[o] = v.toByte()
    b[o + 1] = (v ushr 8).toByte()
    b[o + 2] = (v ushr 16).toByte()
    b[o + 3] = (v ushr 24).toByte()
}

/** int16 little-endian со знаком (отрицательный DC = media). */
internal fun readShortLE(b: ByteArray, o: Int): Int =
    ((b[o + 1].toInt() shl 8) or (b[o].toInt() and 0xff)).toShort().toInt()

internal fun writeShortLE(b: ByteArray, o: Int, v: Int) {
    b[o] = v.toByte()
    b[o + 1] = (v ushr 8).toByte()
}

/** AES-256-CTR как поток: состояние счётчика сохраняется между вызовами. */
class AesCtr(key: ByteArray, iv: ByteArray) {
    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").also {
        it.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }

    fun apply(data: ByteArray, off: Int = 0, len: Int = data.size - off): ByteArray {
        if (len == 0) return ByteArray(0)
        val out = cipher.update(data, off, len)
        check(out != null && out.size == len) { "AES-CTR returned unexpected length" }
        return out
    }
}

/** Сторона клиента (Telegram -> наш локальный прокси). */
class ClientSession(
    /** расшифровка данных от клиента */
    val dec: AesCtr,
    /** шифрование данных для клиента */
    val enc: AesCtr,
    val protoTag: Int,
    /** DC как прислал клиент: <0 = media, >10000 = тестовый */
    val dcRaw: Int,
)

/** Сторона датацентра (наш прокси -> DC), без секрета. */
class RelaySession(
    /** 64 байта, которые нужно отправить DC как есть */
    val initWire: ByteArray,
    val enc: AesCtr,
    val dec: AesCtr,
)

object Obf2 {
    private val FORBIDDEN_FIRST = setOf(
        0x44414548, // "HEAD"
        0x54534f50, // "POST"
        0x20544547, // "GET "
        0x4954504f, // "OPTI"
        0x02010316,
        0xdddddddd.toInt(),
        0xeeeeeeee.toInt(),
    )

    /**
     * Разбирает 64-байтный obfuscated2 init от клиента с учётом секрета прокси.
     * Возвращает null, если секрет не подошёл или тег транспорта некорректен.
     */
    fun parseClientInit(init: ByteArray, secret: ByteArray): ClientSession? {
        require(init.size == 64)
        val sha = MessageDigest.getInstance("SHA-256")

        sha.update(init, 8, 32)
        sha.update(secret)
        val decKey = sha.digest()
        val decIv = init.copyOfRange(40, 56)
        val dec = AesCtr(decKey, decIv)
        val plain = dec.apply(init) // сдвигает состояние на 64 байта — так и надо

        val tag = readIntLE(plain, 56)
        if (tag != Tag.ABRIDGED && tag != Tag.INTERMEDIATE && tag != Tag.PADDED) return null
        val dc = readShortLE(plain, 60)

        val rev = init.copyOfRange(8, 56).reversedArray()
        sha.reset()
        sha.update(rev, 0, 32)
        sha.update(secret)
        val encKey = sha.digest()
        val encIv = rev.copyOfRange(32, 48)
        return ClientSession(dec, AesCtr(encKey, encIv), tag, dc)
    }

    /** Для журнала: почему 64-байтный init не подошёл (чтобы понять, кто и как подключается). */
    fun classify(init: ByteArray, secret: ByteArray): String {
        val b0 = init[0].toInt() and 0xff
        val b1 = init[1].toInt() and 0xff
        if (b0 == 0x16 && b1 == 0x03) {
            return "fake-TLS клиент (секрет на «ee…»): этот прокси принимает только секрет «dd…»"
        }
        val head = String(init, 0, 4, Charsets.ISO_8859_1)
        if (head == "GET " || head == "POST" || head == "HEAD" || head == "OPTI" || head == "CONN") {
            return "HTTP-запрос, это не Telegram (порт проверяет другое приложение?)"
        }
        val plain = AesCtr(init.copyOfRange(8, 40), init.copyOfRange(40, 56)).apply(init)
        val tag = readIntLE(plain, 56)
        if (tag == Tag.ABRIDGED || tag == Tag.INTERMEDIATE || tag == Tag.PADDED) {
            return "клиент без секрета: в Telegram запись прокси без секрета (удалите её)"
        }
        return "неверный секрет: в Telegram, вероятно, осталась старая запись прокси с другим секретом"
    }

    /** Создаёт init-пакет для подключения к DC (как это делает обычный клиент без прокси). */
    fun makeRelayInit(tag: Int, dcRaw: Int, rnd: SecureRandom = SecureRandom()): RelaySession {
        val init = ByteArray(64)
        while (true) {
            rnd.nextBytes(init)
            if (init[0] == 0xef.toByte()) continue
            if (readIntLE(init, 0) in FORBIDDEN_FIRST) continue
            if (readIntLE(init, 4) == 0) continue
            break
        }
        writeIntLE(init, 56, tag)
        writeShortLE(init, 60, dcRaw)

        val enc = AesCtr(init.copyOfRange(8, 40), init.copyOfRange(40, 56))
        val encInit = enc.apply(init) // состояние продолжается после 64 байт
        val wire = init.copyOf()
        System.arraycopy(encInit, 56, wire, 56, 8)

        val rev = init.copyOfRange(8, 56).reversedArray()
        val dec = AesCtr(rev.copyOfRange(0, 32), rev.copyOfRange(32, 48))
        return RelaySession(wire, enc, dec)
    }
}
