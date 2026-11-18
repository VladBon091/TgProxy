package app.tgproxy.selftest

import app.tgproxy.core.Diagnostics
import app.tgproxy.core.NetEnv
import app.tgproxy.core.Parse
import app.tgproxy.core.ProxyConfig
import app.tgproxy.core.ProxyServer
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Тест-стенд: запускает ядро прокси против локальных фейковых серверов.
 * Аргументы: mode proxyPort secretHex wsPort tcpPort certPem
 */
private fun parseSelfCheck() {
    fun eq(a: Any?, b: Any?, what: String) { if (a != b) error("parse check failed: $what: $a != $b") }
    eq(Parse.dcIps("2:149.154.167.220\n4:149.154.167.220, 9:bad, x:1.2.3.4, 5:1.2.3.999"), mapOf(2 to "149.154.167.220", 4 to "149.154.167.220"), "dcIps")
    eq(Parse.domains("https://Foo.Workers.dev/path, bar.example.com  baz"), listOf("foo.workers.dev", "bar.example.com"), "domains")
    eq(Parse.isValidSecretHex("00112233445566778899aabbccddeeff"), true, "secret ok")
    eq(Parse.isValidSecretHex("zz112233445566778899aabbccddeeff"), false, "secret bad")
    eq(Parse.hexToBytes("00ff10").toList(), listOf<Byte>(0, -1, 16), "hex")
    eq(Parse.randomSecretHex().length, 32, "random secret")
    println("PARSE OK")
}

fun main(args: Array<String>) {
    if (args[0] == "parse") { parseSelfCheck(); return }
    val mode = args[0]
    val proxyPort = args[1].toInt()
    val secret = args[2].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val wsPort = args[3].toInt()
    val tcpPort = args[4].toInt()
    val certPath = args[5]

    val cert = FileInputStream(certPath).use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null); setCertificateEntry("test", cert) }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
    val ssl = SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }

    val env = NetEnv(
        wsPortOverride = wsPort, tcpPortOverride = tcpPort, sslFactory = ssl.socketFactory,
        tcpIpOverride = "127.0.0.1", connectTimeoutMs = 2000, handshakeTimeoutMs = 2000,
    )

    val secretArr = secret
    val cfg = when (mode) {
        "ws" -> ProxyConfig(port = proxyPort, secret = secretArr, dcIps = mapOf(2 to "127.0.0.1", 4 to "127.0.0.1"),
            tcpFallback = false)
        "cf" -> ProxyConfig(port = proxyPort, secret = secretArr, wsDirect = false, tcpFallback = false,
            cfWorkers = listOf("127.0.0.1"), cfNoTls = true)
        "tcp" -> ProxyConfig(port = proxyPort, secret = secretArr, wsDirect = false, tcpFallback = true)
        "failover" -> ProxyConfig(port = proxyPort, secret = secretArr, dcIps = mapOf(2 to "127.0.0.2", 4 to "127.0.0.2"),
            tcpFallback = true, firstByteTimeoutMs = 1500, poolSize = 0)
        "refuse" -> ProxyConfig(port = proxyPort, secret = secretArr, dcIps = mapOf(2 to "127.0.0.4", 4 to "127.0.0.4"),
            tcpFallback = true)
        "diag" -> ProxyConfig(port = proxyPort, secret = secretArr, dcIps = mapOf(2 to "127.0.0.1"),
            cfWorkers = listOf("127.0.0.1"), cfNoTls = true, tcpFallback = true)
        "diag-bad" -> ProxyConfig(port = proxyPort, secret = secretArr, dcIps = mapOf(2 to "127.0.0.2"),
            cfWorkers = listOf("127.0.0.3"), cfNoTls = true, tcpFallback = false)
        else -> error("unknown mode $mode")
    }

    if (mode.startsWith("diag")) {
        val res = Diagnostics.run(cfg, env, dc = 2)
        for (r in res) println("DIAG ${if (r.ok) "OK" else "FAIL"} | ${r.route.label} | ${r.ms} ms | ${r.detail}")
        println("DONE")
        return
    }

    val server = ProxyServer(cfg, env) { println("LOG $it") }
    server.start()
    println("READY ${server.port}")
    System.out.flush()
    // работаем, пока не закроют stdin
    while (System.`in`.read() >= 0) { }
    server.stop()
}
