package app.tgproxy.core

import java.net.ConnectException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException

/** Человекочитаемое описание сетевой ошибки (для лога и диагностики). */
fun explain(e: Throwable): String = when (e) {
    is WsHandshakeException ->
        "сервер ответил HTTP ${e.status}" + (e.location?.let { " → $it" } ?: "")
    is SocketTimeoutException -> "таймаут"
    is ConnectException -> "нет соединения (отказ или маршрут заблокирован)"
    is UnknownHostException -> "домен не резолвится (DNS)"
    is SSLException -> "TLS: ${e.message}"
    is SocketException -> "обрыв: ${e.message}"
    else -> "${e.javaClass.simpleName}: ${e.message}"
}
