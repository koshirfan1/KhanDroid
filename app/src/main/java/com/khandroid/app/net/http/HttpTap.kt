package com.khandroid.app.net.http

import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.net.crypto.DecryptorRegistry
import java.util.concurrent.ConcurrentLinkedQueue

private const val PREVIEW_LIMIT = 4096 // only keep this many bytes for the human-readable preview

/**
 * Sits on one TCP connection, watching bytes in both directions. Not a
 * transform — it only taps/copies what's already being relayed, so it
 * works equally for plain HTTP (tapping the raw relay) and for MITM'd
 * HTTPS (tapping the decrypted plaintext on each side of the TLS layer).
 *
 * Assumes non-pipelined HTTP/1.1 (one in-flight request per connection at
 * a time), which covers virtually all real mobile app / browser traffic.
 */
class HttpTap(
    private val packageName: String,
    private val host: String,
    private val port: Int,
    private val isTls: Boolean,
    private val decryptKey: ByteArray?,
    private val onExchange: (HttpExchangeEntity) -> Unit
) {
    private var reqParser = HttpStreamParser(isRequestDirection = true)
    private var resParser = HttpStreamParser(isRequestDirection = false)
    private val pendingRequests = ConcurrentLinkedQueue<ParsedHttpMessage>()
    private var reqStartTime = 0L

    fun onClientBytes(buf: ByteArray, offset: Int, len: Int) {
        if (reqStartTime == 0L) reqStartTime = System.currentTimeMillis()
        val msg = runCatching { reqParser.feed(buf, offset, len) }.getOrNull() ?: return
        pendingRequests.add(msg)
        reqParser = HttpStreamParser(isRequestDirection = true) // ready for the next request on this connection
    }

    fun onServerBytes(buf: ByteArray, offset: Int, len: Int) {
        val msg = runCatching { resParser.feed(buf, offset, len) }.getOrNull() ?: return
        completeExchange(msg)
        resParser = HttpStreamParser(isRequestDirection = false)
    }

    /** Call when the connection closes, in case the last response was framed by "read until close". */
    fun onConnectionClosed() {
        resParser.finishOnClose()?.let { completeExchange(it) }
    }

    private fun completeExchange(response: ParsedHttpMessage) {
        val request = pendingRequests.poll() ?: return // response with no matching request: drop (can't attribute it)
        val now = System.currentTimeMillis()

        var decryptedWith: String? = null
        var resBody = response.body
        DecryptorRegistry.tryDecrypt(response.body, decryptKey)?.let { (name, plain) ->
            decryptedWith = name
            resBody = plain
        }

        val resolvedHost = request.header("Host")?.substringBefore(':')?.takeIf { it.isNotBlank() } ?: host

        val entity = HttpExchangeEntity(
            time = now,
            packageName = packageName,
            isTls = isTls,
            host = resolvedHost,
            port = port,
            method = request.method ?: "?",
            path = request.path ?: "?",
            reqHeadersBlock = request.headers.joinToString("\n") { "${it.first}: ${it.second}" },
            reqBodyPreview = previewOf(request.body),
            statusCode = response.statusCode,
            resHeadersBlock = response.headers.joinToString("\n") { "${it.first}: ${it.second}" },
            resBodyPreview = previewOf(resBody),
            durationMs = now - (if (reqStartTime != 0L) reqStartTime else now),
            decryptedWith = decryptedWith
        )
        onExchange(entity)
    }

    private fun previewOf(body: ByteArray): String? {
        if (body.isEmpty()) return null
        val slice = body.copyOfRange(0, minOf(body.size, PREVIEW_LIMIT))
        // Best-effort text preview; binary bodies will just show as odd characters
        // rather than crashing (no strict charset decoding here).
        return String(slice, Charsets.UTF_8).let {
            if (body.size > PREVIEW_LIMIT) it + "\u2026 [truncated, ${body.size} bytes total]" else it
        }
    }
}
