package com.khandroid.app.net.http

import java.io.ByteArrayOutputStream
import java.util.zip.GZIPInputStream

data class ParsedHttpMessage(
    val isRequest: Boolean,
    val requestLine: String?,  // "GET /path HTTP/1.1" (requests only)
    val statusLine: String?,   // "HTTP/1.1 200 OK" (responses only)
    val headers: List<Pair<String, String>>,
    val body: ByteArray
) {
    val method: String? get() = requestLine?.substringBefore(' ')
    val path: String? get() = requestLine?.split(' ')?.getOrNull(1)
    val statusCode: Int? get() = statusLine?.split(' ')?.getOrNull(1)?.toIntOrNull()
    fun header(name: String): String? =
        headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
}

private enum class State { START_LINE, HEADERS, BODY_CONTENT_LENGTH, BODY_CHUNKED, BODY_UNTIL_CLOSE, DONE }

/**
 * Feed raw bytes from one direction of a TCP connection (either all the
 * client->server bytes, or all the server->client bytes) incrementally as
 * they arrive; [poll] returns a completed message once enough bytes have
 * accumulated, or null if more data is needed.
 *
 * Only handles plain HTTP/1.1 text framing (no HTTP/2 binary framing).
 * Decompresses gzip bodies automatically; brotli/deflate bodies are kept
 * as raw bytes (documented limitation - not decoded).
 */
class HttpStreamParser(private val isRequestDirection: Boolean) {

    private var state = State.START_LINE
    private val lineBuf = ByteArrayOutputStream()
    private var startLine: String? = null
    private val headers = mutableListOf<Pair<String, String>>()
    private var contentLength = -1
    private var chunked = false
    private val body = ByteArrayOutputStream()
    private var chunkRemaining = -1

    fun feed(buf: ByteArray, offset: Int, len: Int): ParsedHttpMessage? {
        var i = offset
        val end = offset + len
        while (i < end) {
            when (state) {
                State.START_LINE, State.HEADERS -> {
                    val b = buf[i]; i++
                    if (b == '\n'.code.toByte()) {
                        val line = lineBuf.toString(Charsets.ISO_8859_1.name()).trimEnd('\r')
                        lineBuf.reset()
                        if (state == State.START_LINE) {
                            startLine = line
                            state = State.HEADERS
                        } else if (line.isEmpty()) {
                            onHeadersComplete()
                            if (state == State.DONE) return finish()
                        } else {
                            val idx = line.indexOf(':')
                            if (idx > 0) headers.add(line.substring(0, idx).trim() to line.substring(idx + 1).trim())
                        }
                    } else {
                        lineBuf.write(b.toInt())
                    }
                }
                State.BODY_CONTENT_LENGTH -> {
                    val remaining = contentLength - body.size()
                    val take = minOf(remaining, end - i)
                    body.write(buf, i, take)
                    i += take
                    if (body.size() >= contentLength) return finish()
                }
                State.BODY_UNTIL_CLOSE -> {
                    body.write(buf, i, end - i)
                    i = end
                    // Only "completes" when the connection closes; caller should call finishOnClose().
                }
                State.BODY_CHUNKED -> {
                    i = feedChunked(buf, i, end)?.let { return it } ?: end
                }
                State.DONE -> return null
            }
        }
        return null
    }

    /** Call when the underlying connection closes, to flush a BODY_UNTIL_CLOSE message with whatever was read. */
    fun finishOnClose(): ParsedHttpMessage? =
        if (state == State.BODY_UNTIL_CLOSE) finish() else null

    private fun onHeadersComplete() {
        val cl = headers.firstOrNull { it.first.equals("Content-Length", true) }?.second?.toIntOrNull()
        val te = headers.firstOrNull { it.first.equals("Transfer-Encoding", true) }?.second

        when {
            te != null && te.contains("chunked", ignoreCase = true) -> {
                chunked = true
                state = State.BODY_CHUNKED
            }
            cl != null -> {
                contentLength = cl
                state = if (cl == 0) State.DONE else State.BODY_CONTENT_LENGTH
            }
            !isRequestDirection -> state = State.BODY_UNTIL_CLOSE // responses with no length: read until close
            else -> state = State.DONE // requests with no body (e.g. GET)
        }
    }

    /** Parses one or more chunk-size/data segments; returns a completed message if the terminating 0-chunk was seen. */
    private fun feedChunked(buf: ByteArray, startIdx: Int, end: Int): ParsedHttpMessage? {
        var i = startIdx
        while (i < end) {
            if (chunkRemaining < 0) {
                // Need a chunk-size line, e.g. "1a3\r\n"
                val b = buf[i]; i++
                if (b == '\n'.code.toByte()) {
                    val line = lineBuf.toString(Charsets.ISO_8859_1.name()).trimEnd('\r')
                    lineBuf.reset()
                    val size = line.substringBefore(';').trim().toIntOrNull(16) ?: 0
                    if (size == 0) { state = State.DONE; return finish() }
                    chunkRemaining = size
                } else {
                    lineBuf.write(b.toInt())
                }
            } else if (chunkRemaining == 0) {
                // Consume the trailing CRLF after chunk data (2 bytes), then wait for next chunk-size line.
                i++
                chunkRemaining = -1
            } else {
                val take = minOf(chunkRemaining, end - i)
                body.write(buf, i, take)
                i += take
                chunkRemaining -= take
            }
        }
        return null
    }

    private fun finish(): ParsedHttpMessage {
        state = State.DONE
        var bodyBytes = body.toByteArray()
        val encoding = headers.firstOrNull { it.first.equals("Content-Encoding", true) }?.second
        if (encoding?.contains("gzip", ignoreCase = true) == true) {
            runCatching {
                bodyBytes = GZIPInputStream(bodyBytes.inputStream()).readBytes()
            } // on failure, keep the raw (still-compressed) bytes
        }
        return ParsedHttpMessage(
            isRequest = isRequestDirection,
            requestLine = if (isRequestDirection) startLine else null,
            statusLine = if (!isRequestDirection) startLine else null,
            headers = headers.toList(),
            body = bodyBytes
        )
    }
}
