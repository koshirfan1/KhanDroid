package com.khandroid.app.net.tls

import android.util.Log
import com.khandroid.app.net.http.HttpTap
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private const val TAG = "KhanDroid/TlsMitm"
private const val NET_BUF_SIZE = 32 * 1024
private const val SNI_WAIT_LIMIT = 4096 // give up waiting for a full ClientHello after this many bytes

/**
 * EXPERIMENTAL / best-effort: this hand-drives an [SSLEngine] (server
 * side, talking to the device) and a real [SSLSocket] (client side,
 * talking to the actual server) to terminate TLS on both ends and relay
 * decrypted HTTP through [httpTap]. It covers the common case — a normal
 * TLS 1.2/1.3 handshake, no client-certificate auth, no renegotiation —
 * but is not a hardened TLS implementation. Test against your own app
 * before relying on it (same caution the guide gives for Section 6.4).
 *
 * [sendToClient] must hand bytes to the owning TcpConnection's normal
 * sequence-tracked TCP send path — from the TCP layer's point of view
 * these are just more bytes on the same connection, which happen to be
 * our freshly re-encrypted TLS records instead of the original ones.
 */
class TlsMitmHandler(
    private val caManager: CaManager,
    private val serverAddr: InetAddress,
    private val serverPort: Int,
    private val plainSocket: Socket, // already TCP-connected (unencrypted) to the real server
    private val httpTap: HttpTap?,
    private val sendToClient: (ByteArray) -> Unit,
    private val onFatalError: () -> Unit
) {
    private var engine: SSLEngine? = null
    private val netIn = ByteBuffer.allocate(NET_BUF_SIZE)   // encrypted bytes from device, awaiting unwrap
    private val sniProbe = ByteArrayOutputStream()

    @Volatile private var deviceHandshakeDone = false
    @Volatile private var upstream: SSLSocket? = null
    @Volatile private var upstreamHandshakeDone = false
    private val pendingToUpstream = ByteArrayOutputStream() // client app-data buffered until upstream is ready

    /** Feed raw (still-encrypted) bytes arriving from the device. */
    @Synchronized
    fun handleClientBytes(buf: ByteArray, offset: Int, len: Int) {
        if (engine == null) {
            sniProbe.write(buf, offset, len)
            val probeBytes = sniProbe.toByteArray()
            val sni = TlsSni.extract(probeBytes, 0, probeBytes.size)
            if (sni == null && probeBytes.size < SNI_WAIT_LIMIT) return // wait for more of the ClientHello
            val host = sni ?: serverAddr.hostAddress ?: "unknown-host"
            setupEngine(host)
            connectUpstreamAsync(host)
            netIn.put(probeBytes)
            sniProbe.reset()
        } else {
            growIfNeededAndPut(buf, offset, len)
        }
        pump()
    }

    fun onConnectionClosed() {
        runCatching { upstream?.close() }
        httpTap?.onConnectionClosed()
    }

    private fun growIfNeededAndPut(buf: ByteArray, offset: Int, len: Int) {
        if (netIn.remaining() < len) {
            // Our capture loop reads bounded MTU-sized chunks, so this should be rare;
            // best-effort: drop the overflow rather than crashing.
            Log.w(TAG, "netIn buffer full, dropping ${len - netIn.remaining()} bytes")
        }
        val toWrite = minOf(len, netIn.remaining())
        netIn.put(buf, offset, toWrite)
    }

    private fun setupEngine(host: String) {
        val (leafCert, leafKey) = caManager.leafFor(host)

        val ks = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("leaf", leafKey, charArrayOf(), arrayOf(leafCert, caManager.caCertificate()))
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(ks, charArrayOf())
        }
        val ctx = SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, null, SecureRandom())
        }
        engine = ctx.createSSLEngine().apply {
            useClientMode = false
            beginHandshake()
        }
    }

    private fun connectUpstreamAsync(host: String) {
        Thread({
            try {
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                val s = factory.createSocket(plainSocket, host, serverPort, true) as SSLSocket
                s.startHandshake()
                upstream = s
                upstreamHandshakeDone = true
                flushPendingToUpstream()
                startUpstreamReader(s)
            } catch (e: Exception) {
                Log.w(TAG, "upstream TLS connect failed for $host:$serverPort", e)
                onFatalError()
            }
        }, "khandroid-tls-upstream").start()
    }

    private fun flushPendingToUpstream() {
        val s = upstream ?: return
        synchronized(pendingToUpstream) {
            if (pendingToUpstream.size() > 0) {
                runCatching { s.outputStream.write(pendingToUpstream.toByteArray()) }
                pendingToUpstream.reset()
            }
        }
    }

    private fun startUpstreamReader(s: SSLSocket) {
        Thread({
            val buf = ByteArray(16 * 1024)
            try {
                val input = s.inputStream
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    httpTap?.onServerBytes(buf, 0, n)
                    wrapAndSend(buf, 0, n)
                }
            } catch (e: Exception) {
                Log.d(TAG, "upstream reader ended: ${e.message}")
            } finally {
                onFatalError() // treat upstream close as end-of-connection for this MITM session
            }
        }, "khandroid-tls-upstream-read").start()
    }

    /** Drives the SSLEngine: consumes [netIn], performs the handshake, and relays any decrypted app data. */
    @Synchronized
    private fun pump() {
        val eng = engine ?: return
        val appOut = ByteBuffer.allocate(NET_BUF_SIZE)

        var iterations = 0
        loop@ while (true) {
            if (++iterations > 10_000) {
                Log.e(TAG, "pump() exceeded iteration cap, aborting connection (likely a handshake bug)")
                onFatalError()
                return
            }
            when (eng.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.NEED_TASK -> {
                    var task = eng.delegatedTask
                    while (task != null) {
                        task.run()
                        task = eng.delegatedTask
                    }
                    // loop back around: eng.handshakeStatus is now whatever comes next (usually NEED_WRAP)
                }
                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    val out = ByteBuffer.allocate(NET_BUF_SIZE)
                    val res = eng.wrap(ByteBuffer.allocate(0), out)
                    out.flip()
                    if (out.hasRemaining()) sendToClient(out.toByteArray())
                    if (res.status == SSLEngineResult.Status.CLOSED) { onFatalError(); return }
                }
                else -> {
                    val readView = netIn.duplicate().apply { flip() }
                    if (!readView.hasRemaining()) break@loop

                    val result = runCatching { eng.unwrap(readView, appOut) }.getOrElse {
                        Log.w(TAG, "unwrap failed", it); onFatalError(); return
                    }
                    compact(readView.position())

                    if (!deviceHandshakeDone && eng.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        deviceHandshakeDone = true
                    }

                    if (result.status == SSLEngineResult.Status.CLOSED) { onFatalError(); return }

                    if (result.bytesProduced() > 0) {
                        appOut.flip()
                        val plain = appOut.toByteArray()
                        appOut.clear()
                        handleAppDataFromClient(plain)
                    }

                    // Important: don't exit the whole pump() here just because this unwrap
                    // produced nothing — the engine may now be sitting on NEED_WRAP (e.g. it
                    // just consumed ClientHello and needs to emit ServerHello). Looping back
                    // lets the top of the loop re-check eng.handshakeStatus fresh. We only stop
                    // when there's truly nothing left to do without more bytes from the device.
                    if (result.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) break@loop
                    val stuckWaitingForMoreInput = !readView.hasRemaining() &&
                        eng.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                    if (stuckWaitingForMoreInput) break@loop
                }
            }
        }
    }

    private fun handleAppDataFromClient(plain: ByteArray) {
        httpTap?.onClientBytes(plain, 0, plain.size)
        val s = upstream
        if (s != null && upstreamHandshakeDone) {
            runCatching { s.outputStream.write(plain) }
        } else {
            synchronized(pendingToUpstream) { pendingToUpstream.write(plain) }
        }
    }

    private fun wrapAndSend(buf: ByteArray, offset: Int, len: Int) {
        val eng = engine ?: return
        var src = ByteBuffer.wrap(buf, offset, len)
        while (src.hasRemaining()) {
            val out = ByteBuffer.allocate(NET_BUF_SIZE)
            val res = synchronized(this) { eng.wrap(src, out) }
            out.flip()
            if (out.hasRemaining()) sendToClient(out.toByteArray())
            if (res.status == SSLEngineResult.Status.CLOSED) { onFatalError(); return }
        }
    }

    /** Shifts any unconsumed bytes in [netIn] to the front after [consumed] bytes were used by unwrap(). */
    private fun compact(consumed: Int) {
        val remaining = netIn.position() - consumed
        if (remaining > 0) {
            System.arraycopy(netIn.array(), consumed, netIn.array(), 0, remaining)
        }
        netIn.position(remaining)
    }

    private fun ByteBuffer.toByteArray(): ByteArray {
        val arr = ByteArray(remaining())
        get(arr)
        return arr
    }
}
