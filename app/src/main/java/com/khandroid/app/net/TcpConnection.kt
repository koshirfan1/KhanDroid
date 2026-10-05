package com.khandroid.app.net

import android.net.VpnService
import android.util.Log
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.net.http.HttpTap
import com.khandroid.app.net.tls.CaManager
import com.khandroid.app.net.tls.TlsMitmHandler
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

private const val TAG = "KhanDroid/Tcp"
private const val OUR_RECV_WINDOW = 65535
private const val CHUNK_SIZE = 1360 // keeps the IPv4/TCP segment under a 1400-byte MTU
private const val MASK32 = 0xFFFFFFFFL

enum class TcpState { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }
private enum class Mode { UNDECIDED, PLAIN, MITM }

/**
 * One terminated TCP connection: the device's app talks TCP to us over the
 * TUN interface, and we relay the bytes through a real, protected [Socket]
 * to the actual destination. Also the integration point for HTTP tapping
 * (guide Section 6) and TLS MITM (Section 6.4), decided lazily from the
 * first client payload bytes once the connection is established.
 *
 * Scope / known limitations (documented rather than silently assumed away):
 *  - No retransmission timers and no out-of-order handling. Segments that
 *    arrive with an unexpected sequence number are dropped. This works
 *    fine on typical Wi-Fi/mobile links but is not a spec-complete TCP.
 *  - No TCP options (no MSS negotiation, no window scaling, no SACK).
 *  - Sequence/ack numbers are tracked as plain Longs masked to 32 bits;
 *    there's no wraparound-safe modular comparison, so an individual
 *    connection that runs long enough to wrap 2^32 bytes will misbehave.
 *    Fine for normal request/response HTTP-style traffic.
 *  - TLS MITM (see TlsMitmHandler) is best-effort: normal TLS 1.2/1.3,
 *    no client-cert auth, no renegotiation.
 */
class TcpConnection(
    private val vpnService: VpnService,
    private val tunOut: OutputStream,
    val clientAddr: InetAddress,
    val clientPort: Int,
    val serverAddr: InetAddress,
    val serverPort: Int,
    private val packageName: String,
    private val httpInspectionEnabled: Boolean,
    private val mitmEnabled: Boolean,
    private val caManager: CaManager?,
    private val decryptKey: ByteArray?,
    private val onHttpExchange: ((HttpExchangeEntity) -> Unit)?,
    private val onClosed: () -> Unit
) {
    @Volatile var state = TcpState.SYN_RECEIVED
        private set

    private var socket: Socket? = null
    private var mode = Mode.UNDECIDED
    private var httpTap: HttpTap? = null
    private var mitm: TlsMitmHandler? = null

    // Sequence space, as plain increasing counters masked to 32 bits on the wire.
    private var clientIsn = 0L
    private val bytesFromClient = AtomicLong(0)   // how many payload bytes we've accepted from the client
    private val ourIsn = Random.nextLong(0, MASK32)
    private val bytesToClient = AtomicLong(0)     // how many payload bytes we've sent to the client

    @Volatile private var clientWindow = 65535
    @Volatile private var clientFinSeq: Long? = null
    private val weSentFin = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)

    private fun clientNextSeq() = (clientIsn + 1 + bytesFromClient.get()) and MASK32
    private fun ourNextSeq() = (ourIsn + bytesToClient.get()) and MASK32

    /** Call when a SYN packet opens this connection. Connects the real socket in the background. */
    fun open(seg: TcpSegment) {
        clientIsn = seg.seq
        Thread({
            try {
                val s = Socket()
                vpnService.protect(s) // mandatory: avoid routing this socket's own traffic back into the TUN
                s.connect(InetSocketAddress(serverAddr, serverPort), 8000)
                socket = s
                sendControl(flags = TcpFlags.SYN or TcpFlags.ACK, bumpOurSeq = true)
                // NOTE: we deliberately do NOT start reading from `s` here. Whether we
                // relay it raw (PLAIN) or hand it off wrapped in TLS (MITM) is decided
                // from the first client payload bytes, in handleClientPayload().
            } catch (e: Exception) {
                Log.w(TAG, "connect failed to $serverAddr:$serverPort", e)
                sendControl(flags = TcpFlags.RST)
                close()
            }
        }, "khandroid-tcp-connect").start()
    }

    /** Call for every subsequent packet on this connection (post-SYN). */
    fun onSegment(seg: TcpSegment, buf: ByteArray) {
        if (seg.has(TcpFlags.RST)) {
            close()
            return
        }

        if (seg.has(TcpFlags.ACK) && state == TcpState.SYN_RECEIVED) {
            state = TcpState.ESTABLISHED
        }

        clientWindow = seg.window

        if (seg.payloadLen > 0) {
            if (seg.seq == clientNextSeq()) {
                handleClientPayload(buf, seg.payloadOffsetInBuf, seg.payloadLen)
                bytesFromClient.addAndGet(seg.payloadLen.toLong())
            } else {
                Log.d(TAG, "out-of-order/unexpected seq from client, dropping segment")
            }
            sendControl(flags = TcpFlags.ACK) // ack whatever we accepted (or re-ack the expected seq)
        }

        if (seg.has(TcpFlags.FIN)) {
            if (clientFinSeq == null) {
                clientFinSeq = seg.seq + seg.payloadLen
                bytesFromClient.addAndGet(1) // FIN consumes one sequence number
                if (mode == Mode.MITM) {
                    mitm?.onConnectionClosed()
                } else {
                    runCatching { socket?.shutdownOutput() }
                }
                sendControl(flags = TcpFlags.ACK)
                maybeCloseIfBothSidesFinished()
            }
        }

        if (seg.has(TcpFlags.ACK) && weSentFin.get()) {
            maybeCloseIfBothSidesFinished()
        }
    }

    /**
     * First call decides PLAIN vs MITM for the whole connection, based on
     * whether the first byte looks like a TLS handshake record (0x16) and
     * whether MITM is enabled. Every call after that just feeds bytes to
     * whichever path was chosen.
     */
    private fun handleClientPayload(buf: ByteArray, offset: Int, len: Int) {
        val s = socket ?: return

        if (mode == Mode.UNDECIDED) {
            val looksLikeTls = len > 0 && (buf[offset].toInt() and 0xFF) == 0x16
            mode = if (mitmEnabled && looksLikeTls && caManager != null) Mode.MITM else Mode.PLAIN

            if (httpInspectionEnabled) {
                httpTap = HttpTap(
                    packageName = packageName,
                    host = serverAddr.hostAddress ?: "?",
                    port = serverPort,
                    isTls = (mode == Mode.MITM),
                    decryptKey = decryptKey,
                    onExchange = { onHttpExchange?.invoke(it) }
                )
            }

            if (mode == Mode.PLAIN) {
                startReadPump(s)
            } else {
                mitm = TlsMitmHandler(
                    caManager = caManager!!,
                    serverAddr = serverAddr,
                    serverPort = serverPort,
                    plainSocket = s,
                    httpTap = httpTap,
                    sendToClient = { bytes -> sendData(bytes, bytes.size) },
                    onFatalError = { close() }
                )
            }
        }

        when (mode) {
            Mode.MITM -> mitm?.handleClientBytes(buf, offset, len)
            else -> {
                httpTap?.onClientBytes(buf, offset, len)
                runCatching { s.getOutputStream().write(buf, offset, len) }
                    .onFailure { Log.w(TAG, "write to real socket failed", it) }
            }
        }
    }

    /** PLAIN mode only: pumps bytes read from the real socket back to the client, tapping HTTP along the way. */
    private fun startReadPump(s: Socket) {
        Thread({
            val buf = ByteArray(CHUNK_SIZE)
            try {
                val input = s.getInputStream()
                while (!closed.get()) {
                    val n = input.read(buf)
                    if (n < 0) break // real server closed its side
                    httpTap?.onServerBytes(buf, 0, n)
                    waitForWindow(n)
                    sendData(buf, n)
                }
            } catch (e: Exception) {
                if (!closed.get()) Log.d(TAG, "read pump ended: ${e.message}")
            } finally {
                httpTap?.onConnectionClosed()
                sendControl(flags = TcpFlags.FIN or TcpFlags.ACK, bumpOurSeq = true)
                weSentFin.set(true)
                maybeCloseIfBothSidesFinished()
            }
        }, "khandroid-tcp-readpump").start()
    }

    /**
     * Very simple flow control: wait for the client's last-advertised TCP
     * window to be able to fit this chunk, rather than tracking exact
     * bytes-in-flight against acks. Good enough to avoid flooding a slow
     * receiver; gives up after 5s so a stalled client can't hang the pump.
     */
    private fun waitForWindow(chunkLen: Int) {
        var waited = 0
        while (!closed.get() && clientWindow in 1 until chunkLen) {
            Thread.sleep(10)
            waited += 10
            if (waited > 5000) break // send anyway rather than hang forever
        }
    }

    /** Sends [len] bytes of [buf] to the client as one or more TCP data segments (chunked to the MTU). */
    private fun sendData(buf: ByteArray, len: Int) {
        var offset = 0
        while (offset < len) {
            val chunk = minOf(CHUNK_SIZE, len - offset)
            val pkt = TcpPacketBuilder.build(
                srcAddr = serverAddr, srcPort = serverPort,
                dstAddr = clientAddr, dstPort = clientPort,
                seq = ourNextSeq(), ack = clientNextSeq(),
                flags = TcpFlags.PSH or TcpFlags.ACK,
                window = OUR_RECV_WINDOW,
                payload = buf, payloadOffset = offset, payloadLen = chunk
            )
            runCatching { tunOut.write(pkt) }.onFailure { Log.w(TAG, "tun write failed", it) }
            bytesToClient.addAndGet(chunk.toLong())
            offset += chunk
        }
    }

    private fun sendControl(flags: Int, bumpOurSeq: Boolean = false) {
        val pkt = TcpPacketBuilder.build(
            srcAddr = serverAddr, srcPort = serverPort,
            dstAddr = clientAddr, dstPort = clientPort,
            seq = ourNextSeq(), ack = clientNextSeq(),
            flags = flags, window = OUR_RECV_WINDOW
        )
        runCatching { tunOut.write(pkt) }.onFailure { Log.w(TAG, "tun write failed", it) }
        if (bumpOurSeq) bytesToClient.addAndGet(1) // SYN/FIN each consume one sequence number
    }

    private fun maybeCloseIfBothSidesFinished() {
        if (clientFinSeq != null && weSentFin.get()) close()
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            state = TcpState.CLOSED
            httpTap?.onConnectionClosed()
            runCatching { socket?.close() }
            onClosed()
        }
    }
}
