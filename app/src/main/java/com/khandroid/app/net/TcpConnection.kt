package com.khandroid.app.net

import android.net.VpnService
import android.util.Log
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.data.TcpConnectionEntity
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
private const val CHUNK_SIZE = 1360
private const val MASK32 = 0xFFFFFFFFL

enum class TcpState { SYN_RECEIVED, ESTABLISHED, CLOSING, CLOSED }
private enum class Mode { UNDECIDED, PLAIN, MITM }

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
    private val onConnectionEvent: ((TcpConnectionEntity) -> Unit)?,
    private val onClosed: () -> Unit
) {
    @Volatile var state = TcpState.SYN_RECEIVED
        private set

    private var socket: Socket? = null
    private var mode = Mode.UNDECIDED
    private var httpTap: HttpTap? = null
    private var mitm: TlsMitmHandler? = null

    private var clientIsn = 0L
    private val bytesFromClient = AtomicLong(0)
    private val ourIsn = Random.nextLong(0, MASK32)
    private val bytesToClient = AtomicLong(0)

    @Volatile private var clientWindow = 65535
    @Volatile private var clientFinSeq: Long? = null
    private val weSentFin = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)

    private val connectionStartTime = System.currentTimeMillis()
    private val accumulatedStream = java.io.ByteArrayOutputStream()

    private fun clientNextSeq() = (clientIsn + 1 + bytesFromClient.get()) and MASK32
    private fun ourNextSeq() = (ourIsn + bytesToClient.get()) and MASK32

    fun open(seg: TcpSegment) {
        clientIsn = seg.seq
        reportEvent()
        Thread({
            try {
                val s = Socket()
                vpnService.protect(s)
                s.connect(InetSocketAddress(serverAddr, serverPort), 8000)
                socket = s
                sendControl(flags = TcpFlags.SYN or TcpFlags.ACK, bumpOurSeq = true)
            } catch (e: Exception) {
                Log.w(TAG, "connect failed to $serverAddr:$serverPort", e)
                sendControl(flags = TcpFlags.RST)
                close()
            }
        }, "khandroid-tcp-connect").start()
    }

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
                synchronized(accumulatedStream) {
                    accumulatedStream.write(buf, seg.payloadOffsetInBuf, minOf(seg.payloadLen, 1024))
                }
                reportEvent()
            } else {
                Log.d(TAG, "out-of-order/unexpected seq from client, dropping segment")
            }
            sendControl(flags = TcpFlags.ACK)
        }

        if (seg.has(TcpFlags.FIN)) {
            if (clientFinSeq == null) {
                clientFinSeq = seg.seq + seg.payloadLen
                bytesFromClient.addAndGet(1)
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

    private fun startReadPump(s: Socket) {
        Thread({
            val buf = ByteArray(CHUNK_SIZE)
            try {
                val input = s.getInputStream()
                while (!closed.get()) {
                    val n = input.read(buf)
                    if (n < 0) break
                    httpTap?.onServerBytes(buf, 0, n)
                    waitForWindow(n)
                    sendData(buf, n)
                    synchronized(accumulatedStream) {
                        accumulatedStream.write(buf, 0, minOf(n, 1024))
                    }
                    reportEvent()
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

    private fun waitForWindow(chunkLen: Int) {
        var waited = 0
        while (!closed.get() && clientWindow in 1 until chunkLen) {
            Thread.sleep(10)
            waited += 10
            if (waited > 5000) break
        }
    }

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
        if (bumpOurSeq) bytesToClient.addAndGet(1)
    }

    private fun reportEvent() {
        val bytes = synchronized(accumulatedStream) { accumulatedStream.toByteArray() }
        val preview = buildString {
            for (b in bytes) {
                val intVal = b.toInt() and 0xFF
                if (intVal in 32..126 || intVal == 10 || intVal == 13) {
                    append(intVal.toChar())
                } else {
                    append('.')
                }
            }
        }
        val entity = TcpConnectionEntity(
            time = connectionStartTime,
            packageName = packageName,
            remoteHost = serverAddr.hostAddress ?: serverAddr.toString(),
            remotePort = serverPort,
            localPort = clientPort,
            protocol = "TCP",
            bytesSent = bytesToClient.get(),
            bytesReceived = bytesFromClient.get(),
            rawStreamPreview = preview.take(800)
        )
        onConnectionEvent?.invoke(entity)
    }

    private fun maybeCloseIfBothSidesFinished() {
        if (clientFinSeq != null && weSentFin.get()) close()
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            state = TcpState.CLOSED
            httpTap?.onConnectionClosed()
            runCatching { socket?.close() }
            reportEvent()
            onClosed()
        }
    }
}
