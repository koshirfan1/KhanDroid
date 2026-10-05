package com.khandroid.app.net

import android.net.VpnService
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.net.tls.CaManager
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap

/** Keys a TCP connection by the client's side of the 4-tuple plus the server side (client IP is always fixed). */
private data class TcpKey(val clientPort: Int, val serverAddr: String, val serverPort: Int)

/**
 * Terminates TCP at the TUN boundary: every distinct (client port, server
 * addr, server port) becomes a [TcpConnection] backed by a real socket.
 * Also threads through the HTTP inspection / MITM / decryption settings
 * so each connection can decide for itself whether to tap or MITM.
 */
class TcpForwarder(
    private val vpnService: VpnService,
    private val packageName: String,
    private val httpInspectionEnabled: Boolean,
    private val mitmEnabled: Boolean,
    private val caManager: CaManager?,
    private val decryptKey: ByteArray?,
    private val onHttpExchange: ((HttpExchangeEntity) -> Unit)?
) {
    private val connections = ConcurrentHashMap<TcpKey, TcpConnection>()

    fun handle(buf: ByteArray, len: Int, ipPkt: Ipv4Packet, tunOut: OutputStream) {
        val seg = TcpSegment.parse(buf, ipPkt.headerLen, len) ?: return
        val key = TcpKey(seg.srcPort, ipPkt.dstAddr.hostAddress ?: return, seg.dstPort)

        if (seg.has(TcpFlags.SYN) && !seg.has(TcpFlags.ACK)) {
            // Fresh connection attempt. Replace any stale entry for this 4-tuple.
            connections.remove(key)?.close()
            val conn = TcpConnection(
                vpnService = vpnService,
                tunOut = tunOut,
                clientAddr = ipPkt.srcAddr,
                clientPort = seg.srcPort,
                serverAddr = ipPkt.dstAddr,
                serverPort = seg.dstPort,
                packageName = packageName,
                httpInspectionEnabled = httpInspectionEnabled,
                mitmEnabled = mitmEnabled,
                caManager = caManager,
                decryptKey = decryptKey,
                onHttpExchange = onHttpExchange,
                onClosed = { connections.remove(key) }
            )
            connections[key] = conn
            conn.open(seg)
            return
        }

        connections[key]?.onSegment(seg, buf)
        // No matching connection (e.g. stray ACK/RST after we've already cleaned up): ignore.
    }

    fun stop() {
        connections.values.forEach { it.close() }
        connections.clear()
    }
}
