package com.khandroid.app.net

import android.net.VpnService
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.data.TcpConnectionEntity
import com.khandroid.app.net.tls.CaManager
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap

private data class TcpKey(val clientPort: Int, val serverAddr: String, val serverPort: Int)

class TcpForwarder(
    private val vpnService: VpnService,
    private val packageName: String,
    private val httpInspectionEnabled: Boolean,
    private val mitmEnabled: Boolean,
    private val caManager: CaManager?,
    private val decryptKey: ByteArray?,
    private val onHttpExchange: ((HttpExchangeEntity) -> Unit)?,
    private val onConnectionEvent: ((TcpConnectionEntity) -> Unit)?
) {
    private val connections = ConcurrentHashMap<TcpKey, TcpConnection>()

    fun handle(buf: ByteArray, len: Int, ipPkt: Ipv4Packet, tunOut: OutputStream) {
        val seg = TcpSegment.parse(buf, ipPkt.headerLen, len) ?: return
        val key = TcpKey(seg.srcPort, ipPkt.dstAddr.hostAddress ?: return, seg.dstPort)

        if (seg.has(TcpFlags.SYN) && !seg.has(TcpFlags.ACK)) {
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
                onConnectionEvent = onConnectionEvent,
                onClosed = { connections.remove(key) }
            )
            connections[key] = conn
            conn.open(seg)
            return
        }

        connections[key]?.onSegment(seg, buf)
    }

    fun stop() {
        connections.values.forEach { it.close() }
        connections.clear()
    }
}
