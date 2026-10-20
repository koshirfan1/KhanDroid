package com.khandroid.app.net

import android.net.VpnService
import android.util.Log
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.data.TcpConnectionEntity
import com.khandroid.app.net.tls.CaManager
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

private const val TAG = "KhanDroid/Forwarder"

class Forwarder(
    private val vpnService: VpnService,
    packageName: String,
    httpInspectionEnabled: Boolean,
    mitmEnabled: Boolean,
    caManager: CaManager?,
    decryptKey: ByteArray?,
    onHttpExchange: ((HttpExchangeEntity) -> Unit)?,
    onConnectionEvent: ((TcpConnectionEntity) -> Unit)?
) {

    private data class UdpKey(val srcPort: Int, val dstAddr: String, val dstPort: Int)

    private val udpSockets = ConcurrentHashMap<UdpKey, DatagramSocket>()
    private val tcpForwarder = TcpForwarder(
        vpnService, packageName, httpInspectionEnabled, mitmEnabled, caManager, decryptKey, onHttpExchange, onConnectionEvent
    )
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = true

    fun handleOutgoing(buf: ByteArray, len: Int, tunOut: FileOutputStream) {
        val pkt = Ipv4Packet.parse(buf, len) ?: return

        if (pkt.protocol == 6) {
            tcpForwarder.handle(buf, len, pkt, tunOut)
            return
        }
        if (pkt.protocol != 17) return

        val key = UdpKey(pkt.srcPort, pkt.dstAddr.hostAddress ?: return, pkt.dstPort)
        val socket = udpSockets.getOrPut(key) {
            DatagramSocket().also { s ->
                vpnService.protect(s)
                startReplyPump(s, pkt, tunOut)
            }
        }

        val payloadOffset = pkt.headerLen + 8
        val payloadLen = len - payloadOffset
        if (payloadLen <= 0) return

        runCatching {
            socket.send(DatagramPacket(buf, payloadOffset, payloadLen, pkt.dstAddr, pkt.dstPort))
        }.onFailure { Log.w(TAG, "udp send failed", it) }
    }

    private fun startReplyPump(socket: DatagramSocket, originalReq: Ipv4Packet, tunOut: FileOutputStream) {
        executor.execute {
            val buf = ByteArray(32 * 1024)
            while (running && !socket.isClosed) {
                val dp = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(dp)
                } catch (e: Exception) {
                    break
                }
                val ipPacket = IpPacketBuilder.buildUdp(
                    srcAddr = originalReq.dstAddr,
                    srcPort = originalReq.dstPort,
                    dstAddr = originalReq.srcAddr,
                    dstPort = originalReq.srcPort,
                    payload = dp.data,
                    payloadOffset = dp.offset,
                    payloadLen = dp.length
                )
                runCatching { tunOut.write(ipPacket) }
                    .onFailure { Log.w(TAG, "tun write failed", it) }
            }
        }
    }

    fun stop() {
        running = false
        udpSockets.values.forEach { runCatching { it.close() } }
        udpSockets.clear()
        tcpForwarder.stop()
        executor.shutdownNow()
    }
}
