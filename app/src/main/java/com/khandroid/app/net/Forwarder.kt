package com.khandroid.app.net

import android.net.VpnService
import android.util.Log
import com.khandroid.app.data.HttpExchangeEntity
import com.khandroid.app.net.tls.CaManager
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

private const val TAG = "KhanDroid/Forwarder"

/**
 * Forwards packets read from the TUN interface to the real network, and
 * writes replies back into the TUN interface so the device's internet
 * connection keeps working while KhanDroid is capturing.
 *
 * UDP: a simple NAT table (one real DatagramSocket per client 4-tuple).
 *
 * TCP: terminated at the TUN boundary and relayed through a real, protected
 * socket per connection (see [TcpForwarder] / [TcpConnection]). This is a
 * best-effort userspace implementation (no retransmission timers, no
 * options, no wraparound-safe sequence math) rather than a spec-complete
 * TCP/IP stack — see the class docs on [TcpConnection] for the exact scope.
 * It's enough for normal HTTP(S)-style request/response traffic on a
 * typical Wi-Fi/mobile link, and it's the same redirect point the
 * HTTP/HTTPS inspection feature (guide Section 6) builds on.
 */
class Forwarder(
    private val vpnService: VpnService,
    packageName: String,
    httpInspectionEnabled: Boolean,
    mitmEnabled: Boolean,
    caManager: CaManager?,
    decryptKey: ByteArray?,
    onHttpExchange: ((HttpExchangeEntity) -> Unit)?
) {

    private data class UdpKey(val srcPort: Int, val dstAddr: String, val dstPort: Int)

    private val udpSockets = ConcurrentHashMap<UdpKey, DatagramSocket>()
    private val tcpForwarder = TcpForwarder(
        vpnService, packageName, httpInspectionEnabled, mitmEnabled, caManager, decryptKey, onHttpExchange
    )
    private val executor = Executors.newCachedThreadPool()
    @Volatile private var running = true

    fun handleOutgoing(buf: ByteArray, len: Int, tunOut: FileOutputStream) {
        val pkt = Ipv4Packet.parse(buf, len) ?: return

        if (pkt.protocol == 6) {
            tcpForwarder.handle(buf, len, pkt, tunOut)
            return
        }
        if (pkt.protocol != 17) return // nothing else forwarded yet (e.g. ICMP)

        val key = UdpKey(pkt.srcPort, pkt.dstAddr.hostAddress ?: return, pkt.dstPort)
        val socket = udpSockets.getOrPut(key) {
            DatagramSocket().also { s ->
                vpnService.protect(s) // mandatory: avoid routing our own reply traffic back into the TUN
                startReplyPump(s, pkt, tunOut)
            }
        }

        val payloadOffset = pkt.headerLen + 8 // UDP header is 8 bytes
        val payloadLen = len - payloadOffset
        if (payloadLen <= 0) return

        runCatching {
            socket.send(DatagramPacket(buf, payloadOffset, payloadLen, pkt.dstAddr, pkt.dstPort))
        }.onFailure { Log.w(TAG, "udp send failed", it) }
    }

    /** Reads replies from [socket] and re-wraps them as IPv4/UDP packets back into the TUN. */
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
