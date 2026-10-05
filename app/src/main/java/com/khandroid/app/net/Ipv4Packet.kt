package com.khandroid.app.net

import java.net.InetAddress

/** Minimal read-only view over a raw IPv4 packet sitting in a byte array. */
data class Ipv4Packet(
    val protocol: Int,       // 6 = TCP, 17 = UDP
    val srcAddr: InetAddress,
    val dstAddr: InetAddress,
    val srcPort: Int,
    val dstPort: Int,
    val headerLen: Int,
    val totalLen: Int
) {
    companion object {
        /** Returns null if [buf] (first [len] bytes) isn't a parseable IPv4 TCP/UDP packet. */
        fun parse(buf: ByteArray, len: Int): Ipv4Packet? {
            if (len < 20) return null
            val versionAndIhl = buf[0].toInt() and 0xFF
            if ((versionAndIhl shr 4) != 4) return null

            val ihl = (versionAndIhl and 0x0F) * 4
            if (len < ihl + 4) return null

            val proto = buf[9].toInt() and 0xFF
            if (proto != 6 && proto != 17) return null

            val src = InetAddress.getByAddress(buf.copyOfRange(12, 16))
            val dst = InetAddress.getByAddress(buf.copyOfRange(16, 20))

            val srcPort = ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl + 1].toInt() and 0xFF)
            val dstPort = ((buf[ihl + 2].toInt() and 0xFF) shl 8) or (buf[ihl + 3].toInt() and 0xFF)

            val totalLen = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)

            return Ipv4Packet(proto, src, dst, srcPort, dstPort, ihl, totalLen)
        }
    }
}
