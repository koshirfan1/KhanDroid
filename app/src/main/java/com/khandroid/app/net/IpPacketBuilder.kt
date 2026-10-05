package com.khandroid.app.net

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Builds minimal raw IPv4 packets, used to write UDP replies back into the TUN interface. */
object IpPacketBuilder {

    fun buildUdp(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLen: Int
    ): ByteArray {
        val udpLen = 8 + payloadLen
        val totalLen = 20 + udpLen
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)

        // --- IPv4 header ---
        buf.put(0, (0x45).toByte())           // version=4, IHL=5 (20 bytes, no options)
        buf.put(1, 0)                          // DSCP/ECN
        buf.putShort(2, totalLen.toShort())    // total length
        buf.putShort(4, 0)                     // identification
        buf.putShort(6, 0x4000.toShort())      // flags=DF, fragment offset=0
        buf.put(8, 64)                         // TTL
        buf.put(9, 17)                         // protocol = UDP
        buf.putShort(10, 0)                    // header checksum (filled below)
        buf.put(12, srcAddr.address, 0, 4)
        buf.put(16, dstAddr.address, 0, 4)

        val ipChecksum = checksum(buf.array(), 0, 20)
        buf.putShort(10, ipChecksum.toShort())

        // --- UDP header ---
        buf.putShort(20, srcPort.toShort())
        buf.putShort(22, dstPort.toShort())
        buf.putShort(24, udpLen.toShort())
        buf.putShort(26, 0) // checksum optional for IPv4 UDP; 0 = not computed

        // --- Payload ---
        buf.position(28)
        buf.put(payload, payloadOffset, payloadLen)

        return buf.array()
    }

    /** Standard one's-complement IPv4 header checksum. */
    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }
}
