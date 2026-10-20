package com.khandroid.app.net

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** TCP flag bits, as they sit in the low 6 bits of the flags byte. */
object TcpFlags {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    const val URG = 0x20
}

/** Read-only view over a TCP segment that already had its IPv4 header parsed separately. */
data class TcpSegment(
    val srcPort: Int,
    val dstPort: Int,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val window: Int,
    val dataOffsetBytes: Int, // length of the TCP header (including options)
    val payloadOffsetInBuf: Int,
    val payloadLen: Int
) {
    fun has(flag: Int) = (flags and flag) != 0

    companion object {
        /** [buf] starting at [tcpStart] is the TCP header; [totalLen] is the whole IPv4 packet length. */
        fun parse(buf: ByteArray, tcpStart: Int, totalLen: Int): TcpSegment? {
            if (totalLen - tcpStart < 20) return null
            val bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN)

            val srcPort = bb.getShort(tcpStart).toInt() and 0xFFFF
            val dstPort = bb.getShort(tcpStart + 2).toInt() and 0xFFFF
            val seq = bb.getInt(tcpStart + 4).toLong() and 0xFFFFFFFFL
            val ack = bb.getInt(tcpStart + 8).toLong() and 0xFFFFFFFFL
            val dataOffsetByte = buf[tcpStart + 12].toInt() and 0xFF
            val dataOffset = ((dataOffsetByte shr 4) and 0x0F) * 4
            val flags = buf[tcpStart + 13].toInt() and 0x3F
            val window = bb.getShort(tcpStart + 14).toInt() and 0xFFFF

            val payloadOffset = tcpStart + dataOffset
            val payloadLen = totalLen - payloadOffset
            if (payloadLen < 0) return null

            return TcpSegment(srcPort, dstPort, seq, ack, flags, window, dataOffset, payloadOffset, payloadLen)
        }
    }
}

/** Builds raw IPv4/TCP segments for writing replies back into the TUN interface. */
object TcpPacketBuilder {

    /** Builds one IPv4/TCP segment with [payload] (may be empty for pure control segments like ACK/SYN-ACK). */
    fun build(
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray = ByteArray(0),
        payloadOffset: Int = 0,
        payloadLen: Int = payload.size
    ): ByteArray {
        val tcpLen = 20 + payloadLen
        val totalLen = 20 + tcpLen
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
        val array = buf.array()

        // --- IPv4 header ---
        array[0] = 0x45.toByte()
        array[1] = 0.toByte()
        buf.putShort(2, totalLen.toShort())
        buf.putShort(4, 0)
        buf.putShort(6, 0x4000.toShort()) // DF, no fragment offset
        array[8] = 64.toByte()
        array[9] = 6.toByte() // protocol = TCP
        buf.putShort(10, 0) // checksum filled below
        System.arraycopy(srcAddr.address, 0, array, 12, 4)
        System.arraycopy(dstAddr.address, 0, array, 16, 4)
        buf.putShort(10, ipChecksum(array, 0, 20).toShort())

        // --- TCP header ---
        val tcpStart = 20
        buf.putShort(tcpStart, srcPort.toShort())
        buf.putShort(tcpStart + 2, dstPort.toShort())
        buf.putInt(tcpStart + 4, seq.toInt())
        buf.putInt(tcpStart + 8, ack.toInt())
        array[tcpStart + 12] = (5 shl 4).toByte() // data offset = 5 words (20 bytes), no options
        array[tcpStart + 13] = flags.toByte()
        buf.putShort(tcpStart + 14, window.toShort())
        buf.putShort(tcpStart + 16, 0) // checksum, filled below
        buf.putShort(tcpStart + 18, 0) // urgent pointer

        if (payloadLen > 0) {
            buf.position(tcpStart + 20)
            buf.put(payload, payloadOffset, payloadLen)
        }

        val tcpChecksum = tcpChecksum(array, srcAddr, dstAddr, tcpStart, tcpLen)
        buf.putShort(tcpStart + 16, tcpChecksum.toShort())

        return array
    }

    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int = checksum16(data, offset, length, 0)

    /** TCP checksum covers a pseudo-header (src/dst IP, protocol, TCP length) plus the TCP segment itself. */
    private fun tcpChecksum(data: ByteArray, src: InetAddress, dst: InetAddress, tcpStart: Int, tcpLen: Int): Int {
        val pseudo = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
        pseudo.put(src.address, 0, 4)
        pseudo.put(dst.address, 0, 4)
        pseudo.put(0)
        pseudo.put(6) // protocol = TCP
        pseudo.putShort(tcpLen.toShort())

        var sum = sumBytes(pseudo.array(), 0, 12)
        sum += sumBytes(data, tcpStart, tcpLen)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun checksum16(data: ByteArray, offset: Int, length: Int, seed: Int): Int {
        var sum = seed + sumBytes(data, offset, length)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun sumBytes(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        return sum
    }
}
