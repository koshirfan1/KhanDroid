package com.khandroid.app.net.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class FoxucPacket(
    val packetSize: Int,
    val mainCmd: Int,
    val subCmd: Int,
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as FoxucPacket
        return packetSize == other.packetSize &&
                mainCmd == other.mainCmd &&
                subCmd == other.subCmd &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = packetSize
        result = 31 * result + mainCmd
        result = 31 * result + subCmd
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

/**
 * Parser for the Foxuc Gaming Protocol used in DTC game apps.
 * Typically uses an 8-byte header structure:
 * - 2 bytes: Packet Size (wPacketSize)
 * - 2 bytes: Main Command (wMainCmd)
 * - 2 bytes: Sub Command (wSubCmd)
 * - 2 bytes: Reserved / Flags
 */
object FoxucProtocolParser {
    fun parsePackets(data: ByteArray): List<FoxucPacket> {
        val packets = mutableListOf<FoxucPacket>()
        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        while (buf.remaining() >= 8) {
            val size = buf.short.toInt() and 0xFFFF
            val mainCmd = buf.short.toInt() and 0xFFFF
            val subCmd = buf.short.toInt() and 0xFFFF
            val _flags = buf.short.toInt() and 0xFFFF

            if (size < 8 || size > buf.remaining() + 8) {
                break
            }

            val payloadSize = size - 8
            val payload = ByteArray(payloadSize)
            if (payloadSize > 0) {
                buf.get(payload)
            }
            packets.add(FoxucPacket(size, mainCmd, subCmd, payload))
        }
        return packets
    }
}

/**
 * A composite PayloadDecryptor for Foxuc Gaming Protocol streams.
 * Applies underlying decryption (Substitution/XOR/XXTEA) followed by
 * Foxuc 8-byte header parsing (wMainCmd, wSubCmd).
 */
class FoxucDecryptor(private val underlying: PayloadDecryptor) : PayloadDecryptor {
    override val name = "Foxuc-Protocol (${underlying.name})"

    override fun decrypt(data: ByteArray, key: ByteArray?): ByteArray? {
        val decryptedBytes = underlying.decrypt(data, key) ?: data
        val packets = FoxucProtocolParser.parsePackets(decryptedBytes)
        if (packets.isEmpty()) return null

        val sb = StringBuilder()
        for ((i, pkt) in packets.withIndex()) {
            sb.append("--- Foxuc Packet #${i + 1} [MainCmd: 0x${pkt.mainCmd.toString(16)}, SubCmd: 0x${pkt.subCmd.toString(16)}, Size: ${pkt.packetSize}] ---\n")
            val text = String(pkt.payload, Charsets.UTF_8)
            val isPrintable = text.all { it.isDefined() && !it.isISOControl() || it == '\n' || it == '\r' || it == '\t' }
            if (isPrintable && text.isNotBlank()) {
                sb.append(text)
            } else {
                sb.append("[Binary payload: ${pkt.payload.size} bytes]")
            }
            sb.append("\n\n")
        }
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}
