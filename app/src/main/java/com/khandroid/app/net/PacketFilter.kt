package com.khandroid.app.net

/**
 * Looks at a raw IPv4 packet and decides whether it should be exported,
 * based on the ports configured in [CaptureConfig].
 *
 * NOTE: this filter only gates *export/logging*. Forwarding to the real
 * network must happen for every packet regardless of the filter result,
 * otherwise the target app's other connections break.
 */
class PacketFilter(private val cfg: CaptureConfig) {

    fun matches(buf: ByteArray, len: Int): Boolean {
        if (len < 20) return false

        val versionAndIhl = buf[0].toInt() and 0xFF
        val version = versionAndIhl shr 4
        if (version != 4) return false // IPv6 not handled yet

        val ihl = (versionAndIhl and 0x0F) * 4
        if (len < ihl + 4) return false

        val proto = buf[9].toInt() and 0xFF
        if (cfg.protocols.isNotEmpty() && proto !in cfg.protocols) return false

        // If no ports were specified, match on protocol alone.
        if (cfg.targetPorts.isEmpty()) return true

        // TCP and UDP both start their header with: src port (2B), dst port (2B)
        val srcPort = ((buf[ihl].toInt() and 0xFF) shl 8) or (buf[ihl + 1].toInt() and 0xFF)
        val dstPort = ((buf[ihl + 2].toInt() and 0xFF) shl 8) or (buf[ihl + 3].toInt() and 0xFF)

        return srcPort in cfg.targetPorts || dstPort in cfg.targetPorts
    }
}
