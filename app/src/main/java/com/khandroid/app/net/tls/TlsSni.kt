package com.khandroid.app.net.tls

/**
 * Minimal parser that pulls the SNI (Server Name Indication) hostname out
 * of a raw TLS ClientHello. Assumes the full ClientHello arrived in the
 * bytes handed in (true for virtually all real-world TLS clients, which
 * send it in the first TCP segment). Returns null if anything doesn't
 * look like a well-formed ClientHello with an SNI extension — callers
 * should fall back to the connection's destination IP as the certificate
 * CN in that case.
 */
object TlsSni {

    fun extract(buf: ByteArray, offset: Int, len: Int): String? = runCatching {
        var p = offset
        val end = offset + len

        fun u8() = buf[p].toInt() and 0xFF
        fun u16(): Int { val v = ((buf[p].toInt() and 0xFF) shl 8) or (buf[p + 1].toInt() and 0xFF); return v }

        // TLS record header: type(1) version(2) length(2)
        if (u8() != 0x16) return null // not a handshake record
        p += 5

        // Handshake header: type(1) length(3)
        if ((buf[p].toInt() and 0xFF) != 0x01) return null // not ClientHello
        p += 4

        p += 2  // client_version
        p += 32 // random

        val sessionIdLen = u8(); p += 1 + sessionIdLen
        val cipherSuitesLen = u16(); p += 2 + cipherSuitesLen
        val compressionLen = u8(); p += 1 + compressionLen

        if (p + 2 > end) return null
        val extensionsLen = u16(); p += 2
        val extensionsEnd = minOf(p + extensionsLen, end)

        while (p + 4 <= extensionsEnd) {
            val extType = u16(); p += 2
            val extLen = u16(); p += 2
            if (extType == 0x0000) { // server_name
                var q = p
                q += 2 // server_name_list length
                val nameType = buf[q].toInt() and 0xFF; q += 1
                val nameLen = ((buf[q].toInt() and 0xFF) shl 8) or (buf[q + 1].toInt() and 0xFF); q += 2
                if (nameType == 0 && q + nameLen <= end) {
                    return String(buf, q, nameLen, Charsets.US_ASCII)
                }
                return null
            }
            p += extLen
        }
        null
    }.getOrNull()
}
