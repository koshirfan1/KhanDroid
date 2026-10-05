package com.khandroid.app.net.crypto

/**
 * Decrypts data that was encrypted with a fixed 256-byte substitution
 * table (every possible byte value maps to some other fixed byte value).
 * The table itself acts as the "key" here; the optional [key] parameter
 * on [decrypt] is unused.
 */
class SubstitutionCipher(private val sBox: ByteArray) : PayloadDecryptor {
    override val name = "Substitution-256"

    init {
        require(sBox.size == 256) { "S-box must be exactly 256 bytes" }
    }

    // Inverse table: inverse[sBox[i]] = i, so decrypt = apply the inverse mapping.
    private val inverse = ByteArray(256).also { inv ->
        for (i in 0..255) inv[sBox[i].toInt() and 0xFF] = i.toByte()
    }

    override fun decrypt(data: ByteArray, key: ByteArray?): ByteArray =
        ByteArray(data.size) { i -> inverse[data[i].toInt() and 0xFF] }

    companion object {
        /** Parses a 256-byte table from a hex string (512 hex chars, e.g. "00 1f 2a ..." or no separators). */
        fun fromHex(hex: String): SubstitutionCipher {
            val clean = hex.replace(Regex("[^0-9a-fA-F]"), "")
            require(clean.length == 512) { "Expected 256 bytes (512 hex chars), got ${clean.length / 2}" }
            val bytes = ByteArray(256) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            return SubstitutionCipher(bytes)
        }
    }
}
