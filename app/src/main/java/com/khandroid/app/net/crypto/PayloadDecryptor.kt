package com.khandroid.app.net.crypto

/**
 * A pluggable "try to decrypt this body" step, run on HTTP bodies after
 * HTTP/HTTPS parsing (see Section 7 of the guide). Intended for apps that
 * layer their own lightweight obfuscation/encryption on top of HTTP —
 * generic, well-known algorithms only. Not for reverse-engineering a
 * specific third party's proprietary protocol without authorization.
 */
interface PayloadDecryptor {
    val name: String

    /** Returns the decrypted bytes, or null if this cipher doesn't apply / the key is wrong-shaped. */
    fun decrypt(data: ByteArray, key: ByteArray?): ByteArray?
}

object DecryptorRegistry {
    private val decryptors = mutableListOf<PayloadDecryptor>()

    /** Nothing registered by default — the user opts in per Settings (see Section 7.6 of the guide). */
    fun register(d: PayloadDecryptor) {
        decryptors.add(d)
    }

    fun unregisterAll() {
        decryptors.clear()
    }

    /** Returns (algorithm name, plaintext) from the first decryptor that produces a result, or null. */
    fun tryDecrypt(data: ByteArray, key: ByteArray?): Pair<String, ByteArray>? {
        for (d in decryptors) {
            val result = runCatching { d.decrypt(data, key) }.getOrNull()
            if (result != null) return d.name to result
        }
        return null
    }
}
