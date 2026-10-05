package com.khandroid.app.net.crypto

/**
 * Repeating-key XOR. Encrypt and decrypt are the same operation, since
 * XOR is its own inverse.
 *
 * Note: some apps vary the key per-packet (e.g. XOR with a counter or
 * session nonce mixed in). That app-specific variation isn't implemented
 * here — this covers the plain repeating-key case only.
 */
class XorCipher : PayloadDecryptor {
    override val name = "XOR"

    override fun decrypt(data: ByteArray, key: ByteArray?): ByteArray? {
        if (key.isNullOrEmpty()) return null // this cipher requires a key; let other decryptors try instead
        return ByteArray(data.size) { i -> (data[i].toInt() xor key[i % key.size].toInt()).toByte() }
    }
}
