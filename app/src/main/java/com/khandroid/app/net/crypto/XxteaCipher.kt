package com.khandroid.app.net.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * XXTEA (Corrected Block TEA). Operates on 32-bit words; data length must
 * be a multiple of 4 bytes and at least 8 bytes (2 words). Requires a
 * 128-bit (16-byte) key, supplied by the user.
 */
class XxteaCipher : PayloadDecryptor {
    override val name = "XXTEA"
    private val delta = -0x61c88647 // golden ratio constant, standard for (X)TEA

    override fun decrypt(data: ByteArray, key: ByteArray?): ByteArray? {
        if (key == null || key.size != 16) return null
        if (data.size < 8 || data.size % 4 != 0) return null

        val v = bytesToIntArray(data)
        val k = bytesToIntArray(key)
        val n = v.size
        val rounds = 6 + 52 / n
        var sum = delta * rounds

        repeat(rounds) {
            val e = (sum ushr 2) and 3
            for (p in n - 1 downTo 0) {
                val z = v[if (p == 0) n - 1 else p - 1]
                val y = v[(p + 1) % n]
                v[p] -= (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor
                        ((sum xor y) + (k[(p and 3) xor e] xor z))
            }
            sum -= delta
        }
        return intArrayToBytes(v)
    }

    private fun bytesToIntArray(b: ByteArray): IntArray {
        val buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
        return IntArray(b.size / 4) { buf.int }
    }

    private fun intArrayToBytes(arr: IntArray): ByteArray {
        val buf = ByteBuffer.allocate(arr.size * 4).order(ByteOrder.LITTLE_ENDIAN)
        arr.forEach { buf.putInt(it) }
        return buf.array()
    }
}
