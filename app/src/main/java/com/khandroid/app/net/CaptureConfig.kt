package com.khandroid.app.net

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * User-chosen capture settings: which app, which ports, and where to
 * send the matching packets over UDP.
 */
@Parcelize
data class CaptureConfig(
    val targetPackage: String,              // e.g. "com.whatsapp"
    val targetPorts: Set<Int>,              // e.g. setOf(443, 5222). Empty set = all ports.
    val protocols: Set<Int> = setOf(6, 17), // 6 = TCP, 17 = UDP
    val udpExportEnabled: Boolean = true,   // UDP export is mandatory in KhanDroid by default
    val udpHost: String,                    // receiver IP, e.g. "192.168.1.10"
    val udpPort: Int = 5555,

    // --- HTTP/HTTPS inspection (guide Section 6) ---
    val httpInspectionEnabled: Boolean = true,  // tap plain HTTP on any TCP connection
    val mitmEnabled: Boolean = false,           // opt-in: requires the KhanDroid CA to be installed on-device

    // --- Custom payload decryption (guide Section 7, generic ciphers only) ---
    val decryptCipher: String? = null,          // "XOR" | "XXTEA" | "Substitution-256" | null = off
    val decryptKeyHex: String? = null,          // hex key for XOR/XXTEA
    val substitutionTableHex: String? = null    // 512 hex chars (256 bytes) for Substitution-256
) : Parcelable {
    fun isValid(): Boolean =
        targetPackage.isNotBlank() && udpHost.isNotBlank() && udpPort in 1..65535
}
