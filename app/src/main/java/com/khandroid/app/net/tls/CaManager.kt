package com.khandroid.app.net.tls

import android.content.Context
import android.util.Log
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.util.io.pem.PemWriter
import java.io.File
import java.io.FileInputStream
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

private const val TAG = "KhanDroid/CA"
private const val ONE_DAY_MS = 86_400_000L

/**
 * Generates and caches the KhanDroid root CA, plus per-host "leaf"
 * certificates signed by it, for the TLS MITM feature (guide Section 6.4).
 *
 * The CA is generated once and persisted to the app's private storage, so
 * it stays the same across app restarts (the user only has to install it
 * on their device once, not after every run). The CA private key never
 * leaves the device and is never exported — only the CA's public
 * certificate is (see [exportCaCertPem]), which is all the user needs to
 * install for their device to trust KhanDroid's re-signed certificates.
 */
class CaManager(private val context: Context) {

    private val caDir = File(context.filesDir, "ca").apply { mkdirs() }
    private val caCertFile = File(caDir, "ca_cert.der")
    private val caKeyFile = File(caDir, "ca_key.der")

    private lateinit var caCert: X509Certificate
    private lateinit var caKey: PrivateKey

    private val leafCache = ConcurrentHashMap<String, Pair<X509Certificate, PrivateKey>>()

    init {
        Security.addProvider(BouncyCastleProvider())
        loadOrCreateCa()
    }

    private fun loadOrCreateCa() {
        if (caCertFile.exists() && caKeyFile.exists()) {
            runCatching {
                val certFactory = CertificateFactory.getInstance("X.509")
                caCert = FileInputStream(caCertFile).use { certFactory.generateCertificate(it) } as X509Certificate
                val keyBytes = caKeyFile.readBytes()
                val keyFactory = KeyFactory.getInstance("RSA")
                caKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
                Log.i(TAG, "loaded existing CA (expires ${caCert.notAfter})")
                return
            }.onFailure { Log.w(TAG, "failed to load stored CA, regenerating", it) }
        }
        generateAndStoreCa()
    }

    private fun generateAndStoreCa() {
        val kp = newKeyPair()
        val name = X500Name("CN=KhanDroid CA, O=KhanDroid, OU=Generated on-device")
        val now = System.currentTimeMillis()

        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(now),
            Date(now - ONE_DAY_MS), Date(now + 3650L * ONE_DAY_MS),
            name, kp.public
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(kp.private)
        caCert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        caKey = kp.private

        caCertFile.writeBytes(caCert.encoded)
        caKeyFile.writeBytes(caKey.encoded)
        Log.i(TAG, "generated new CA, persisted to ${caDir.absolutePath}")
    }

    /** Gets (generating + caching if needed) a leaf certificate + key for [host], signed by the KhanDroid CA. */
    fun leafFor(host: String): Pair<X509Certificate, PrivateKey> =
        leafCache.getOrPut(host) { generateLeaf(host) }

    fun caCertificate(): X509Certificate = caCert

    private fun generateLeaf(host: String): Pair<X509Certificate, PrivateKey> {
        val kp = newKeyPair()
        val now = System.currentTimeMillis()

        val builder = JcaX509v3CertificateBuilder(
            X500Name(caCert.subjectX500Principal.name),
            BigInteger.valueOf(now + leafCache.size + 1), // unique-ish serial
            Date(now - ONE_DAY_MS), Date(now + 365L * ONE_DAY_MS),
            X500Name("CN=$host"), kp.public
        )
        builder.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(GeneralName(GeneralName.dNSName, host))
        )
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))

        val signer = JcaContentSignerBuilder("SHA256withRSA").build(caKey)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        return cert to kp.private
    }

    private fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    /**
     * Writes the CA's public certificate (PEM) to app storage for sharing
     * via FileProvider, so the user can install it under
     * Settings > Security > Encryption & credentials > Install a certificate.
     * Never writes the private key.
     */
    fun exportCaCertPem(): File {
        val out = File(caDir, "KhanDroid-CA.crt")
        val sw = StringWriter()
        PemWriter(sw).use { it.writeObject(JcaMiscPEMGenerator(caCert)) }
        out.writeText(sw.toString())
        return out
    }
}
