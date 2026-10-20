package com.khandroid.app.service

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.khandroid.app.R
import com.khandroid.app.data.KhanDroidDatabase
import com.khandroid.app.net.CaptureConfig
import com.khandroid.app.net.Forwarder
import com.khandroid.app.net.PacketFilter
import com.khandroid.app.net.UdpExporter
import com.khandroid.app.net.crypto.DecryptorRegistry
import com.khandroid.app.net.crypto.FoxucDecryptor
import com.khandroid.app.net.crypto.SubstitutionCipher
import com.khandroid.app.net.crypto.XorCipher
import com.khandroid.app.net.crypto.XxteaCipher
import com.khandroid.app.net.tls.CaManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

private const val TAG = "KhanDroid/Service"
private const val CHANNEL_ID = "khandroid_capture"
private const val NOTIF_ID = 1
private const val MTU = 1400

class KhanDroidService : VpnService() {

    companion object {
        const val EXTRA_CONFIG = "extra_config"
        const val ACTION_STOP = "com.khandroid.app.STOP"

        @Volatile var isRunning = false
            internal set
        @Volatile var lastSent = 0L
            internal set
        @Volatile var lastDropped = 0L
            internal set
    }

    private var tun: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var captureThread: Thread? = null
    private var exporter: UdpExporter? = null
    private var forwarder: Forwarder? = null
    private var caManager: CaManager? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopCapture()
            return START_NOT_STICKY
        }

        val cfg = if (Build.VERSION.SDK_INT >= 33)
            intent?.getParcelableExtra(EXTRA_CONFIG, CaptureConfig::class.java)
        else
            @Suppress("DEPRECATION") intent?.getParcelableExtra(EXTRA_CONFIG)

        if (cfg == null || !cfg.isValid()) {
            Log.e(TAG, "missing/invalid CaptureConfig, stopping")
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIF_ID, buildNotification(cfg))
        startCapture(cfg)
        return START_STICKY
    }

    private fun startCapture(cfg: CaptureConfig) {
        if (running.get()) return

        val builder = Builder()
            .setSession("KhanDroid")
            .setMtu(MTU)
            .addAddress("10.215.173.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")

        runCatching { builder.addAllowedApplication(cfg.targetPackage) }
            .onFailure { Log.e(TAG, "target package not found: ${cfg.targetPackage}", it) }

        tun = builder.establish()
        if (tun == null) {
            Log.e(TAG, "VPN establish() returned null (permission not granted?)")
            stopSelf()
            return
        }

        setUpDecryptors(cfg)

        val ca = if (cfg.mitmEnabled) CaManager(this).also { caManager = it } else null
        val decryptKeyBytes = cfg.decryptKeyHex?.let { hexToBytes(it) }
        val db = KhanDroidDatabase.get(this)
        val dao = db.httpExchangeDao()
        val tcpDao = db.tcpConnectionDao()

        val filter = PacketFilter(cfg)
        val udpExporter = UdpExporter(this, cfg.udpHost, cfg.udpPort).also { it.start() }
        val fwd = Forwarder(
            vpnService = this,
            packageName = cfg.targetPackage,
            httpInspectionEnabled = cfg.httpInspectionEnabled,
            mitmEnabled = cfg.mitmEnabled,
            caManager = ca,
            decryptKey = decryptKeyBytes,
            onHttpExchange = { entity -> serviceScope.launch { dao.insert(entity) } },
            onConnectionEvent = { entity -> serviceScope.launch { tcpDao.insert(entity) } }
        )
        exporter = udpExporter
        forwarder = fwd

        running.set(true)
        isRunning = true

        captureThread = Thread({ captureLoop(filter, udpExporter, fwd) }, "khandroid-capture")
            .also { it.start() }

        Log.i(TAG, "capture started: app=${cfg.targetPackage} ports=${cfg.targetPorts} " +
                "export=${cfg.udpHost}:${cfg.udpPort}")
    }

    /**
     * Registers at most one generic decryptor based on the user's choice
     * in [CaptureConfig] (guide Section 7). Only ever one of the three
     * generic, well-known ciphers here — nothing protocol-specific or
     * third-party-targeted.
     */
    private fun setUpDecryptors(cfg: CaptureConfig) {
        DecryptorRegistry.unregisterAll()
        when (cfg.decryptCipher) {
            "XOR" -> DecryptorRegistry.register(XorCipher())
            "XXTEA" -> DecryptorRegistry.register(XxteaCipher())
            "Substitution-256" -> cfg.substitutionTableHex?.let {
                runCatching { DecryptorRegistry.register(SubstitutionCipher.fromHex(it)) }
                    .onFailure { e -> Log.e(TAG, "invalid substitution table", e) }
            }
            "Foxuc-Substitution" -> cfg.substitutionTableHex?.let {
                runCatching {
                    val sub = SubstitutionCipher.fromHex(it)
                    DecryptorRegistry.register(FoxucDecryptor(sub))
                }.onFailure { e -> Log.e(TAG, "invalid substitution table for Foxuc", e) }
            }
            "Foxuc-XXTEA" -> DecryptorRegistry.register(FoxucDecryptor(XxteaCipher()))
            else -> {} // decryption off
        }
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val clean = hex.replace(Regex("[^0-9a-fA-F]"), "")
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        return ByteArray(clean.length / 2) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun captureLoop(filter: PacketFilter, exp: UdpExporter, fwd: Forwarder) {
        val input = FileInputStream(tun!!.fileDescriptor)
        val output = FileOutputStream(tun!!.fileDescriptor)
        val buffer = ByteArray(32 * 1024)

        while (running.get()) {
            val len = try {
                input.read(buffer)
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "tun read error", e)
                break
            }
            if (len <= 0) continue

            // 1. Always forward (TCP + UDP), regardless of filter, so the
            //    target app's connections keep working.
            fwd.handleOutgoing(buffer, len, output)

            // 2. Export only packets that match the configured app/port filter.
            if (filter.matches(buffer, len)) {
                exp.send(buffer, len)
            }

            lastSent = exp.sentCount.get()
            lastDropped = exp.droppedCount.get()
        }
    }

    private fun stopCapture() {
        running.set(false)
        isRunning = false
        captureThread?.join(1000)
        captureThread = null

        exporter?.stop()
        exporter = null
        forwarder?.stop()
        forwarder = null

        runCatching { tun?.close() }
        tun = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopCapture()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        // User revoked VPN permission from system settings.
        stopCapture()
        super.onRevoke()
    }

    private fun buildNotification(cfg: CaptureConfig): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "KhanDroid Capture", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }

        val stopIntent = Intent(this, KhanDroidService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("KhanDroid capturing")
            .setContentText("${cfg.targetPackage} \u2192 ${cfg.udpHost}:${cfg.udpPort}")
            .setSmallIcon(R.drawable.ic_notification)
            .addAction(0, "Stop", stopPending)
            .setOngoing(true)
            .build()
    }
}
