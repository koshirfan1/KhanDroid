package com.khandroid.app.net

import android.net.VpnService
import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

private const val TAG = "KhanDroid/UdpExporter"
private const val QUEUE_CAPACITY = 2000

/**
 * Streams captured packets to [host]:[port] over UDP, one packet per
 * datagram, each prefixed with a 16-byte pcap-record header so a receiver
 * can reconstruct a .pcap file (see khandroid_receiver.py).
 *
 * Export is mandatory in KhanDroid: if the exporter can't keep up, packets
 * are dropped rather than blocking the capture loop.
 */
class UdpExporter(
    private val vpnService: VpnService,
    private val host: String,
    private val port: Int
) {
    private val queue = LinkedBlockingQueue<ByteArray>(QUEUE_CAPACITY)
    @Volatile private var running = false
    private var thread: Thread? = null

    val sentCount = AtomicLong(0)
    val droppedCount = AtomicLong(0)

    fun start() {
        if (running) return
        running = true
        thread = Thread({
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                // Mandatory: protect this socket so its own traffic does not
                // re-enter the TUN interface and loop back into capture.
                vpnService.protect(socket)
                val addr = InetAddress.getByName(host)

                while (running) {
                    val data = queue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                    socket.send(DatagramPacket(data, data.size, addr, port))
                    sentCount.incrementAndGet()
                }
            } catch (e: Exception) {
                Log.e(TAG, "export thread error", e)
            } finally {
                socket?.close()
            }
        }, "khandroid-udp-export").also { it.start() }
    }

    /** Queues [len] bytes of [pkt] for export, wrapped with a pcap record header. */
    fun send(pkt: ByteArray, len: Int) {
        val now = System.currentTimeMillis()
        val out = ByteBuffer.allocate(16 + len).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt((now / 1000).toInt())          // ts_sec
        out.putInt(((now % 1000) * 1000).toInt())  // ts_usec
        out.putInt(len)                            // incl_len
        out.putInt(len)                             // orig_len
        out.put(pkt, 0, len)

        if (!queue.offer(out.array())) {
            droppedCount.incrementAndGet()
        }
    }

    fun stop() {
        running = false
        thread?.join(1000)
        thread = null
    }
}
