package com.khandroid.app.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "tcp_connections")
data class TcpConnectionEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val time: Long,
    val packageName: String,
    val remoteHost: String,
    val remotePort: Int,
    val localPort: Int,
    val protocol: String = "TCP",
    val bytesSent: Long,
    val bytesReceived: Long,
    val rawStreamPreview: String,
    val decryptedWith: String? = null
)
