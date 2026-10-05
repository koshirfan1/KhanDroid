package com.khandroid.app.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * One logged HTTP(S) request/response pair. Headers are stored as a
 * simple "Name: Value" block (one per line) rather than pulling in a JSON
 * library, since this is just for display/export, not re-parsing.
 */
@Entity(tableName = "http_exchanges")
data class HttpExchangeEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val time: Long,
    val packageName: String,
    val isTls: Boolean,
    val host: String,
    val port: Int,
    val method: String,
    val path: String,
    val reqHeadersBlock: String,
    val reqBodyPreview: String?,     // truncated, human-readable preview only
    val statusCode: Int?,
    val resHeadersBlock: String,
    val resBodyPreview: String?,
    val durationMs: Long,
    val decryptedWith: String?,      // name of the custom cipher that successfully decoded the body, if any
    val error: String? = null
)
