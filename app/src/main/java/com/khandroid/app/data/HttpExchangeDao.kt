package com.khandroid.app.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface HttpExchangeDao {

    @Insert
    suspend fun insert(exchange: HttpExchangeEntity): Long

    @Query("SELECT * FROM http_exchanges ORDER BY time DESC")
    fun observeAll(): Flow<List<HttpExchangeEntity>>

    @Query("""
        SELECT * FROM http_exchanges
        WHERE (:host IS NULL OR host LIKE '%' || :host || '%')
          AND (:method IS NULL OR method = :method)
          AND (:status IS NULL OR statusCode = :status)
        ORDER BY time DESC
    """)
    fun observeFiltered(host: String?, method: String?, status: Int?): Flow<List<HttpExchangeEntity>>

    @Query("DELETE FROM http_exchanges")
    suspend fun clearAll()
}
