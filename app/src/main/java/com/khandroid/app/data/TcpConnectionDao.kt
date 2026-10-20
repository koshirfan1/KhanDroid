package com.khandroid.app.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface TcpConnectionDao {
    @Query("SELECT * FROM tcp_connections ORDER BY time DESC")
    fun observeAll(): Flow<List<TcpConnectionEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: TcpConnectionEntity)

    @Query("DELETE FROM tcp_connections")
    suspend fun clearAll()
}
