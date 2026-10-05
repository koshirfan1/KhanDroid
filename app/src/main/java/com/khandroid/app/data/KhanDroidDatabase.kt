package com.khandroid.app.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [HttpExchangeEntity::class], version = 1, exportSchema = false)
abstract class KhanDroidDatabase : RoomDatabase() {
    abstract fun httpExchangeDao(): HttpExchangeDao

    companion object {
        @Volatile private var instance: KhanDroidDatabase? = null

        fun get(context: Context): KhanDroidDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    KhanDroidDatabase::class.java,
                    "khandroid.db"
                ).build().also { instance = it }
            }
    }
}
