package com.example.fortify

import android.content.Context
import androidx.room.*

// 1. THE TABLE
@Entity(tableName = "scanned_messages")
data class MessageEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0, // Auto-incrementing ID
    val jobId: String,
    val sender: String,
    val messageBody: String,
    val result: String,
    val timestamp: Long = System.currentTimeMillis() // Saves when it was scanned
)

// 2. THE SQL COMMANDS
@Dao
interface MessageDao {
    // Fetches all messages, newest at the top
    @Query("SELECT * FROM scanned_messages ORDER BY timestamp DESC")
    suspend fun getAllMessages(): List<MessageEntity>

    // Inserts a new message
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertMessage(message: MessageEntity)

    @Query("DELETE FROM scanned_messages WHERE jobId IN (:jobIds)")
    suspend fun deleteMessagesByJobIds(jobIds: List<String>)
}

// 3. THE DATABASE MANAGER
@Database(entities = [MessageEntity::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun messageDao(): MessageDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "fortify_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}