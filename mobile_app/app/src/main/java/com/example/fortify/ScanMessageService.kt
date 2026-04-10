package com.example.fortify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import okhttp3.*
import org.json.JSONObject
import java.io.IOException
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.*

class ScanMessageService : Service() {

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var client: OkHttpClient
    private val handler = Handler(Looper.getMainLooper())

    // SupervisorJob ensures that one failure doesn't cancel the whole scope
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        client = OkHttpClient()
        sharedPreferences = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val message = intent?.getStringExtra("SMS_MESSAGE")
        val senderNumber = intent?.getStringExtra("SENDER_NUMBER")

        if (message != null && senderNumber != null) {
            scanMessage(message, senderNumber)
        } else {
            stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun scanMessage(message: String, senderNumber: String) {
        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        if (serverUrl.isNullOrEmpty() || jwtToken.isNullOrEmpty()) {
            Log.e("ScanService", "Server URL or Token not set.")
            stopSelf()
            return
        }

        val jsonObject = JSONObject().apply { put("message", message) }
        val requestBody = jsonObject.toString().toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("$serverUrl/scanMessage")
            .header("Authorization", "Bearer $jwtToken")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                Log.e("ScanService", "Initial scan network failure: ${e.message}")
                stopSelf()
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    val responseBody = it.body?.string()
                    if (it.isSuccessful && responseBody != null) {
                        try {
                            val jobId = JSONObject(responseBody).getString("jobID")
                            startPolling(jobId, senderNumber, message)
                        } catch (e: Exception) {
                            Log.e("ScanService", "Failed to parse job ID.")
                            stopSelf()
                        }
                    } else {
                        stopSelf()
                    }
                }
            }
        })
    }

    private fun startPolling(jobId: String, senderNumber: String, message: String) {
        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        lateinit var pollingRunnable: Runnable
        pollingRunnable = Runnable {
            val jsonObject = JSONObject().apply { put("jobID", jobId) }
            val requestBody = jsonObject.toString().toRequestBody("application/json; charset=utf-8".toMediaType())

            val request = Request.Builder()
                .url("$serverUrl/scanStatus")
                .header("Authorization", "Bearer $jwtToken")
                .post(requestBody)
                .build()

            client.newCall(request).enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    handler.postDelayed(pollingRunnable, 5000)
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        val responseBody = it.body?.string()
                        if (it.isSuccessful && responseBody != null) {
                            try {
                                val json = JSONObject(responseBody)
                                val status = json.optInt("status", 0)

                                when (status) {
                                    1 -> fetchScanDetails(jobId, senderNumber, message)
                                    -1 -> stopSelf()
                                    else -> handler.postDelayed(pollingRunnable, 5000)
                                }
                            } catch (e: Exception) {
                                handler.postDelayed(pollingRunnable, 5000)
                            }
                        } else {
                            if (it.code == 404) stopSelf() else handler.postDelayed(pollingRunnable, 5000)
                        }
                    }
                }
            })
        }
        handler.post(pollingRunnable)
    }

    private fun fetchScanDetails(jobId: String, senderNumber: String, message: String) {
        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        val jsonObject = JSONObject().apply { put("jobID", jobId) }
        val requestBody = jsonObject.toString().toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("$serverUrl/getScanDetails")
            .header("Authorization", "Bearer $jwtToken")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { stopSelf() }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    val responseBody = it.body?.string()
                    if (it.isSuccessful && responseBody != null) {
                        try {
                            val json = JSONObject(responseBody)
                            val finalVerdict = json.getString("detection") // "Phishing", "Suspicious", or "Safe"

                            // Use GlobalScope or stay within serviceScope but handle stopSelf carefully
                            serviceScope.launch {
                                try {
                                    val db = AppDatabase.getDatabase(applicationContext)
                                    db.messageDao().insertMessage(
                                        MessageEntity(
                                            jobId = jobId,
                                            sender = senderNumber,
                                            messageBody = message,
                                            result = finalVerdict
                                        )
                                    )
                                    Log.d("ScanService", "Success: Saved $finalVerdict to DB")

                                    // Broadcast update to the UI feed
                                    val broadcastIntent = Intent("com.fortify.LIVE_UPDATE").apply {
                                        putExtra("JOB_ID", jobId)
                                        putExtra("SENDER", senderNumber)
                                        putExtra("BODY", message)
                                        putExtra("RESULT", finalVerdict)
                                    }
                                    sendBroadcast(broadcastIntent)

                                    // Notification for non-safe messages
                                    if (!finalVerdict.equals("Safe", ignoreCase = true)) {
                                        handler.post { showPhishingNotification(senderNumber, finalVerdict) }
                                    }
                                } catch (e: Exception) {
                                    Log.e("ScanService", "Database Error", e)
                                } finally {
                                    // CRITICAL: Only stop service AFTER the coroutine work is done
                                    withContext(Dispatchers.Main) { stopSelf() }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("ScanService", "Result parsing error.")
                            stopSelf()
                        }
                    } else {
                        stopSelf()
                    }
                }
            }
        })
    }

    private fun showPhishingNotification(senderNumber: String, verdict: String) {
        val channelId = "PHISHING_ALERT_CHANNEL"
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "Phishing Alerts"
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(channelId, name, importance)
            notificationManager.createNotificationChannel(channel)
        }

        val title = if (verdict.equals("Phishing", ignoreCase = true)) "PHISHING ALERT!" else "SUSPICIOUS MESSAGE!"
        val text = "Received from: $senderNumber"

        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel() // Cleanup all pending coroutines
    }

    override fun onBind(intent: Intent?): IBinder? = null
}