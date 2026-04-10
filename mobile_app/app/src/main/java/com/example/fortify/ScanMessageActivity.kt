package com.example.fortify

import android.content.Context
import android.content.SharedPreferences
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.core.content.ContextCompat
import com.google.android.material.card.MaterialCardView
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class ScanMessageActivity : AppCompatActivity() {

    private lateinit var messageEditText: EditText
    private lateinit var scanMessageButton: Button
    private lateinit var resultCard: MaterialCardView
    private lateinit var resultCardLayout: ConstraintLayout
    private lateinit var pollingProgressBar: ProgressBar
    private lateinit var statusTitleTextView: TextView
    private lateinit var statusTextView: TextView

    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var client: OkHttpClient
    private val handler = Handler(Looper.getMainLooper())
    private var pollingRunnable: Runnable? = null
    private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaTypeOrNull()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_message)

        bindViews()
        client = OkHttpClient()
        sharedPreferences = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)

        scanMessageButton.setOnClickListener {
            val message = messageEditText.text.toString().trim()
            if (message.isNotEmpty()) {
                scanMessage(message)
            } else {
                Toast.makeText(this, "Please enter a message.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun bindViews() {
        messageEditText = findViewById(R.id.messageEditText)
        scanMessageButton = findViewById(R.id.scanMessageButton)
        resultCard = findViewById(R.id.resultCard)
        resultCardLayout = findViewById(R.id.resultCardLayout)
        pollingProgressBar = findViewById(R.id.pollingProgressBar)
        statusTitleTextView = findViewById(R.id.statusTitleTextView)
        statusTextView = findViewById(R.id.statusTextView)
    }

    private fun setUiState(isScanning: Boolean) {
        scanMessageButton.isEnabled = !isScanning
        messageEditText.isEnabled = !isScanning
        resultCard.visibility = if (isScanning) View.VISIBLE else View.GONE
        pollingProgressBar.visibility = if (isScanning) View.VISIBLE else View.GONE
        statusTitleTextView.visibility = if (isScanning) View.VISIBLE else View.GONE
        statusTextView.visibility = if (isScanning) View.VISIBLE else View.GONE

        if (isScanning) {
            statusTextView.text = "Scanning..."
            resultCardLayout.setBackgroundColor(ContextCompat.getColor(this, R.color.card_background))
        }
    }

    private fun scanMessage(message: String) {
        setUiState(true)
        Log.d("Fortify", "SCAN: Sending text: $message")

        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        val json = JSONObject().apply { put("message", message) }
        val body = json.toString().toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("$serverUrl/scanMessage")
            .header("Authorization", "Bearer $jwtToken")
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    setUiState(false)
                    Log.e("Fortify", "SCAN FAILED: ${e.message}")
                    Toast.makeText(applicationContext, "Network Error. Check IP/Cleartext.", Toast.LENGTH_LONG).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                Log.d("Fortify", "SCAN RESPONSE: $responseBody")
                if (response.isSuccessful && responseBody != null) {
                    try {
                        val jobId = JSONObject(responseBody).getString("jobID")
                        runOnUiThread { startPolling(jobId) }
                    } catch (e: Exception) {
                        runOnUiThread { setUiState(false) }
                    }
                } else {
                    runOnUiThread {
                        setUiState(false)
                        Log.e("Fortify", "SERVER ERROR: ${response.code}")
                    }
                }
            }
        })
    }

    private fun startPolling(jobId: String) {
        Log.d("Fortify", "POLLING: Started for $jobId")
        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        pollingRunnable = object : Runnable {
            override fun run() {
                val jsonBody = JSONObject().apply { put("jobID", jobId) }
                val body = jsonBody.toString().toRequestBody(JSON_MEDIA_TYPE)

                val request = Request.Builder()
                    .url("$serverUrl/scanStatus")
                    .header("Authorization", "Bearer $jwtToken")
                    .post(body)
                    .build()

                client.newCall(request).enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        Log.e("Fortify", "POLL FAILED: ${e.message}")
                    }

                    override fun onResponse(call: Call, response: Response) {
                        val responseBody = response.body?.string()
                        Log.d("Fortify", "POLL RESPONSE: $responseBody")
                        if (response.isSuccessful && responseBody != null) {
                            try {
                                val json = JSONObject(responseBody)
                                val status = json.optString("status", "0")

                                if (status == "1") {
                                    Log.d("Fortify", "POLL DONE: Moving to results...")
                                    handler.removeCallbacks(pollingRunnable!!)
                                    fetchFinalResults(jobId)
                                } else {
                                    // RE-POST THE DELAY HERE ONLY IF NOT DONE
                                    handler.postDelayed(pollingRunnable!!, 3000)
                                }
                            } catch (e: Exception) {
                                Log.e("Fortify", "POLL PARSE ERROR")
                            }
                        }
                    }
                })
            }
        }
        handler.post(pollingRunnable!!)
    }

    private fun fetchFinalResults(jobId: String) {
        Log.d("Fortify", "RESULTS: Fetching final detection...")
        val serverUrl = sharedPreferences.getString("serverUrl", "")
        val jwtToken = sharedPreferences.getString("jwtToken", "")

        val json = JSONObject().apply { put("jobID", jobId) }
        val body = json.toString().toRequestBody(JSON_MEDIA_TYPE)

        val request = Request.Builder()
            .url("$serverUrl/getScanDetails")
            .header("Authorization", "Bearer $jwtToken")
            .post(body)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread { setUiState(false) }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                Log.d("Fortify", "FINAL RESPONSE: $responseBody")
                if (response.isSuccessful && responseBody != null) {
                    try {
                        val jsonResponse = JSONObject(responseBody)
                        val detection = jsonResponse.getString("detection")
                        runOnUiThread { displayResults(detection) }
                    } catch (e: Exception) {
                        Log.e("Fortify", "FINAL PARSE ERROR")
                        runOnUiThread { setUiState(false) }
                    }
                }
            }
        })
    }

    private fun displayResults(result: String) {
        // --- THIS MUST SHOW IF YOU REACH THIS POINT ---
        Toast.makeText(this, "RAW DATA: $result", Toast.LENGTH_LONG).show()

        pollingProgressBar.visibility = View.GONE
        statusTitleTextView.visibility = View.VISIBLE
        statusTextView.visibility = View.VISIBLE
        scanMessageButton.isEnabled = true
        messageEditText.isEnabled = true

        statusTextView.text = result.uppercase()

        when {
            result.equals("Phishing", ignoreCase = true) -> {
                resultCardLayout.setBackgroundColor(ContextCompat.getColor(this, R.color.result_malicious))
            }
            result.equals("Suspicious", ignoreCase = true) -> {
                // If it hits here, it turns Orange!
                resultCardLayout.setBackgroundColor(ContextCompat.getColor(this, R.color.result_suspicious))
            }
            else -> {
                statusTextView.text = "SAFE"
                resultCardLayout.setBackgroundColor(ContextCompat.getColor(this, R.color.result_clean))
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        pollingRunnable?.let { handler.removeCallbacks(it) }
    }
}