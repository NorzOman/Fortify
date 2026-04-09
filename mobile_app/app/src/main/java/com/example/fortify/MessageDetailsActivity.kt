package com.example.fortify

import android.content.Context
import android.graphics.BitmapFactory
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class MessageDetailsActivity : AppCompatActivity() {

    private lateinit var client: OkHttpClient
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_message_details)

        client = OkHttpClient()

        // 1. Get Data from the Intent
        val jobId = intent.getStringExtra("JOB_ID") ?: ""
        val sender = intent.getStringExtra("SENDER") ?: ""
        val messageBody = intent.getStringExtra("MESSAGE_BODY") ?: ""
        val result = intent.getStringExtra("RESULT") ?: ""

        // 2. Populate basic UI
        findViewById<TextView>(R.id.detailSenderText).text = "From: $sender ($result)"
        findViewById<TextView>(R.id.detailMessageBody).text = messageBody

        // 3. Fetch SHAP Data from Server
        if (jobId.isNotEmpty() && result == "Phishing") {
            // UPDATED: Now passing the messageBody to the function!
            fetchExplainableAIData(jobId, messageBody)
        } else {
            // Hide the SHAP loading bar if it's a safe message
            findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE
            Toast.makeText(this, "Message is Safe. No forensic analysis needed.", Toast.LENGTH_SHORT).show()
        }
    }

    // UPDATED: Function now requires the message string
    private fun fetchExplainableAIData(jobId: String, messageBody: String) {
        val prefs = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("serverUrl", "")
        val jwtToken = prefs.getString("jwtToken", "")

        // UPDATED: Sending BOTH the jobID and the original message to make the server stateless!
        val jsonObject = JSONObject().apply {
            put("jobID", jobId)
            put("message", messageBody)
        }
        val requestBody = jsonObject.toString().toRequestBody("application/json; charset=utf-8".toMediaType())

        val request = Request.Builder()
            .url("$serverUrl/getExplanation")
            .header("Authorization", "Bearer $jwtToken")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                handler.post { Toast.makeText(applicationContext, "Failed to load XAI data", Toast.LENGTH_SHORT).show() }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                if (response.isSuccessful && responseBody != null) {
                    try {
                        val json = JSONObject(responseBody)

                        // Parse the array of words
                        val wordsArray = json.getJSONArray("suspicious_words")
                        val wordsList = mutableListOf<String>()
                        for (i in 0 until wordsArray.length()) {
                            wordsList.add(wordsArray.getString(i))
                        }

                        // Parse the Base64 image
                        val forcePlotBase64 = json.getString("force_plot_image")

                        handler.post {
                            displayXAI(wordsList, forcePlotBase64)
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                } else {
                    handler.post { Toast.makeText(applicationContext, "Server error: couldn't fetch explanation", Toast.LENGTH_SHORT).show() }
                }
            }
        })
    }

    private fun displayXAI(suspiciousWords: List<String>, forcePlotBase64: String) {
        findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE
        findViewById<LinearLayout>(R.id.shapContentLayout).visibility = View.VISIBLE

        // Add Red Chips for each suspicious word
        val chipGroup = findViewById<ChipGroup>(R.id.suspiciousWordsGroup)
        chipGroup.removeAllViews() // Clear any existing chips just in case

        for (word in suspiciousWords) {
            val chip = Chip(this)
            chip.text = word
            chip.setTextColor(android.graphics.Color.WHITE)
            chip.setChipBackgroundColorResource(android.R.color.holo_red_dark)
            chipGroup.addView(chip)
        }

        // Decode Base64 string to Bitmap and show it
        if (forcePlotBase64.isNotEmpty()) {
            try {
                val decodedString: ByteArray = Base64.decode(forcePlotBase64, Base64.DEFAULT)
                val decodedByte = BitmapFactory.decodeByteArray(decodedString, 0, decodedString.size)
                findViewById<ImageView>(R.id.forcePlotImageView).setImageBitmap(decodedByte)
            } catch (e: IllegalArgumentException) {
                e.printStackTrace()
            }
        }
    }
}