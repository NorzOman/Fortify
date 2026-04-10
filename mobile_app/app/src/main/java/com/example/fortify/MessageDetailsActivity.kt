package com.example.fortify

import android.app.Dialog
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
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
        val result = intent.getStringExtra("RESULT") ?: "Safe"

        // 2. Populate basic UI
        findViewById<TextView>(R.id.detailSenderText).text = "From: $sender"
        findViewById<TextView>(R.id.detailMessageBody).text = messageBody

        val statusLabel = findViewById<TextView>(R.id.detailStatusText)
        statusLabel.text = result.uppercase()

        // Apply 3-way color logic to the status label
        when {
            result.equals("Phishing", ignoreCase = true) -> {
                statusLabel.setTextColor(Color.parseColor("#D32F2F")) // Red
            }
            result.equals("Suspicious", ignoreCase = true) -> {
                statusLabel.setTextColor(Color.parseColor("#FF8F00")) // Orange
            }
            else -> {
                statusLabel.setTextColor(Color.parseColor("#388E3C")) // Green
            }
        }

        // 3. Logic for Forensics/XAI Report
        val isMalicious = result.equals("Phishing", ignoreCase = true) ||
                result.equals("Suspicious", ignoreCase = true)

        if (jobId.isNotEmpty() && isMalicious) {
            findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.VISIBLE
            findViewById<TextView>(R.id.safeMessageTextView).visibility = View.GONE
            fetchExplainableAIData(jobId, messageBody)
        } else {
            findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE
            findViewById<LinearLayout>(R.id.shapContentLayout).visibility = View.GONE
            val safeTextView = findViewById<TextView>(R.id.safeMessageTextView)
            safeTextView.visibility = View.VISIBLE
            safeTextView.text = "This message is verified as Safe.\nNo forensic analysis required."
        }
    }

    private fun fetchExplainableAIData(jobId: String, messageBody: String) {
        val prefs = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)
        val serverUrl = prefs.getString("serverUrl", "")
        val jwtToken = prefs.getString("jwtToken", "")

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
                handler.post {
                    findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE
                    Toast.makeText(applicationContext, "XAI Load Failed", Toast.LENGTH_SHORT).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                if (response.isSuccessful && responseBody != null) {
                    try {
                        val json = JSONObject(responseBody)
                        val wordsArray = json.getJSONArray("suspicious_words")
                        val wordsList = mutableListOf<String>()
                        for (i in 0 until wordsArray.length()) {
                            wordsList.add(wordsArray.getString(i))
                        }
                        val forcePlotBase64 = json.getString("force_plot_image")

                        handler.post { displayXAI(wordsList, forcePlotBase64) }
                    } catch (e: Exception) {
                        handler.post { findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE }
                    }
                }
            }
        })
    }

    private fun displayXAI(suspiciousWords: List<String>, forcePlotBase64: String) {
        findViewById<ProgressBar>(R.id.shapProgressBar).visibility = View.GONE
        findViewById<LinearLayout>(R.id.shapContentLayout).visibility = View.VISIBLE

        // Add Red Chips for keywords
        val chipGroup = findViewById<ChipGroup>(R.id.suspiciousWordsGroup)
        chipGroup.removeAllViews()
        for (word in suspiciousWords) {
            val chip = Chip(this)
            chip.text = word
            chip.setTextColor(Color.WHITE)
            chip.setChipBackgroundColorResource(android.R.color.holo_red_dark)
            chipGroup.addView(chip)
        }

        // Decode and enable Click-to-Zoom
        if (forcePlotBase64.isNotEmpty()) {
            try {
                val decodedString: ByteArray = Base64.decode(forcePlotBase64, Base64.DEFAULT)
                val bitmap = BitmapFactory.decodeByteArray(decodedString, 0, decodedString.size)

                val plotImageView = findViewById<ImageView>(R.id.forcePlotImageView)
                plotImageView.setImageBitmap(bitmap)

                // Set click listener for the popup
                plotImageView.setOnClickListener {
                    showFullPlotPopup(bitmap)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun showFullPlotPopup(bitmap: Bitmap) {
        // Create a full-screen dialog
        val dialog = Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
        dialog.setContentView(R.layout.dialog_full_plot)

        val fullImageView = dialog.findViewById<ImageView>(R.id.fullPlotImageView)
        fullImageView.setImageBitmap(bitmap)

        // --- UPDATED LOGIC ---
        // 1. Remove the OnClickListener that was calling dialog.dismiss()
        // 2. Disable dismissal when clicking outside the image (the "scrim" area)
        dialog.setCanceledOnTouchOutside(false)

        // 3. Ensure back-button behavior is allowed (this is true by default, but let's be explicit)
        dialog.setCancelable(true)

        dialog.show()
    }
}