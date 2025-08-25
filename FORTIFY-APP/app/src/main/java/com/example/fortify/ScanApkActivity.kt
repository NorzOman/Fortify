package com.example.fortify // Or your package name

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class ScanApkActivity : AppCompatActivity() {

    // UI Views
    private lateinit var selectedFileTextView: TextView
    private lateinit var uploadApkButton: Button
    private lateinit var scanProgressBar: ProgressBar
    private lateinit var statusTextView: TextView
    private lateinit var resultsCardView: CardView
    private lateinit var maliciousTextView: TextView
    private lateinit var confidenceTextView: TextView
    private lateinit var reportContentTextView: TextView

    // Networking and Data
    private val client = OkHttpClient()
    private lateinit var serverUrl: String
    private lateinit var jwtToken: String
    private var fileUri: Uri? = null

    // Polling
    private val handler = Handler(Looper.getMainLooper())
    private var pollingRunnable: Runnable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_apk)

        // Initialize UI
        bindViews()

        // Get data from SharedPreferences
        val sharedPreferences = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)
        serverUrl = sharedPreferences.getString("serverUrl", "")!!
        jwtToken = sharedPreferences.getString("jwtToken", "")!!

        // Get file details from the Intent
        val fileUriString = intent.getStringExtra("FILE_URI")
        val fileName = intent.getStringExtra("FILE_NAME")
        if (fileUriString != null) {
            fileUri = Uri.parse(fileUriString)
            selectedFileTextView.text = "Selected: $fileName"
            uploadApkButton.isEnabled = true
        }

        uploadApkButton.setOnClickListener {
            if (fileUri != null) {
                uploadApkFile(fileUri!!)
            } else {
                Toast.makeText(this, "No file selected.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun bindViews() {
        selectedFileTextView = findViewById(R.id.selectedFileTextView)
        uploadApkButton = findViewById(R.id.uploadApkButton)
        scanProgressBar = findViewById(R.id.scanProgressBar)
        statusTextView = findViewById(R.id.statusTextView)
        resultsCardView = findViewById(R.id.resultsCardView)
        maliciousTextView = findViewById(R.id.maliciousTextView)
        confidenceTextView = findViewById(R.id.confidenceTextView)
        reportContentTextView = findViewById(R.id.reportContentTextView)
    }

    private fun setUiState(state: ScanState) {
        when (state) {
            ScanState.Idle -> {
                uploadApkButton.isEnabled = true
                scanProgressBar.visibility = View.GONE
                statusTextView.visibility = View.GONE
                resultsCardView.visibility = View.GONE
            }
            ScanState.Uploading -> {
                uploadApkButton.isEnabled = false
                scanProgressBar.visibility = View.VISIBLE
                statusTextView.visibility = View.VISIBLE
                statusTextView.text = "Status: Uploading..."
                resultsCardView.visibility = View.GONE
            }
            ScanState.Polling -> {
                uploadApkButton.isEnabled = false
                scanProgressBar.visibility = View.VISIBLE
                statusTextView.visibility = View.VISIBLE
                statusTextView.text = "Status: Scanning..."
                resultsCardView.visibility = View.GONE
            }
            is ScanState.Done -> {
                uploadApkButton.isEnabled = true
                scanProgressBar.visibility = View.GONE
                statusTextView.visibility = View.GONE
                resultsCardView.visibility = View.VISIBLE
                displayResults(state.result)
            }
        }
    }

    private fun uploadApkFile(uri: Uri) {
        setUiState(ScanState.Uploading)

        // Create a temporary file from the URI to upload
        val tempFile = File(cacheDir, getFileName(uri) ?: "temp_apk.apk")
        contentResolver.openInputStream(uri)?.use { inputStream ->
            FileOutputStream(tempFile).use { outputStream ->
                inputStream.copyTo(outputStream)
            }
        }

        val requestBody = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart(
                "file",
                tempFile.name,
                tempFile.asRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull())
            )
            .build()

        val request = Request.Builder()
            .url("$serverUrl/scanApk")
            .header("Authorization", "Bearer $jwtToken")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    setUiState(ScanState.Idle)
                    Toast.makeText(applicationContext, "Upload failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                if (response.isSuccessful && responseBody != null) {
                    val jsonObject = JSONObject(responseBody)
                    val jobId = jsonObject.getString("jobID")
                    runOnUiThread {
                        setUiState(ScanState.Polling)
                        startPolling(jobId)
                    }
                } else {
                    runOnUiThread {
                        setUiState(ScanState.Idle)
                        Toast.makeText(applicationContext, "Server error: ${response.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        })
    }

    private fun startPolling(jobId: String) {
        pollingRunnable = object : Runnable {
            override fun run() {
                checkScanStatus(jobId)
                handler.postDelayed(this, 10000) // Poll every 10 seconds
            }
        }
        handler.post(pollingRunnable!!)
    }

    private fun checkScanStatus(jobId: String) {
        val request = Request.Builder()
            .url("$serverUrl/scanStatus?jobID=$jobId")
            .header("Authorization", "Bearer $jwtToken")
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                // Don't show toast on every poll failure, just log it
                e.printStackTrace()
            }

            override fun onResponse(call: Call, response: Response) {
                val responseBody = response.body?.string()
                if (response.isSuccessful && responseBody != null) {
                    val json = JSONObject(responseBody)
                    val details = json.getJSONObject("details")
                    val status = details.getString("STATUS")

                    if (status.equals("Done", ignoreCase = true)) {
                        handler.removeCallbacks(pollingRunnable!!)

                        // Parse the final result
                        val finalResult = ScanResult(
                            malicious = !details.getString("DETECTION").equals("N/A", ignoreCase = true),
                            confidence = details.optDouble("CONFIDENCE", 0.0),
                            report = details.getString("DETECTION")
                        )
                        runOnUiThread { setUiState(ScanState.Done(finalResult)) }
                    }
                }
            }
        })
    }

    private fun displayResults(result: ScanResult) {
        maliciousTextView.text = "Result: ${if (result.malicious) "Malicious" else "Clean"}"
        confidenceTextView.text = "Confidence: ${(result.confidence * 100).toInt()}%"
        reportContentTextView.text = result.report
    }

    // Helper function to get filename from URI
    private fun getFileName(uri: Uri): String? {
        var fileName: String? = null
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) {
                    fileName = cursor.getString(nameIndex)
                }
            }
        }
        return fileName
    }

    override fun onDestroy() {
        super.onDestroy()
        // Stop polling when the activity is destroyed to prevent memory leaks
        pollingRunnable?.let { handler.removeCallbacks(it) }
    }
}

// Sealed class to represent the different states of the UI
sealed class ScanState {
    object Idle : ScanState()
    object Uploading : ScanState()
    object Polling : ScanState()
    data class Done(val result: ScanResult) : ScanState()
}

// Data class to hold the final scan result
data class ScanResult(
    val malicious: Boolean,
    val confidence: Double,
    val report: String
)
