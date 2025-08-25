package com.example.fortify // Or your package name e.g., com.example.fortify

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.Toast
import com.example.fortify.HomeActivity
import com.example.fortify.R
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

class MainActivity : AppCompatActivity() {

    private lateinit var serverUrlEditText: EditText
    private lateinit var usernameEditText: EditText
    private lateinit var proceedButton: Button
    private lateinit var loadingProgressBar: ProgressBar
    private lateinit var sharedPreferences: SharedPreferences

    private val client = OkHttpClient()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        serverUrlEditText = findViewById(R.id.serverUrlEditText)
        usernameEditText = findViewById(R.id.usernameEditText)
        proceedButton = findViewById(R.id.proceedButton)
        loadingProgressBar = findViewById(R.id.loadingProgressBar)

        sharedPreferences = getSharedPreferences("FortifyPrefs", Context.MODE_PRIVATE)

        val savedUrl = sharedPreferences.getString("serverUrl", "")
        if (!savedUrl.isNullOrEmpty()) {
            serverUrlEditText.setText(savedUrl)
        }

        proceedButton.setOnClickListener {
            var serverUrl = serverUrlEditText.text.toString().trim()
            val username = usernameEditText.text.toString().trim()

            if (serverUrl.isNotEmpty() && username.isNotEmpty()) {
                if (!serverUrl.startsWith("http://") && !serverUrl.startsWith("https://")) {
                    serverUrl = "http://$serverUrl"
                }
                setLoadingState(true)
                getTokenFromServer(serverUrl, username)
            } else {
                Toast.makeText(this, "Please fill in all fields", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun setLoadingState(isLoading: Boolean) {
        if (isLoading) {
            loadingProgressBar.visibility = View.VISIBLE
            proceedButton.isEnabled = false
            serverUrlEditText.isEnabled = false
            usernameEditText.isEnabled = false
        } else {
            loadingProgressBar.visibility = View.GONE
            proceedButton.isEnabled = true
            serverUrlEditText.isEnabled = true
            usernameEditText.isEnabled = true
        }
    }

    private fun getTokenFromServer(serverUrl: String, username: String) {
        val jsonObject = JSONObject()
        jsonObject.put("username", username)
        val json = jsonObject.toString()
        val requestBody = json.toRequestBody("application/json; charset=utf-8".toMediaType())
        val request = Request.Builder()
            .url("$serverUrl/getToken")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    setLoadingState(false)
                    Toast.makeText(applicationContext, "Connection failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                // *** FIX: Read the body here, on the background thread ***
                val responseBody = response.body?.string()

                Log.d("SERVER_RESPONSE", "Response: $responseBody")

                // Now, switch to the main thread to update the UI with the result
                runOnUiThread {
                    setLoadingState(false)
                    if (response.isSuccessful && responseBody != null) {
                        try {
                            val jsonResponse = JSONObject(responseBody)
                            val token = jsonResponse.getString("token")

                            val editor = sharedPreferences.edit()
                            editor.putString("serverUrl", serverUrl)
                            editor.putString("username", username)
                            editor.putString("jwtToken", token)
                            editor.apply()

                            val intent = Intent(this@MainActivity, HomeActivity::class.java)
                            startActivity(intent)
                            finish()

                        } catch (e: Exception) {
                            Toast.makeText(applicationContext, "Failed to parse server response.", Toast.LENGTH_SHORT).show()
                        }
                    } else {
                        Toast.makeText(applicationContext, "Server error: ${response.code} ${response.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        })
    }
}
