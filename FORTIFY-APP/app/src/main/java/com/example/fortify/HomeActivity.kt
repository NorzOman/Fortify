package com.example.fortify // Or your package name

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import com.example.fortify.R
import com.example.fortify.ScanApkActivity

class HomeActivity : AppCompatActivity() {

    private lateinit var scanApkButton: Button
    private lateinit var scanMessageButton: Button

    // This is the modern way to handle the result from the file picker
    private val filePickerLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                // A file was selected. Now get its name and launch ScanApkActivity
                val fileName = getFileName(uri)
                val intent = Intent(this, ScanApkActivity::class.java).apply {
                    putExtra("FILE_URI", uri.toString())
                    putExtra("FILE_NAME", fileName)
                }
                startActivity(intent)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        scanApkButton = findViewById(R.id.scanApkButton)
        scanMessageButton = findViewById(R.id.scanMessageButton)

        scanApkButton.setOnClickListener {
            // This now calls the function to open the file picker
            openFilePicker()
        }

        scanMessageButton.setOnClickListener {
            // We will implement this next
            Toast.makeText(this, "Message Scan coming soon!", Toast.LENGTH_SHORT).show()
        }
    }

    private fun openFilePicker() {
        // This creates an intent to open the system's file manager
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            // We specifically ask for files with the .apk mime type
            type = "application/vnd.android.package-archive"
        }
        // Launch the file picker and wait for the result
        filePickerLauncher.launch(intent)
    }

    // This is a helper function to get the actual file name from its URI
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
}
