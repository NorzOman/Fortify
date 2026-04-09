package com.example.fortify

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Color // <--- NEW IMPORT FOR COLOR CHANGE
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class HomeActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var messageAdapter: MessageAdapter
    private val messageList = mutableListOf<ScannedMessage>()

    // --- UI Elements ---
    private lateinit var selectionBar: View
    private lateinit var tvSelectedCount: TextView
    private lateinit var btnSelectAll: Button
    private lateinit var btnDeleteSelected: ImageButton
    // Cancel button removed!

    private val liveUpdateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val jobId = intent?.getStringExtra("JOB_ID") ?: ""
            val sender = intent?.getStringExtra("SENDER") ?: "Unknown"
            val body = intent?.getStringExtra("BODY") ?: ""
            val result = intent?.getStringExtra("RESULT") ?: "Error"

            messageAdapter.addMessage(ScannedMessage(jobId, sender, body, result))
            recyclerView.scrollToPosition(0)
        }
    }

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
            val smsGranted = permissions[Manifest.permission.RECEIVE_SMS] ?: false
            if (!smsGranted) {
                Toast.makeText(this, "Fortify cannot protect you without SMS permissions.", Toast.LENGTH_LONG).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        // Bind UI Elements
        selectionBar = findViewById(R.id.selectionBar)
        tvSelectedCount = findViewById(R.id.tvSelectedCount)
        btnSelectAll = findViewById(R.id.btnSelectAll)
        btnDeleteSelected = findViewById(R.id.btnDeleteSelected)

        recyclerView = findViewById(R.id.liveFeedRecyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)

        // --- UPDATED: Callback now handles the Color/Text Toggle ---
        messageAdapter = MessageAdapter(messageList) { selectedCount ->
            if (selectedCount > 0) {
                selectionBar.visibility = View.VISIBLE
                tvSelectedCount.text = "$selectedCount Selected"

                // Toggle logic for the button UI
                if (messageAdapter.areAllSelected()) {
                    btnSelectAll.text = "Unselect All"
                    btnSelectAll.setTextColor(Color.parseColor("#FFD54F")) // Turns text Yellow to indicate it's active
                } else {
                    btnSelectAll.text = "Select All"
                    btnSelectAll.setTextColor(Color.WHITE) // Default color
                }
            } else {
                // If 0 are selected, hide the bar completely
                selectionBar.visibility = View.GONE
            }
        }
        recyclerView.adapter = messageAdapter

        // --- UPDATED: Button Click Listener Toggle ---
        btnSelectAll.setOnClickListener {
            if (messageAdapter.areAllSelected()) {
                // If everything is selected, clear it (which also hides the bar)
                messageAdapter.clearSelection()
            } else {
                // Otherwise, select everything
                messageAdapter.selectAll()
            }
        }

        btnDeleteSelected.setOnClickListener {
            val jobsToDelete = messageAdapter.selectedJobIds.toList()

            lifecycleScope.launch {
                val db = AppDatabase.getDatabase(this@HomeActivity)
                db.messageDao().deleteMessagesByJobIds(jobsToDelete)
            }

            messageAdapter.removeSelectedItems()
            Toast.makeText(this, "Messages deleted", Toast.LENGTH_SHORT).show()
        }

        // LOAD HISTORY FROM ROOM DATABASE
        val db = AppDatabase.getDatabase(this)
        lifecycleScope.launch {
            val oldMessages = db.messageDao().getAllMessages()
            messageList.clear()
            oldMessages.forEach { entity ->
                messageList.add(ScannedMessage(entity.jobId, entity.sender, entity.messageBody, entity.result))
            }
            messageAdapter.notifyDataSetChanged()
        }

        checkAndRequestPermissions()

        val filter = IntentFilter("com.fortify.LIVE_UPDATE")
        ContextCompat.registerReceiver(
            this,
            liveUpdateReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(liveUpdateReceiver)
    }

    private fun checkAndRequestPermissions() {
        val permissionsToRequest = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.RECEIVE_SMS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (permissionsToRequest.isNotEmpty()) {
            requestPermissionLauncher.launch(permissionsToRequest.toTypedArray())
        }
    }
}