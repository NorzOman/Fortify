package com.example.fortify

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.recyclerview.widget.RecyclerView
import android.content.Intent

data class ScannedMessage(val jobId: String, val sender: String, val messageBody: String, val result: String)

class MessageAdapter(
    private val messageList: MutableList<ScannedMessage>,
    private val onSelectionChanged: (Int) -> Unit
) : RecyclerView.Adapter<MessageAdapter.MessageViewHolder>() {

    val selectedJobIds = mutableSetOf<String>()
    var isSelectionMode = false

    inner class MessageViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val cardView: CardView = view.findViewById(R.id.messageCard)
        val senderText: TextView = view.findViewById(R.id.senderTextView)
        val bodyText: TextView = view.findViewById(R.id.bodyTextView)
        val resultText: TextView = view.findViewById(R.id.resultTextView)

        init {
            cardView.setOnClickListener {
                if (isSelectionMode) {
                    toggleSelection(bindingAdapterPosition)
                } else {
                    val context = itemView.context
                    val item = messageList[bindingAdapterPosition]
                    val intent = Intent(context, MessageDetailsActivity::class.java).apply {
                        putExtra("JOB_ID", item.jobId)
                        putExtra("SENDER", item.sender)
                        putExtra("MESSAGE_BODY", item.messageBody)
                        putExtra("RESULT", item.result)
                    }
                    context.startActivity(intent)
                }
            }

            cardView.setOnLongClickListener {
                if (!isSelectionMode) {
                    isSelectionMode = true
                    toggleSelection(bindingAdapterPosition)
                }
                true
            }
        }
    }

    private fun toggleSelection(position: Int) {
        if (position == RecyclerView.NO_POSITION) return

        val jobId = messageList[position].jobId
        if (selectedJobIds.contains(jobId)) {
            selectedJobIds.remove(jobId)
        } else {
            selectedJobIds.add(jobId)
        }

        if (selectedJobIds.isEmpty()) {
            isSelectionMode = false
        }

        notifyItemChanged(position)
        onSelectionChanged(selectedJobIds.size)
    }

    // --- Helper Functions ---

    fun selectAll() {
        selectedJobIds.clear()
        messageList.forEach { selectedJobIds.add(it.jobId) }
        notifyDataSetChanged()
        onSelectionChanged(selectedJobIds.size)
    }

    fun clearSelection() {
        isSelectionMode = false
        selectedJobIds.clear()
        notifyDataSetChanged()
        onSelectionChanged(0)
    }

    fun removeSelectedItems() {
        messageList.removeAll { selectedJobIds.contains(it.jobId) }
        clearSelection()
    }

    fun areAllSelected(): Boolean {
        return messageList.isNotEmpty() && selectedJobIds.size == messageList.size
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MessageViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return MessageViewHolder(view)
    }

    override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
        val item = messageList[position]
        holder.senderText.text = "From: ${item.sender}"
        holder.bodyText.text = item.messageBody
        holder.resultText.text = item.result.uppercase() // Force uppercase for cleaner UI

        // --- Logic for 3-Way Result Colors ---
        when {
            item.result.equals("Phishing", ignoreCase = true) -> {
                holder.resultText.setTextColor(Color.parseColor("#D32F2F")) // Strong Red
            }
            item.result.equals("Suspicious", ignoreCase = true) -> {
                holder.resultText.setTextColor(Color.parseColor("#FF8F00")) // Amber/Orange
            }
            item.result.equals("Safe", ignoreCase = true) -> {
                holder.resultText.setTextColor(Color.parseColor("#388E3C")) // Forest Green
            }
            else -> {
                holder.resultText.setTextColor(Color.parseColor("#757575")) // Default Gray
            }
        }

        // --- Logic for Card Backgrounds ---
        if (selectedJobIds.contains(item.jobId)) {
            // Priority: Show Selection Color if item is selected
            holder.cardView.setCardBackgroundColor(Color.parseColor("#B0BEC5"))
        } else {
            // Otherwise, set background based on the detection result
            when {
                item.result.equals("Phishing", ignoreCase = true) -> {
                    holder.cardView.setCardBackgroundColor(Color.parseColor("#EF9A9A")) // Light Red
                }
                item.result.equals("Suspicious", ignoreCase = true) -> {
                    holder.cardView.setCardBackgroundColor(Color.parseColor("#FFF3E0")) // Very Light Orange
                }
                item.result.equals("Safe", ignoreCase = true) -> {
                    holder.cardView.setCardBackgroundColor(Color.parseColor("#E8F5E9")) // Light Green
                }
                else -> {
                    holder.cardView.setCardBackgroundColor(Color.parseColor("#F5F5F5")) // Off-White
                }
            }
        }
    }

    override fun getItemCount() = messageList.size

    fun addMessage(message: ScannedMessage) {
        messageList.add(0, message)
        notifyItemInserted(0)
    }
}