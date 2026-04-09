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
                    toggleSelection(adapterPosition)
                } else {
                    val context = itemView.context
                    val item = messageList[adapterPosition]
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
                    toggleSelection(adapterPosition)
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

    // --- NEW HELPER FOR THE TOGGLE BUTTON ---
    fun areAllSelected(): Boolean {
        return messageList.isNotEmpty() && selectedJobIds.size == messageList.size
    }

    // ----------------------------------------

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MessageViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return MessageViewHolder(view)
    }

    override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
        val item = messageList[position]
        holder.senderText.text = "From: ${item.sender}"
        holder.bodyText.text = item.messageBody
        holder.resultText.text = item.result

        when (item.result) {
            "Phishing" -> holder.resultText.setTextColor(Color.parseColor("#D32F2F"))
            "Safe" -> holder.resultText.setTextColor(Color.parseColor("#388E3C"))
            else -> holder.resultText.setTextColor(Color.parseColor("#757575"))
        }

        if (selectedJobIds.contains(item.jobId)) {
            holder.cardView.setCardBackgroundColor(Color.parseColor("#B0BEC5"))
        } else {
            when (item.result) {
                "Phishing" -> holder.cardView.setCardBackgroundColor(Color.parseColor("#FFEBEE"))
                "Safe" -> holder.cardView.setCardBackgroundColor(Color.parseColor("#E8F5E9"))
                else -> holder.cardView.setCardBackgroundColor(Color.parseColor("#F5F5F5"))
            }
        }
    }

    override fun getItemCount() = messageList.size

    fun addMessage(message: ScannedMessage) {
        messageList.add(0, message)
        notifyItemInserted(0)
    }
}