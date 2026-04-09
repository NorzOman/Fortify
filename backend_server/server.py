from flask import Flask, request, render_template
from transformers import pipeline
from phishing_api.worker import predict_message_type, load_model
from collections import deque
import threading
import uuid
import signal
import sys

import shap
import matplotlib
matplotlib.use('Agg') # Crucial: Allows plotting without a GUI/Monitor!
import matplotlib.pyplot as plt
import io
import base64
import numpy as np

app = Flask(__name__)
job_lock = threading.Lock()
job_condition = threading.Condition(lock=job_lock)
queue = deque()
jobLookup = {}
tokenizer, model = load_model("phishing_api/model")
classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)


class Job:
    def __init__(self, jobID: str, message: str) -> None:
        self.jobID = jobID
        self.message = message
        self.status = 0
        self.confidence = None
        self.detection = None

# -- mother function
def queryJobsDB(queryType: str, param):
    with job_condition:
        if queryType == "createJob":
            queue.append(param)
            job_condition.notify()  # wake up worker
        elif queryType == "getJobDetails":
            return jobLookup[param].status
        elif queryType == "getLatestJob":
            if queue:
                return queue[0]
            else:
                return None
        elif queryType == "updateJobDetails":
            queue.popleft()
            jobLookup[param.jobID] = param
        else:
            print(" -- An unknown query type call was made, returning None")
            return None

# -- routes

@app.route("/getToken", methods=["POST"])
def getToken():
    print(" -- Got a request for authentication token (Temporary Bypass)")
    try:
        data = request.get_json()
        
        # We generate a fake token so your Android app successfully logs in
        fake_jwt_token = f"fortify-auth-{uuid.uuid4()}"
        
        return {"token": fake_jwt_token}, 200
    except Exception as e:
        print(f" -- Token error: {e}")
        return {"error": "Failed to generate token"}, 500
    
@app.route("/verifyToken", methods=["GET", "POST"])
def verifyToken():
    print(" -- Got a request to verify Auto-Login token")
    # In a fully deployed app, you would verify the JWT signature here.
    # For local testing, if the app can reach this endpoint, the connection is good!
    return {"status": "valid"}, 200
    
@app.route("/scanMessage", methods=["POST"])
def scanMessage():
    print(" -- Got a request for message scan")
    try:
        data = request.get_json()
        message = data.get('message')
        jobID = str(uuid.uuid4())
        if not message:
            print(" -- The message scan request didn't have a 'message' field in it")
            return {"error": "Message field is missing"}, 400
        j = Job(jobID, message)
        queryJobsDB("createJob", j)
        jobLookup[jobID] = queue[-1]
        return {"jobID": jobID}, 200
    except Exception as e:
        print(f" -- An error occurred in the job creation process: {e}")
        return {"error": "Failed to create job, refer to system logs for errors"}, 500

@app.route("/scanStatus", methods=["POST"])
def scanStatus():
    print(" -- Got a request for status check on message")
    try:
        data = request.get_json()
        jobID = data.get('jobID')
        if not jobID:
            print(" -- The status check request didn't have a 'jobID' field in it")
            return {"error": "The jobID field is missing"}, 400
        if jobID not in jobLookup:
            print(" -- The status check was performed on a job that doesn't exist")
            return {"error": "Job not found"}, 404
        status = queryJobsDB("getJobDetails", jobID)
        return {"status": status}, 200
    except Exception as e:
        print(f" -- An error occurred in checking job status: {e}")
        return {"error": "Failed to check job status, refer to system logs for errors"}, 500

@app.route("/getScanDetails", methods=["POST"])
def get_scan_details():
    data = request.get_json()
    jobID = data.get('jobID')
    if not jobID:
        return {"error": "jobID required"}, 400
    try:
        return {"detection": jobLookup[jobID].detection, "confidence": jobLookup[jobID].confidence}, 200
    except Exception as e:
        print(f" -- An error occurred: {e}")
        return {"error": "An exception occurred"}, 500

def message_worker():
    while True:
        with job_condition:
            while not queue:
                job_condition.wait()  # wait efficiently for a new job
            j = queue[0]
        try:
            out = predict_message_type(j.message, classifier)
            j.status = 1
            j.confidence = out[0]['score']
            j.detection = "Safe" if out[0]['label'] == "LABEL_0" else "Phishing"
            queryJobsDB("updateJobDetails", j)
        except Exception as e:
            print(f" -- An error occurred in message_worker: {e}")
            j.status = -1
            j.detection = "Error"
            j.confidence = 0
            queryJobsDB("updateJobDetails", j)

# ==========================================
# EXPLAINABLE AI (SHAP) LOGIC
# ==========================================

def generate_shap_explanation(text_message):
    try:
        print(" -- [XAI] Generating SHAP forensic analysis...")
        
        # 1. Initialize the SHAP Explainer with your Hugging Face model
        explainer = shap.Explainer(classifier)
        
        # 2. Calculate the SHAP values for the specific message
        shap_values = explainer([text_message])
        
        # Extract the tokens (words) and their impact scores
        tokens = shap_values.data[0]
        values = shap_values.values[0] 
        
        # Determine the correct class index (usually 1 for Phishing)
        class_idx = 1 if len(values.shape) > 1 and values.shape[1] > 1 else 0
        scores = values[:, class_idx] if len(values.shape) > 1 else values
        
        # 3. Find the "Suspicious Words" (Words that pushed the score higher)
        words_with_scores = []
        for word, score in zip(tokens, scores):
            # Clean up token fragments (like ## or empty spaces)
            clean_word = word.strip().replace("#", "")
            if len(clean_word) > 2 and score > 0.05: # Only grab words with high impact
                words_with_scores.append((clean_word, score))
                
        # Sort by most suspicious and grab the top 5
        words_with_scores.sort(key=lambda x: x[1], reverse=True)
        suspicious_words = [w[0] for w in words_with_scores[:5]]
        
        # 4. Generate the Visual Plot
        plt.figure(figsize=(10, 5))
        
        # A Bar plot works best for showing individual word impacts in text
        shap.plots.bar(shap_values[0][:, class_idx], show=False)
        
        # Save the plot to an invisible RAM buffer
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=150)
        plt.close() # Free up memory
        buf.seek(0)
        
        # 5. Convert the image to a Base64 string for Android
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        
        print(" -- [XAI] Analysis complete!")
        return suspicious_words, image_base64
        
    except Exception as e:
        print(f" -- [XAI ERROR] Failed to generate SHAP explanation: {e}")
        return [], ""

@app.route("/getExplanation", methods=["POST"])
def getExplanation():
    print(" -- Got a request for XAI forensic explanation")
    try:
        data = request.get_json()
        jobID = data.get('jobID')
        
        # NEW: Get the original text message directly from Android!
        original_message = data.get('message') 
        
        if not jobID or not original_message:
            return {"error": "Missing jobID or message text"}, 400
            
        print(f" -- [XAI] Analyzing text: {original_message[:30]}...")

        # Generate explanations directly from the provided text, ignoring jobLookup!
        suspicious_words, plot_base64 = generate_shap_explanation(original_message)
        
        return {
            "suspicious_words": suspicious_words,
            "force_plot_image": plot_base64
        }, 200
        
    except Exception as e:
        print(f" -- An error occurred in getExplanation: {e}")
        return {"error": "Failed to generate explanation"}, 500
# ==========================================

def shutdown_signal_handler(sig, frame):
    print(" -- Shutdown signal received, exiting gracefully...")
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, shutdown_signal_handler)
    signal.signal(signal.SIGTERM, shutdown_signal_handler)

    t1 = threading.Thread(target=message_worker, daemon=True)
    t1.start()
    print(" -- Flask app starting on 0.0.0.0:8000")
    app.run(host='0.0.0.0', port=8000, debug=False)