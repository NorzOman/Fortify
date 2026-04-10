
# -- import the required items
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

# -- intialize stuffs
app = Flask(__name__)
job_lock = threading.Lock()
job_condition = threading.Condition(lock=job_lock)
queue = deque()
jobLookup = {}
tokenizer, model = load_model("phishing_api/model")
classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, device=-1)
# -- job strucutre
class Job:
    def __init__(self, jobID: str, message: str) -> None:
        self.jobID = jobID
        self.message = message
        self.status = 0
        self.confidence = None
        self.detection = None
        self.suspicious_words = None
        self.force_plot_image = None

# -- mother function
def queryJobsDB(queryType: str, param):
    with job_condition:
        if queryType == "createJob":
            queue.append(param)
            job_condition.notify()
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

# -- route to return the jwt token
@app.route("/getToken", methods=["POST"])
def getToken():
    print(" -- Got a request for authentication token (Temporary Bypass)")
    try:
        data = request.get_json()
        fake_jwt_token = f"fortify-auth-{uuid.uuid4()}"
        return {"token": fake_jwt_token}, 200
    except Exception as e:
        print(f" -- Token error: {e}")
        return {"error": "Failed to generate token"}, 500

# -- route to return the validity of the token
@app.route("/verifyToken", methods=["GET", "POST"])
def verifyToken():
    print(" -- Got a request to verify Auto-Login token")
    return {"status": "valid"}, 200
    
# -- route for the scan message function
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
        jobLookup[jobID] = j
        return {"jobID": jobID}, 200
    except Exception as e:
        print(f" -- An error occurred in the job creation process: {e}")
        return {"error": "Failed to create job, refer to system logs for errors"}, 500

# -- route to query the scan status of the message
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

# -- route to get the result of the scan
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
                job_condition.wait()
            j = queue[0]
        try:
            out = predict_message_type(j.message[:512], classifier)
            j.status = 1
            j.confidence = out[0]['score']
            j.detection = "Safe" if out[0]['label'] == "LABEL_0" else "Phishing"
            if j.detection != "Phishing" and ("http" in j.message or "https" in j.message):
                j.detection = "Suspicious"
            queryJobsDB("updateJobDetails", j)
        except Exception as e:
            print(f" -- An error occurred in message_worker: {e}")
            j.status = -1
            j.detection = "Error"
            j.confidence = 0
            queryJobsDB("updateJobDetails", j)

def generate_shap_explanation(text_message):
    try:
        # 1. TRUNCATION: Analyzing long text on a CPU is the #1 cause of 'Killed' errors.
        # We limit to the first 400 characters where phishing triggers are usually densest.
        truncated_text = text_message[:400] 
        print(f" -- [XAI] Generating optimized SHAP analysis for: {truncated_text[:30]}...")
        
        # 2. INITIALIZE EXPLAINER
        explainer = shap.Explainer(classifier)
        
        # 3. SPEED BOOST: max_evals=100
        # By default, SHAP runs hundreds of permutations. 100 is the 'Sweet Spot' 
        # for a t3.micro to finish quickly without crashing the RAM.
        shap_values = explainer([truncated_text], max_evals=100)
        
        # 4. DATA EXTRACTION
        tokens = shap_values.data[0]
        values = shap_values.values[0] 
        class_idx = 1 if len(values.shape) > 1 and values.shape[1] > 1 else 0
        scores = values[:, class_idx] if len(values.shape) > 1 else values
        
        # 5. FILTER SUSPICIOUS WORDS
        words_with_scores = []
        for word, score in zip(tokens, scores):
            clean_word = word.strip().replace("#", "")
            if len(clean_word) > 2 and score > 0.05: 
                words_with_scores.append((clean_word, score))
        
        words_with_scores.sort(key=lambda x: x[1], reverse=True)
        suspicious_words = [w[0] for w in words_with_scores[:5]]
        
        # 6. MEMORY-EFFICIENT PLOTTING
        # Smaller figure size and lower DPI (100) keeps the RAM usage low.
        plt.figure(figsize=(8, 4)) 
        shap.plots.bar(shap_values[0][:, class_idx], show=False, max_display=10)
        
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png', bbox_inches='tight', dpi=100)
        
        # CRITICAL: plt.close() releases the RAM back to Ubuntu immediately.
        # Without this, the 'Killed' error eventually returns.
        plt.close() 
        
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        
        print(" -- [XAI] Optimized analysis complete!")
        return suspicious_words, image_base64
        
    except Exception as e:
        print(f" -- [XAI ERROR] Optimization failed: {e}")
        return [], ""
    

@app.route("/getExplanation", methods=["POST"])
def getExplanation():
    print(" -- Got a request for XAI forensic explanation")
    try:
        data = request.get_json()
        jobID = data.get('jobID')
        original_message = data.get('message') 

        # 1. SAFETY CHECK: If the jobID doesn't exist in our memory, 
        # return a 404 error instead of letting the server crash.
        if not jobID or jobID not in jobLookup:
            print(f" -- [XAI ERROR] JobID {jobID} not found.")
            return {"error": "Job not found or session expired"}, 404

        if not original_message:
            return {"error": "Message text is required for forensic analysis"}, 400

        print(f" -- [XAI] Analyzing text: {original_message[:30]}...")

        # 2. CACHING LOGIC: Only run the heavy SHAP math if we haven't done it yet
        if jobLookup[jobID].suspicious_words is None or jobLookup[jobID].force_plot_image is None:
            print(" -- [XAI] No cached result found, running SHAP...")
            suspicious_words, plot_base64 = generate_shap_explanation(original_message)
            
            # Save the results so we don't have to run SHAP again for this same job
            jobLookup[jobID].suspicious_words = suspicious_words
            jobLookup[jobID].force_plot_image = plot_base64

        return {
            "suspicious_words": jobLookup[jobID].suspicious_words,
            "force_plot_image": jobLookup[jobID].force_plot_image
        }, 200
        
    except Exception as e:
        # Use a more detailed print for debugging on AWS
        print(f" -- [CRITICAL ERROR] getExplanation failed: {e}")
        return {"error": "Internal forensic analysis failure"}, 500

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