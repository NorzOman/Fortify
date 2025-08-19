from flask import Flask, render_template, request, jsonify
import requests
import os
import sys
import logging
from colorama import Fore, Style, init # <--- ADDED THIS LINE

# Initialize Colorama
init() # <--- ADDED THIS LINE

app = Flask(__name__)

# --- Configuration ---
# Disable default Flask/Werkzeug request logging
# This will suppress messages like "GET / HTTP/1.1" 200 -
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR) # Only show error level logs or higher

BACKEND_URL = "http://127.0.0.1:5000"

# --- Logging Helper (for custom frontend logs) ---
def print_frontend_log(message, level="info"):
    """Prints log messages with specified color and pattern for the frontend."""
    if level == "info":
        print(f"{Fore.CYAN}[ frontend (-) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "success":
        print(f"{Fore.GREEN}[ frontend (✔) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "warning":
        print(f"{Fore.YELLOW}[ frontend (?) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "error":
        print(f"{Fore.RED}[ frontend (!) ] {message}{Style.RESET_ALL}", file=sys.stderr)
    sys.stdout.flush()


@app.route('/')
def index():
    """Renders the main HTML page for the frontend."""
    # print_frontend_log("Serving index.html", level="info") # Can enable if needed for specific debugging
    return render_template('index.html')

@app.route('/submit_scan', methods=['POST'])
def submit_scan():
    """Handles submission of new scan requests (APK or Message) to the backend."""
    jwt_token = request.form.get('jwt_token')
    scan_type = request.form.get('scan_type')

    if not jwt_token:
        print_frontend_log("JWT Token is required for scan submission.", level="warning")
        return jsonify({"error": "JWT Token is required."}), 400

    headers = {'Authorization': f'Bearer {jwt_token}'}
    response_data = {}
    status_code = 500 # Default error status

    print_frontend_log(f"Received scan request: Type={scan_type}, JWT={jwt_token[:10]}...")

    if scan_type == 'Malware':
        if 'file' not in request.files:
            print_frontend_log("No file part in request for Malware scan.", level="error")
            return jsonify({"error": "No file part in request. Please select an APK file."}), 400
        file = request.files['file']
        if file.filename == '':
            print_frontend_log("No selected file for Malware scan (empty filename).", level="error")
            return jsonify({"error": "No selected file. Please select an APK file."}), 400
        
        files = {'file': (file.filename, file.read(), file.content_type)}
        try:
            print_frontend_log(f"Sending POST request to {BACKEND_URL}/scanApk")
            backend_response = requests.post(f'{BACKEND_URL}/scanApk', headers=headers, files=files)
            response_data = backend_response.json()
            status_code = backend_response.status_code
            print_frontend_log(f"Backend /scanApk responded with status {status_code}: {response_data}", level="success")
        except requests.exceptions.ConnectionError:
            print_frontend_log(f"Could not connect to backend at {BACKEND_URL} for scanApk. Is it running?", level="error")
            return jsonify({"error": f"Could not connect to backend at {BACKEND_URL}. Is it running?"}), 503
        except Exception as e:
            print_frontend_log(f"An unexpected error occurred during scanApk request: {e}", level="error")
            return jsonify({"error": f"An unexpected error occurred: {e}"}), 500

    elif scan_type == 'Phishing':
        message = request.form.get('message_text')
        if not message:
            print_frontend_log("No message text for Phishing scan.", level="error")
            return jsonify({"error": "Message text is required for Phishing scan."}), 400
        
        data = {'message': message}
        try:
            print_frontend_log(f"Sending POST request to {BACKEND_URL}/scanMessage")
            backend_response = requests.post(f'{BACKEND_URL}/scanMessage', headers=headers, data=data)
            response_data = backend_response.json()
            status_code = backend_response.status_code
            print_frontend_log(f"Backend /scanMessage responded with status {status_code}: {response_data}", level="success")
        except requests.exceptions.ConnectionError:
            print_frontend_log(f"Could not connect to backend at {BACKEND_URL} for scanMessage. Is it running?", level="error")
            return jsonify({"error": f"Could not connect to backend at {BACKEND_URL}. Is it running?"}), 503
        except Exception as e:
            print_frontend_log(f"An unexpected error occurred during scanMessage request: {e}", level="error")
            return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    else:
        print_frontend_log("Invalid scan type selected.", level="error")
        return jsonify({"error": "Invalid scan type selected."}), 400

    return jsonify(response_data), status_code

@app.route('/check_status', methods=['POST'])
def check_status():
    """Handles requests to check the status of a previously submitted job."""
    jwt_token = request.form.get('jwt_token_status')
    job_id = request.form.get('job_id_status')

    if not jwt_token:
        print_frontend_log("JWT Token is required for status check.", level="warning")
        return jsonify({"error": "JWT Token is required for status check."}), 400
    if not job_id:
        print_frontend_log("Job ID is required for status check.", level="warning")
        return jsonify({"error": "Job ID is required for status check."}), 400

    headers = {'Authorization': f'Bearer {jwt_token}'}
    
    print_frontend_log(f"Received status request: Job ID={job_id}, JWT={jwt_token[:10]}...")

    try:
        print_frontend_log(f"Sending GET request to {BACKEND_URL}/scanStatus?jobID={job_id}")
        backend_response = requests.get(f'{BACKEND_URL}/scanStatus?jobID={job_id}', headers=headers)
        response_data = backend_response.json()
        status_code = backend_response.status_code
        print_frontend_log(f"Backend /scanStatus responded with status {status_code}: {response_data}", level="success")
    except requests.exceptions.ConnectionError:
        print_frontend_log(f"Could not connect to backend at {BACKEND_URL} for scanStatus. Is it running?", level="error")
        return jsonify({"error": f"Could not connect to backend at {BACKEND_URL}. Is it running?"}), 503
    except Exception as e:
        print_frontend_log(f"An unexpected error occurred during scanStatus request: {e}", level="error")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
    
    return jsonify(response_data), status_code

if __name__ == '__main__':
    # Create 'templates' directory if it doesn't exist
    if not os.path.exists('templates'):
        print_frontend_log("Creating 'templates' directory.")
        os.makedirs('templates')
    
    print_frontend_log("Starting Flask frontend application on http://127.0.0.1:5001", level="info")
    app.run(debug=True, port=5001) # Run frontend on a different port than backend