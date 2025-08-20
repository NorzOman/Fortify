import os
import sys
import logging
import requests
from flask import Flask, render_template, request, jsonify
from colorama import Fore, Style, init

# Initialize color for logs
init()

# --- App Setup ---
app = Flask(__name__)
BACKEND_URL = "http://127.0.0.1:5000"

# Silence Flask's default request logs
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

def print_log(message, level="info"):
    prefix = "> ( tsrv ) ::"
    if level == "error":
        print(f"\t{Fore.RED}{prefix} {message}{Style.RESET_ALL}", file=sys.stderr)
    else:
        print(f"\t{prefix} {message}", file=sys.stdout)
    sys.stdout.flush()

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/database')
def database_view():
    """Serves the database viewer HTML page."""
    return render_template('database.html')

@app.route('/get_db_data', methods=['GET'])
def get_db_data():
    """Proxies request to the backend's /seeDbs endpoint."""
    print_log("Fetching database contents from backend for viewer.")
    try:
        backend_response = requests.get(f'{BACKEND_URL}/seeDbs')
        return jsonify(backend_response.json()), backend_response.status_code
    except requests.exceptions.ConnectionError:
        print_log(f"Backend connection failed at {BACKEND_URL}.", level="error")
        return jsonify({"error": "Could not connect to backend service."}), 503

@app.route('/submit_scan', methods=['POST'])
def submit_scan():
    """Handles new scan submissions and forwards them to the backend."""
    jwt_token = request.form.get('jwt_token')
    scan_type = request.form.get('scan_type')

    if not jwt_token:
        return jsonify({"error": "JWT Token is required."}), 400

    headers = {'Authorization': f'Bearer {jwt_token}'}
    print_log(f"New scan request received (Type: {scan_type}).")

    try:
        if scan_type == 'Malware':
            file = request.files.get('file')
            if not file or not file.filename:
                return jsonify({"error": "No APK file selected."}), 400
            files = {'file': (file.filename, file.read(), file.content_type)}
            backend_response = requests.post(f'{BACKEND_URL}/scanApk', headers=headers, files=files)
        elif scan_type == 'Phishing':
            message = request.form.get('message_text')
            if not message:
                return jsonify({"error": "Message text is required."}), 400
            backend_response = requests.post(f'{BACKEND_URL}/scanMessage', headers=headers, data={'message': message})
        else:
            return jsonify({"error": "Invalid scan type selected."}), 400
        return jsonify(backend_response.json()), backend_response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to backend service."}), 503
    except Exception as e:
        return jsonify({"error": f"An unexpected internal error occurred: {e}"}), 500

@app.route('/check_status', methods=['POST'])
def check_status():
    """Checks the status of a submitted job."""
    jwt_token = request.form.get('jwt_token_status')
    job_id = request.form.get('job_id_status')

    if not jwt_token or not job_id:
        return jsonify({"error": "JWT Token and Job ID are required."}), 400

    headers = {'Authorization': f'Bearer {jwt_token}'}
    print_log(f"Status check for Job ID: {job_id}.")

    try:
        url = f'{BACKEND_URL}/scanStatus'
        params = {'jobID': job_id}
        backend_response = requests.get(url, headers=headers, params=params)
        return jsonify(backend_response.json()), backend_response.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to backend service."}), 503
    except Exception as e:
        return jsonify({"error": f"An unexpected internal error occurred: {e}"}), 500

if __name__ == '__main__':
    # Ensure 'templates' directory exists.
    if not os.path.exists('templates'):
        os.makedirs('templates')
    print_log("Starting frontend server on http://127.0.0.1:5001")
    app.run(host='0.0.0.0', port=5001)