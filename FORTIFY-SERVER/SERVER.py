import os
import sys
import random
import sqlite3
import logging
from flask import Flask, request, jsonify
from colorama import Fore, Style, init

# Initialize color for logs
init()

# --- App Setup ---
app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_FOLDER = os.path.join(BASE_DIR, 'INPUTS')
MALWARE_FOLDER = os.path.join(UPLOADS_FOLDER, 'MALWARE')
PHISHING_FOLDER = os.path.join(UPLOADS_FOLDER, 'MESSAGE')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'OUTPUT')

# Silence Flask's default request logs
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

def print_log(message, level="info"):
    """Prints a log message with the server's standard format without tabs."""
    prefix = "> ( srv ) ::"
    if level == "error":
        print(f"{Fore.RED}{prefix} {message}{Style.RESET_ALL}", file=sys.stderr)
    else:
        print(f"{prefix} {message}", file=sys.stdout)
    sys.stdout.flush()

# Ensure all necessary directories exist on startup
os.makedirs(MALWARE_FOLDER, exist_ok=True)
os.makedirs(PHISHING_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# --- Database Helpers ---
def db_init():
    """Initializes and returns a new database connection and cursor."""
    try:
        conn = sqlite3.connect("Job_database.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row # Allows accessing columns by name
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data(
                JOB_ID INTEGER NOT NULL,
                JWT_TOKEN TEXT NOT NULL,
                TYPE TEXT CHECK(TYPE IN ("Malware","Phishing")) NOT NULL,
                INPUT_FILE_PATH TEXT,
                STATUS TEXT CHECK(STATUS IN ("Pending","Done")) NOT NULL,
                OUTPUT_FILE_PATH TEXT,
                CONFIDENCE INTEGER NULL,
                DETECTION TEXT NULL
            )""")
        return conn, cursor
    except sqlite3.Error as e:
        print_log(f"Database initialization failed: {e}", level="error")
        return None, None

def close_db(conn, cursor):
    """Commits changes and closes the database connection."""
    if conn:
        conn.commit()
        conn.close()

# --- API Routes ---
@app.route('/scanApk', methods=['POST'])
def addApp():
    """Handles APK file uploads for malware scanning."""
    auth_header = request.headers.get("Authorization")
    if not (auth_header and auth_header.startswith("Bearer ")):
        return jsonify({"error": "No JWT Token provided"}), 401
    jwt_token = auth_header.split(" ")[1]
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file part in request'}), 400
    filepath = os.path.join(MALWARE_FOLDER, file.filename)
    file.save(filepath)
    conn, cursor = db_init()
    if not conn:
        return jsonify({'error': 'Database service unavailable'}), 500
    job_id = random.randint(100000, 999999)
    cursor.execute("INSERT INTO data (JOB_ID, JWT_TOKEN, TYPE, INPUT_FILE_PATH, STATUS) VALUES (?, ?, ?, ?, ?)",
                   (job_id, jwt_token, 'Malware', filepath, 'Pending'))
    close_db(conn, cursor)
    print_log(f"New malware scan job created. ID: {job_id}")
    return jsonify({'jobID': job_id}), 201

@app.route('/scanMessage', methods=['POST'])
def addMessage():
    """Handles text message submissions for phishing scanning."""
    auth_header = request.headers.get("Authorization")
    if not (auth_header and auth_header.startswith("Bearer ")):
        return jsonify({"error": "No JWT Token provided"}), 401
    jwt_token = auth_header.split(" ")[1]
    message = request.form.get('message')
    if not message:
        return jsonify({'error': 'No message text provided'}), 400
    job_id = random.randint(100000, 999999)
    filepath = os.path.join(PHISHING_FOLDER, f"message_{job_id}.txt")
    with open(filepath, "w") as f:
        f.write(message)
    conn, cursor = db_init()
    if not conn:
        return jsonify({'error': 'Database service unavailable'}), 500
    cursor.execute("INSERT INTO data (JOB_ID, JWT_TOKEN, TYPE, INPUT_FILE_PATH, STATUS) VALUES (?, ?, ?, ?, ?)",
                   (job_id, jwt_token, 'Phishing', filepath, 'Pending'))
    close_db(conn, cursor)
    print_log(f"New phishing scan job created. ID: {job_id}")
    return jsonify({'jobID': job_id}), 201

@app.route('/scanStatus')
def getJob():
    """Retrieves the status and results of a specific job."""
    job_id = request.args.get('jobID')
    if not job_id:
        return jsonify({"error": "jobID parameter is required"}), 400
    auth_header = request.headers.get("Authorization")
    if not (auth_header and auth_header.startswith("Bearer ")):
        return jsonify({"error": "No JWT Token provided"}), 401
    user_jwt = auth_header.split(" ")[1]
    conn, cursor = db_init()
    if not conn:
        return jsonify({'error': 'Database service unavailable'}), 500
    cursor.execute("SELECT * FROM data WHERE JOB_ID = ?", (job_id,))
    row = cursor.fetchone()
    if not row:
        close_db(conn, cursor)
        return jsonify({"error": "Job not found"}), 404
    db_jwt = row['JWT_TOKEN']
    if user_jwt != db_jwt:
        close_db(conn, cursor)
        return jsonify({'error': 'You are not authorized to access this job'}), 403
    job_details = dict(row)
    close_db(conn, cursor)
    print_log(f"Status for Job ID {job_id} retrieved successfully.")
    return jsonify({'details': job_details}), 200

@app.route('/seeDbs', methods=['GET'])
def seeDbs():
    """Fetches and returns all records from the database."""
    conn, cursor = db_init()
    if not conn:
        return jsonify({"error": "Database service unavailable"}), 500
    
    cursor.execute("SELECT * FROM data ORDER BY JOB_ID DESC")
    rows = cursor.fetchall()
    
    # --- FIX IS HERE ---
    # Convert the list of sqlite3.Row objects into a proper list of dictionaries.
    all_jobs = [dict(row) for row in rows]
    
    close_db(conn, cursor)
    print_log("Database records retrieved via /seeDbs endpoint.")
    return jsonify(all_jobs), 200

if __name__ == '__main__':
    print_log("Starting backend server on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000)