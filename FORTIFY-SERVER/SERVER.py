from flask import Flask, request, jsonify
import os
import sqlite3
import random
import sys
import logging
from colorama import Fore, Style, init

init()

app = Flask(__name__)

DEBUG_MODE = False

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_FOLDER = os.path.join(BASE_DIR,'INPUTS')
MALWARE_FOLDER = os.path.join(UPLOADS_FOLDER,'MALWARE')
PHISHING_FOLDER = os.path.join(UPLOADS_FOLDER,'MESSAGE')
OUTPUT_FOLDER = os.path.join(BASE_DIR,'OUTPUT')

def print_log(message, level="info"):
    if level == "info":
        print(f"{Fore.CYAN}[ server (-) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "success":
        print(f"{Fore.GREEN}[ server (✔) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "warning":
        print(f"{Fore.YELLOW}[ server (?) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "error":
        print(f"{Fore.RED}[ server (!) ] {message}{Style.RESET_ALL}", file=sys.stderr)
    sys.stdout.flush()

print_log(f"Ensuring directory: {UPLOADS_FOLDER}")
os.makedirs(UPLOADS_FOLDER, exist_ok=True)
print_log(f"Ensuring directory: {MALWARE_FOLDER}")
os.makedirs(MALWARE_FOLDER, exist_ok=True)
print_log(f"Ensuring directory: {PHISHING_FOLDER}")
os.makedirs(PHISHING_FOLDER, exist_ok=True)
print_log(f"Ensuring directory: {OUTPUT_FOLDER}")
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
print_log("All necessary directories are set up.", level="success")

def id_gen():
    print_log("Running command: id_gen")
    return random.randint(100000,999999)

def print_all_data(cursor):
    print_log("Running command: print_all_data (SELECT *)")
    res = cursor.execute("SELECT * FROM data")
    return res

def delete_data(cursor):
    print_log("Running command: delete_data (DELETE FROM data)")
    cursor.execute("DELETE FROM data")

def insert_data(cursor,id,token,type,input_path,status,output_path,confidence,detection):
    print_log("Running command: insert_data (INSERT INTO data)")
    cursor.execute("INSERT INTO data VALUES (?, ?, ?, ?, ?, ?, ?, ?)",(id, token, type, input_path, status, output_path, confidence, detection))

def db_init():
    print_log("Running command: db_init")
    try:
        conn = sqlite3.connect("Job_database.db")
        cursor = conn.cursor()

        print_log("Executing SQL: CREATE TABLE IF NOT EXISTS data...")
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
            ) """)
        print_log("Database initialized successfully.", level="success")
        return conn, cursor
    except sqlite3.Error as error:
        print_log(f"Error Occurred during DB initialization: {error}", level="error")
        return None, None

def close_db(cursor,conn):
    print_log("Running command: close_db")
    try:
        if conn:
            conn.commit()
            print_log("Database changes committed.")
        if cursor:
            cursor.close()
            print_log("Cursor closed.")
    except sqlite3.Error as error:
        print_log(f"Error Occurred during DB close: {error}", level="error")
    finally:
        if conn:
            conn.close()
            print_log("Connection is closed", level="info")

@app.route('/scanApk',methods=['POST'])
def addApp():
    print_log("Running command: addApp (POST /scanApk)")
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.split(" ")[1]
        print_log("JWT Token extracted.")
    else:
        print_log("No JWT Token sent or invalid format.", level="warning")
        return {"error": "No JWT Token send"}, 401

    if 'file' not in request.files:
        print_log("No 'file' part in the request.", level="error")
        return jsonify({'Error':'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        print_log("No file uploaded (empty filename).", level="error")
        return jsonify({'Error':'No file uploaded'}), 400
    
    filepath = os.path.join(MALWARE_FOLDER, file.filename)
    try:
        file.save(filepath)
        print_log(f"File saved to: {filepath}", level="success")
    except Exception as e:
        print_log(f"Error saving file: {e}", level="error")
        return jsonify({'Error': 'Failed to save file'}), 500
    
    conn,cursor = db_init()
    if not conn:
        return jsonify({'Error': 'Database connection failed'}), 500
    
    id = id_gen()
    insert_data(cursor,id,jwt_token,'Malware',filepath,'Pending','/output/report.pdf',60,None)
    print_log(f"Inserted new malware job with ID: {id}", level="info")
    
    print_log("Current database entries:", level="info")
    for i in print_all_data(cursor):
        print_log(f"DB entry: {i}")
    
    close_db(cursor,conn)
    print_log(f"Job {id} submitted successfully.", level="success")
    return jsonify({'jobID':id}), 201    


@app.route('/scanMessage',methods=['POST'])
def addMessage():
    print_log("Running command: addMessage (POST /scanMessage)")
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        jwt_token = auth_header.split(" ")[1]
        print_log("JWT Token extracted.")
    else:
        print_log("No JWT Token sent or invalid format.", level="warning")
        return {"error": "No JWT Token send"}, 401

    id = id_gen()

    msg = request.form.get('message')
    if not msg:
        print_log("No 'message' field in form data.", level="error")
        return jsonify({'Error': 'No message provided'}), 400

    filepath = os.path.join(PHISHING_FOLDER,f"message_{id}.txt")    
    try:
        with open(filepath, "w") as f:
            f.write(msg)
        print_log(f"Message saved to: {filepath}", level="success")
    except Exception as e:
        print_log(f"Error saving message to file: {e}", level="error")
        return jsonify({'Error': 'Failed to save message'}), 500

    conn,cursor = db_init()
    if not conn:
        return jsonify({'Error': 'Database connection failed'}), 500

    insert_data(cursor,id,jwt_token,'Phishing',filepath,'Pending','/output/report.pdf',60,None)
    print_log(f"Inserted new phishing job with ID: {id}", level="info")
    
    print_log("Current database entries:", level="info")
    for i in print_all_data(cursor):
        print_log(f"DB entry: {i}")
    
    close_db(cursor,conn)
    print_log(f"Job {id} submitted successfully.", level="success")
    return jsonify({'jobID':id}), 201 

@app.route('/scanStatus')
def getJob():
    conn,cursor = db_init()
    if not conn:
        return jsonify({'Error': 'Database connection failed'}), 500

    job_id = request.args.get('jobID')
    if not job_id:
        print_log("No 'jobID' parameter provided in the request.", level="warning")
        close_db(cursor, conn)
        return {"error": "No jobID parameter send"}, 400
    
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        user_jwt_token = auth_header.split(" ")[1]
    else:
        print_log("No JWT Token sent or invalid format.", level="warning")
        close_db(cursor, conn)
        return {"error": "No JWT Token send"}, 401
    
    try:
        cursor.execute("SELECT * FROM data WHERE JOB_ID = ?", (job_id,))
        row = cursor.fetchone()
        
        if row:
            data = {
                "JOB_ID": row[0],
                "JWT_TOKEN": row[1],
                "TYPE": row[2],
                "INPUT_FILE_PATH": row[3],
                "STATUS": row[4],
                "OUTPUT_FILE_PATH": row[5],
                "CONFIDENCE": row[6],
                "DETECTION": row[7]
            }
        else:
            print_log(f"Job with ID {job_id} not found.", level="warning")
            close_db(cursor, conn)
            return {"error": "Job not found"}, 404

        if user_jwt_token == row[1]:
            return{'details':data}
        else:
            print_log(f"Unauthorized access attempt for job {job_id}. JWT token mismatch.", level="error")
            return{'error': 'You cannot access this Job'}, 403
    except sqlite3.Error as e:
        print_log(f"Database error while fetching job {job_id}: {e}", level="error")
        return {"error": "Internal database error"}, 500
    finally:
        close_db(cursor,conn)

if __name__ == '__main__':
    print_log(f"Starting Flask application in debug mode: {DEBUG_MODE}", level="info")
    app.run(debug=DEBUG_MODE)