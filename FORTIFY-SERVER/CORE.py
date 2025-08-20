import subprocess
import time
import os
import sqlite3
import sys
import json
from colorama import Fore, Style, init

# Initialize color for logs
init()

# --- Configuration ---
# Set the absolute path to your JADX executable here. This is required for the malware scanner.
JADX_EXECUTABLE_PATH = "/usr/local/bin/jadx" 


def print_log(message, level="info"):
    """Prints a log message with the core's standard format."""
    prefix = "> ( core ) ::"
    if level == "error":
        print(f"{Fore.RED}{prefix} {message}{Style.RESET_ALL}", file=sys.stderr)
    elif level == "warning":
        print(f"{Fore.YELLOW}{prefix} {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "success":
         print(f"{Fore.GREEN}{prefix} {message}{Style.RESET_ALL}", file=sys.stdout)
    else:
        print(f"{prefix} {message}", file=sys.stdout)
    sys.stdout.flush()

def get_oldest_pending_job():
    """Connects to the DB and fetches the single oldest job with a 'Pending' status."""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Job_database.db")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT JOB_ID, TYPE, INPUT_FILE_PATH FROM data WHERE STATUS = 'Pending' ORDER BY JOB_ID LIMIT 1")
        return cursor.fetchone()
    except sqlite3.Error:
        return None
    finally:
        if conn:
            conn.close()

def update_job_in_db(job_id, output_path, detection_result):
    """Updates a job's status to 'Done' and records the output."""
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Job_database.db")
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE data SET STATUS = ?, OUTPUT_FILE_PATH = ?, DETECTION = ? WHERE JOB_ID = ?",
                       ('Done', output_path, detection_result, job_id))
        conn.commit()
    except sqlite3.Error as e:
        print_log(f"Failed to update database for job {job_id}: {e}", level="error")
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = os.path.join(BASE_DIR, 'OUTPUT')
    
    MALWARE_WORKER_DIR = os.path.join(BASE_DIR, 'FORTIFY-MALWARE-API')
    PHISHING_WORKER_DIR = os.path.join(BASE_DIR, 'FORTIFY-PHISHING-API')
    
    MALWARE_WORKER_PATH = os.path.join(MALWARE_WORKER_DIR, 'MALWARE-WORKER.py')
    PHISHING_WORKER_PATH = os.path.join(PHISHING_WORKER_DIR, 'PHISHING-WORKER.py')
    
    SERVER_PY_PATH = os.path.join(BASE_DIR, 'SERVER.py')
    TEST_WEBSITE_DIR = os.path.join(BASE_DIR, 'TEST-WEBSITE')
    TEST_PY_PATH = os.path.join(TEST_WEBSITE_DIR, 'TEST.py')

    server_process = None
    test_process = None

    print_log("Initializing LambdaCore...")

    try:
        # --- Spawn Services ---
        print_log("Spawning services:")
        print_log(" |")
        print_log(" +-- Spawning backend server (SERVER.py)...")
        server_process = subprocess.Popen(['python3', SERVER_PY_PATH], cwd=BASE_DIR)
        time.sleep(3)

        print_log(" |")
        print_log(" +-- Spawning frontend server (TEST.py)...")
        test_process = subprocess.Popen(['python3', TEST_PY_PATH], cwd=TEST_WEBSITE_DIR)
        time.sleep(2)
        print_log(" |")

        print_log("Services are now running:")
        print_log(" > Backend API:   http://127.0.0.1:5000")
        print_log(" > Frontend App:  http://127.0.0.1:5001")
        print_log("")

        print_log("Starting main dispatcher loop... (Press Ctrl+C to exit)")
        
        # --- Main Dispatcher Loop ---
        while True:
            job = get_oldest_pending_job()

            if job:
                job_id, job_type, input_path = job
                command = []
                worker_cwd = None # <--- ADDED: Variable for current working directory
                
                print_log(f"New job detected: ID={job_id}. Assigning to '{job_type}' worker...", level="warning")

                if job_type == 'Malware':
                    command = ['python3', MALWARE_WORKER_PATH, '--src', input_path, '--out', OUTPUT_DIR, '--jadx_path', JADX_EXECUTABLE_PATH, '--job_id', str(job_id)]
                    worker_cwd = MALWARE_WORKER_DIR # <--- FIX: Set CWD for this worker
                elif job_type == 'Phishing':
                    command = ['python3', PHISHING_WORKER_PATH, '--src', input_path, '--out', OUTPUT_DIR, '--job_id', str(job_id)]
                    worker_cwd = PHISHING_WORKER_DIR # <--- FIX: Set CWD for this worker

                # --- Execute Worker ---
                if command:
                    try:
                        # --- FIX: Added the cwd argument to the subprocess call ---
                        result = subprocess.run(command, check=True, capture_output=True, text=True, cwd=worker_cwd)
                        
                        output_json_path = os.path.join(OUTPUT_DIR, f"{job_id}.json")
                        detection_result = "Scan Error"
                        
                        if os.path.exists(output_json_path):
                            with open(output_json_path, 'r') as f:
                                result_data = json.load(f)
                                if job_type == 'Phishing':
                                    detection_result = result_data.get('detection', 'N/A')
                                elif job_type == 'Malware':
                                    summary = result_data.get('summary', {})
                                    total_detections = summary.get('total_detections', 0)
                                    detection_result = f"{total_detections} Detections"
                        
                        update_job_in_db(job_id, output_json_path, detection_result)
                        print_log(f"Job {job_id} completed successfully. Result: {detection_result}", level="success")

                    except subprocess.CalledProcessError as e:
                        print_log(f"Worker for job {job_id} failed.", level="error")
                        # Print both stdout and stderr for better debugging
                        if e.stdout:
                            print_log(f"--> Stdout: {e.stdout.strip()}", level="error")
                        if e.stderr:
                            print_log(f"--> Stderr: {e.stderr.strip()}", level="error")
                
            else:
                time.sleep(5)

    except KeyboardInterrupt:
        print_log("\nShutdown signal received. Terminating services...", level="warning")
    except Exception as e:
        print_log(f"A critical error occurred: {e}", level="error")
    finally:
        if server_process:
            print_log("Terminating backend server...")
            server_process.terminate()
            server_process.wait(timeout=5)
        if test_process:
            print_log("Terminating frontend server...")
            test_process.terminate()
            test_process.wait(timeout=5)
        
        print_log("LambdaCore has shut down.")