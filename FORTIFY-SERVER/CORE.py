import subprocess
import time
import os
import sqlite3
import sys
from colorama import Fore, Style, init

init()

def print_log(message, level="info"):
    if level == "info":
        print(f"{Fore.CYAN}[ LambdaCore (-) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "success":
        print(f"{Fore.GREEN}[ LambdaCore (✔) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "warning":
        print(f"{Fore.YELLOW}[ LambdaCore (?) ] {message}{Style.RESET_ALL}", file=sys.stdout)
    elif level == "error":
        print(f"{Fore.RED}[ LambdaCore (!) ] {message}{Style.RESET_ALL}", file=sys.stderr)
    sys.stdout.flush()

def db_init():
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Job_database.db")
    print_log(f"Attempting to connect to database: {db_path}")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print_log("Database connection established.", level="success")
        return conn, cursor
    except sqlite3.Error as error:
        print_log(f"Error Occurred during DB connection: {error}", level="error")
        if "unable to open database file" in str(error).lower():
            print_log("Note: Database file 'Job_database.db' might not exist yet. Ensure FORTIFY-SERVER/server.py has run and initialized it.", level="warning")
        return None, None

def close_db(cursor, conn):
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
            print_log("Connection is closed.", level="info")

def get_pending_jobs():
    conn, cursor = db_init()
    if not conn:
        print_log("Failed to connect to database for polling.", level="error")
        return []
    try:
        print_log("Querying for pending jobs (STATUS = 'Pending').")
        cursor.execute("SELECT JOB_ID, TYPE, INPUT_FILE_PATH, STATUS FROM data WHERE STATUS = 'Pending'")
        pending_jobs = cursor.fetchall()
        return pending_jobs
    except sqlite3.OperationalError as e:
        print_log(f"Database error while fetching pending jobs: {e}", level="error")
        if "no such table: data" in str(e).lower():
            print_log("The 'data' table does not exist in the database. Ensure server.py has run and initialized the database schema.", level="error")
        return []
    except sqlite3.Error as e:
        print_log(f"An unexpected database error occurred: {e}", level="error")
        return []
    finally:
        close_db(cursor, conn)

if __name__ == '__main__':
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    SERVER_PY_PATH = os.path.join(BASE_DIR, 'SERVER.py')
    TEST_PY_PATH = os.path.join(BASE_DIR, 'TEST-WEBSITE', 'TEST.py')

    server_process = None
    test_process = None

    print(f"\n{Fore.MAGENTA}" + "="*60 + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}{'Starting Fortify LambdaCore':^60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}" + "="*60 + Style.RESET_ALL + "\n")

    try:
        print(f"{Fore.CYAN}" + "-"*60 + Style.RESET_ALL)
        print_log(f"Launching Flask server: {SERVER_PY_PATH}")
        server_process = subprocess.Popen(['python', SERVER_PY_PATH], cwd=BASE_DIR)
        print_log(f"Flask server initiated with PID: {server_process.pid}", level="success")
        
        print_log("Allowing server.py time to initialize the database (5 seconds)...")
        time.sleep(3) 
        print(f"{Fore.CYAN}" + "-"*60 + Style.RESET_ALL + "\n")

        print(f"{Fore.CYAN}" + "-"*60 + Style.RESET_ALL)
        print_log(f"Launching test website: {TEST_PY_PATH}")
        test_process = subprocess.Popen(['python', TEST_PY_PATH], cwd=os.path.join(BASE_DIR, 'TEST-WEBSITE'))
        print_log(f"Test website initiated with PID: {test_process.pid}", level="success")
        time.sleep(2)
        print(f"{Fore.CYAN}" + "-"*60 + Style.RESET_ALL + "\n")

        print(f"{Fore.GREEN}" + "="*60 + Style.RESET_ALL)
        print(f"{Fore.GREEN}{'SERVICE URLs':^60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}" + "="*60 + Style.RESET_ALL)
        print(f"{Fore.GREEN}  Fortify Server URL: http://127.0.0.1:5000{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  Test Website URL:   http://127.0.0.1:5001{Style.RESET_ALL}")
        print(f"{Fore.GREEN}" + "="*60 + Style.RESET_ALL + "\n")

        reported_job_ids = set()

        print(f"\n{Fore.BLUE}" + "#"*60 + Style.RESET_ALL)
        print_log("Entering continuous polling loop for new jobs.")
        print_log("Polling interval: 10 seconds. Press Ctrl+C to terminate all services.")
        print(f"{Fore.BLUE}" + "#"*60 + Style.RESET_ALL + "\n")

        while True:
            print(f"{Fore.BLUE}" + "-"*60 + Style.RESET_ALL)
            print_log(f"Polling database for pending jobs at {time.strftime('%Y-%m-%d %H:%M:%S')}")
            current_pending_jobs = get_pending_jobs()

            new_jobs_found_in_this_poll = False
            if current_pending_jobs:
                newly_detected_jobs = [job for job in current_pending_jobs if job[0] not in reported_job_ids]
                
                if newly_detected_jobs:
                    for job in newly_detected_jobs:
                        job_id = job[0]
                        print_log(f"NEW JOB DETECTED: JOB_ID={job_id}, Type='{job[1]}', Input='{job[2]}', Status='{job[3]}'", level="warning")
                        reported_job_ids.add(job_id)
                    new_jobs_found_in_this_poll = True
                else:
                    print_log(f"No *new* pending jobs since last check. {len(current_pending_jobs)} job(s) remain pending.", level="info")
            else:
                print_log("No pending jobs found in the database.", level="info")
            
            print(f"{Fore.BLUE}" + "-"*60 + Style.RESET_ALL + "\n")
            time.sleep(10)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}" + "="*60 + Style.RESET_ALL)
        print_log("Ctrl+C detected. Initiating graceful shutdown...", level="warning")
        print(f"{Fore.RED}" + "="*60 + Style.RESET_ALL + "\n")
    except Exception as e:
        print(f"\n{Fore.RED}" + "!"*60 + Style.RESET_ALL)
        print_log(f"An unexpected critical error occurred: {e}", level="error")
        print(f"{Fore.RED}" + "!"*60 + Style.RESET_ALL + "\n")
    finally:
        if server_process and server_process.poll() is None:
            print_log("Terminating Flask server...", level="info")
            server_process.terminate()
            server_process.wait(timeout=5)
            if server_process.poll() is None:
                print_log("Flask server did not terminate gracefully, forcing kill.", level="error")
                server_process.kill()
            print_log("Flask server stopped.", level="success")
        
        if test_process and test_process.poll() is None:
            print_log("Terminating Test website...", level="info")
            test_process.terminate()
            test_process.wait(timeout=5)
            if test_process.poll() is None:
                print_log("Test website did not terminate gracefully, forcing kill.", level="error")
                test_process.kill()
            print_log("Test website stopped.", level="success")
        
        print(f"\n{Fore.MAGENTA}" + "="*60 + Style.RESET_ALL)
        print(f"{Fore.MAGENTA}{'LambdaCore.py Exited':^60}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}" + "="*60 + Style.RESET_ALL + "\n")