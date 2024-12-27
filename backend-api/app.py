# Imports for handling Flask-related stuff
from flask import Flask, request, jsonify, render_template , session , redirect , url_for
# Initializing the app and setting the secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = 'arshad_number_1_also_this_is_uncrackable_secret_key_try_any_wordlists_idc'


# Imports for handling AES encryption and decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import base64


# Imports for token making and related tasks
import jwt
import json
import datetime
import os


# Imports for reading the signatures from the database of hashes
import sqlite3


# Setting up logging
import logging
logs_file_path = os.path.join(app.root_path, 'static', 'logs.txt')
logging.basicConfig(filename=logs_file_path, level=logging.INFO, format='%(message)s - %(asctime)s ')


#Setting up alerts
alerts_file_path = os.path.join(app.root_path, 'static', 'alerts.txt')


# BEFORE AND AFTER REQUEST FOR LOGGING RELATED STUFFS
# ---------------------------------------------------------------------------------------------------------------------------

@app.before_request
def log_request_info():
    pass

@app.after_request
def after_request(response):
    response.headers['X-Processed-By'] = 'Vault - 7'
    response.headers['X-Endpoint'] = request.endpoint
    app.logger.info(f"Response Status: {response.status} | Response Length: {len(response.data)} | Endpoint: {request.endpoint} | IP: {request.remote_addr}")
    return response

# ---------------------------------------------------------------------------------------------------------------------------



# FUNCTIONS NEEDED OVERALL STUFFS
# ---------------------------------------------------------------------------------------------------------------------------

# Token validation function
def validate_token(token):
    try:
        # Decode and validate the token
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

        # Check if the token is expired
        if 'exp' in decoded_token:
            exp_time = datetime.datetime.fromtimestamp(decoded_token['exp'], tz=datetime.timezone.utc)
            if exp_time < datetime.datetime.now(datetime.timezone.utc):
                return False
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


# Function searches through database with MD5 signatures
def check_malicious_signatures(signatures):
    db_path = 'signaturesdb.sqlite'
    
    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    hashes = [signature[1] for signature in signatures]
    placeholders = ', '.join(['?'] * len(hashes))
    query = f"SELECT hash, name FROM HashDB WHERE hash IN ({placeholders})"

    cursor.execute(query, hashes)
    result = cursor.fetchall()
    conn.close()

    malicious_hashes = []

    for row in result:
        hash_value, name = row
        file_name = next(file_name for file_name, file_hash in signatures if file_hash == hash_value)
        malicious_hashes.append({"file_name": file_name, "hash": hash_value, "name": name})

    return json.dumps(malicious_hashes, indent=4)

# ---------------------------------------------------------------------------------------------------------------------------



# API ENDPOINTS RELATED STUFFS
# ------------------------------------------------------------------------------------------------------------------------------

# Root route leads to API documentation
@app.route('/', methods=['GET'])
def home():
    return render_template('docs.html')

# Route returns client IP with 200 OK message to note API is active
@app.route('/api/v1/check_health', methods=['GET'])
def check_health():
    client_ip = request.remote_addr
    response_data = {
        "status": "Server is running OK",
        "client_ip": client_ip
    }
    return jsonify(response_data), 200

# Route returns a token that can be used for SMS phishing detection
@app.route('/api/v1/get_token_for_message', methods=['POST'])
def get_token_for_message():
    data = request.get_json()
    if 'device_guid' not in data:
        return jsonify({"error": "Missing device_guid"}), 400    

    # Get the client IP
    client_ip = request.remote_addr

    # Get the device GUID from the POST request, guid is made from encrypted client IP
    device_guid = data.get('device_guid')

    # Set client IP as the key
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)

    # Try to decrypt the key to validate the get token attempt
    try:
        encrypted_ip = base64.b64decode(device_guid)
        decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
        # If the decrypted thing matches the client IP: token request validated for that IP
        if decrypted_ip == client_ip:
            token = jwt.encode(
                {
                    'client_ip': client_ip,
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).timestamp()
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200
        else:
            return jsonify({"message": "Malicious attempt to get token"}), 400
    except Exception as e:
        return jsonify({"error": "Server Side Issue | Report to admin"}), 400

# Route returns a token that can be used for malware detection
@app.route('/api/v1/get_token_for_files', methods=['POST'])
def get_token_for_files():
    data = request.get_json()
    if 'device_guid' not in data:
        return jsonify({"error": "Missing device_guid"}), 400    

    # Get the client IP
    client_ip = request.remote_addr

    # Get the device GUID from the POST request, guid is made from encrypted client IP
    device_guid = data.get('device_guid')

    # Set client IP as the key
    key = hashlib.sha256(client_ip.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)

    # Try to decrypt the key to validate the get token attempt
    try:
        encrypted_ip = base64.b64decode(device_guid)
        decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
        # If the decrypted thing matches the client IP: token request validated for that IP
        if decrypted_ip == client_ip:
            token = jwt.encode(
                {
                    'client_ip': client_ip,
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).timestamp()
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200
        else:
            return jsonify({"message": "Malicious attempt to get token"}), 400
    except Exception as e:
        return jsonify({"error": "Server Side Issue | Report to admin"}), 400

# Message detection route
@app.route('/api/v1/message_detection', methods=['POST'])
def message_detection():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is missing"}), 400

    if not validate_token(token):
        return jsonify({"error": "Invalid token"}), 403

    message = data.get('message', '')
    if 'free' in message.lower():
        return jsonify({"Report": "Phishing attempt detected"}), 200
    else:
        return jsonify({"message": "Safe SMS | No Phishing attempt detected"}), 200

# Malware detection route
@app.route('/api/v1/malware_detection', methods=['POST'])
def malware_detection():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is missing"}), 400

    if not validate_token(token):
        return jsonify({"error": "Invalid token"}), 403

    signatures = data.get('signatures', [])
    
    if not signatures:
        return jsonify({"error": "No signatures provided"}), 400

    malicious_signatures_json = check_malicious_signatures(signatures)

    return jsonify(json.loads(malicious_signatures_json))


@app.route('/api/v1/dev/alerts', methods=['GET','DELETE'])
def alerts():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized access. Please log in."}), 403
    if session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Admin privileges required."}), 403
 
    if request.method == 'GET':
        with open(alerts_file_path, 'r') as file:
            alerts_data = file.readlines()
            alerts_data = [alert.strip() for alert in alerts_data if alert.strip()]

        return jsonify({"alerts": alerts_data}), 200
    
    elif request.method == 'DELETE':
        with open(alerts_file_path, 'w') as file:
            file.truncate(0)

@app.route('/api/v1/dev/logs', methods=['GET', 'DELETE'])
def logs():
    if not session.get('logged_in'):
        return jsonify({"error": "Unauthorized access. Please log in."}), 403
    if session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Admin privileges required."}), 403

    if request.method == 'GET':
        try:
            with open(logs_file_path, 'r') as file:
                logs_data = file.readlines()
            filtered_logs = [log.strip() for log in logs_data if log.startswith(('IP', 'Response'))]
            return jsonify({"logs": filtered_logs}), 200

        except Exception as e:
            return jsonify({"error": f"An error occurred while reading logs: {str(e)}"}), 500

    elif request.method == 'DELETE':
        try:
            with open(logs_file_path, 'w') as file:
                file.truncate(0)
            return jsonify({"success": True, "message": "Logs cleared successfully!"}), 200

        except Exception as e:
            return jsonify({"error": f"An error occurred while clearing the logs: {str(e)}"}), 500


@app.route('/api/v1/dev/blocklist', methods=['GET'])

# ------------------------------------------------------------------------------------------------------------------------------



# DASHBOARD RELATED STUFFS
# ------------------------------------------------------------------------------------------------------------------------------
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == './admin' and password == 'Engineer$@987':
            session['logged_in'] = True
            session['username'] = 'admin'
            return redirect(url_for('dashboard_home'))
        else:
            return render_template('login.html',error='Incident will be reported')
    return render_template('login.html')

@app.route('/logout',methods=['GET'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard/home',methods=['GET'])
def dashboard_home():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect(url_for('login'))
    return render_template('dashboard_home.html')

@app.route('/dashboard/logs',methods=['GET'])
def dashboard_logs():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect(url_for('login'))
    return render_template('dashboard_logs.html')

# ------------------------------------------------------------------------------------------------------------------------------




if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True,port=5000)
