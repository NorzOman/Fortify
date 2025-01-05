#  __      __         _ _              ______ 
#  \ \    / /        | | |            |____  |
#   \ \  / /_ _ _   _| | |_   ______      / / 
#    \ \/ / _` | | | | | __| |______|    / /  
#     \  / (_| | |_| | | |_             / /   
#      \/ \__,_|\__,_|_|\__|           /_/    
                                            
# ---------------------------------------------------------------------------------------------------------------------------


# Flask-related imports
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for,
    g,
    send_file
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Cryptography imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Standard library imports
import os
import json
import time
import base64
import hashlib
import datetime
import requests

# JWT import
import jwt

# Initialize Flask app
app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = 'arshad_is_the_secret'  # todo : os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)



# Setting up paths:
# ---------------------------------------------------------------------------------------------------------------------------

alerts_file_path = os.path.join(app.root_path, 'static', 'alerts.txt')
allowlist_file_path = os.path.join(app.root_path, 'static', 'IP_allowlist.txt')
blocklist_file_path = os.path.join(app.root_path, 'static', 'IP_blocklist.txt')
requests_file_path = os.path.join(app.root_path, 'static', 'requests.json')
base_url = 'http://127.0.0.1:5000'

# ---------------------------------------------------------------------------------------------------------------------------



# Setting up logging
# ---------------------------------------------------------------------------------------------------------------------------

import logging

logs_file_path = os.path.join(app.root_path, 'static', 'logs.txt')
logging.basicConfig(filename=logs_file_path, level=logging.INFO, format='%(message)s - %(asctime)s')

# ---------------------------------------------------------------------------------------------------------------------------



# Initializing the database
# ---------------------------------------------------------------------------------------------------------------------------

import sqlite3

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(120), nullable=True)
    message_api_calls = db.Column(db.Integer, nullable=True, default=0)
    file_api_calls = db.Column(db.Integer, nullable=True, default=0) 
    threats_detected = db.Column(db.Integer, nullable=True, default=0)
    api_key_requested = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User('{self.email}', '{self.api_key}', '{self.message_api_calls}', '{self.file_api_calls}', '{self.threats_detected}')"

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------------------------------------------------------



# FUNCTIONS NEEDED OVERALL STUFFS
# ---------------------------------------------------------------------------------------------------------------------------


# Function that pushes system alert logs in case of system errors
def push_system_alert(message,category):
    try:
        with open(alerts_file_path, 'a') as f:
            f.write(f"[ {category} ] : {message}\n")
    except Exception as e:
        print(f"Failed to write system alert: {str(e)}")


# Function used to validate the token
def validate_token(token):
    if not token:   # If not token, return false
        return False

    try: # Test if the token is expired , if not return true
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        exp_time = decoded_token.get('exp')
        if exp_time and exp_time < datetime.datetime.now(datetime.timezone.utc).timestamp():
            return False
        return True
    except jwt.ExpiredSignatureError: # If expired, return false
        return False
    except jwt.InvalidTokenError: # If invalid, return false
        return False


# Function used to check if the IP is blocked
def is_ip_blocked(ip_address):
    if os.path.exists(blocklist_file_path):
        try:
            with open(blocklist_file_path, 'r') as f:
                blocklist = [ip.strip() for ip in f.readlines()]
                if ip_address in blocklist:
                    return True
                return False
        except Exception as e:
            push_system_alert(f"Error reading blocklist file: {e}", "failed")
            return True
    else:
        push_system_alert(f"Blocklist file does not exist", "failed")
        return True


# Function used to check if the signatures are malicious
def check_malicious_signatures(signatures):
    try:
        db_path = 'signatures1db.sqlite'
        
        # Input validation - ensure signatures contains valid MD5 hashes
        if not all(isinstance(sig, (list, tuple)) and len(sig) == 2 and 
                  isinstance(sig[1], str) and len(sig[1]) == 32 and 
                  all(c in '0123456789abcdefABCDEF' for c in sig[1])
                  for sig in signatures):
            return json.dumps({"error": "Invalid signature format"})

        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Extract hashes and use parameterized query
        hashes = [signature[1] for signature in signatures]
        placeholders = ','.join('?' * len(hashes))
        query = "SELECT hash, name FROM HashDB WHERE hash IN ({})".format(placeholders)

        # Execute with parameters to prevent SQL injection
        cursor.execute(query, hashes)
        result = cursor.fetchall()
        conn.close()

        malicious_hashes = []
        for row in result:
            hash_value, name = row
            file_name = next(file_name for file_name, file_hash in signatures if file_hash == hash_value)
            malicious_hashes.append({
                "file_name": file_name,
                "hash": hash_value, 
                "name": name,
            })

        if not malicious_hashes:
            return json.dumps({"status": "all-safe"}, indent=4)
        
        return json.dumps(malicious_hashes, indent=4)

    except sqlite3.Error as e:
        error_msg = f"Database error while checking signatures: {str(e)}"
        push_system_alert(error_msg, "failed")
        return json.dumps({"error": "There was an issue on our side, please try again later"})
    
    except Exception as e:
        error_msg = f"Error checking malicious signatures: {str(e)}"
        push_system_alert(error_msg, "failed")
        return json.dumps({"error": "There was an issue on our side, please try again later"})

# ---------------------------------------------------------------------------------------------------------------------------



# BEFORE AND AFTER REQUEST FOR LOGGING RELATED STUFFS
# ---------------------------------------------------------------------------------------------------------------------------

# Before request logging
@app.before_request
def log_request_info():
    g.client_ip = request.remote_addr
    g.request_path = request.path
    g.timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    if is_ip_blocked(g.client_ip):
        return render_template('403.html'), 403


# After request logging 
@app.after_request
def after_request(response):
    app.logger.info(f"[LOG] [{g.timestamp}] IP {g.client_ip}"
                    f" tried to access {g.request_path} and received status {response.status_code} ")
    response.headers['X-Processed-By'] = 'Vault - 7'
    response.headers['X-Endpoint'] = request.endpoint
    return response


# Error handler for 404 errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# ---------------------------------------------------------------------------------------------------------------------------





# API ENDPOINTS RELATED STUFFS
# ------------------------------------------------------------------------------------------------------------------------------


# Root route leads to API documentation
@app.route('/api/v1/dev/docs', methods=['GET'])
def docs():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return render_template('403.html'), 403
    
    return render_template('docs.html')


# Route returns client IP with 200 OK message to note API is active
@app.route('/api/v1/check_health', methods=['GET'])
def check_health():
    try:
        client_ip = request.remote_addr
        response_data = {
            "status": "Server is running OK",
            "client_ip": client_ip
        }
        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": "Internal server error | Report to admin with error code: #HEALTH-001"}), 500


# Route returns a token that can be used for SMS phishing detection
@app.route('/api/v1/get_token_for_message', methods=['POST'])
def get_token_for_message():
    try:
        try:
            data = request.get_json()
            if 'device_guid' not in data:
                return jsonify({"error": "Missing device_guid"}), 400    
        except Exception as e:
            return jsonify({"error": "Invalid request data | Report to admin with error code: #DATA-001"}), 400

        # Get client IP and device GUID
        try:
            client_ip = request.remote_addr
            device_guid = data.get('device_guid')
        except Exception as e:
            return jsonify({"error": "Error processing your IP address | Report to admin with error code: #IP-001"}), 403

        # Generate encryption key and cipher
        try:
            key = hashlib.sha256(client_ip.encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_ip = base64.b64decode(device_guid)
            decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
        except Exception as e:
            return jsonify({"error": "Server side issue | Report to admin with error code: #AES-001"}), 500

        # Validate decrypted IP matches client IP
        if decrypted_ip != client_ip:
            push_system_alert(f"Malicious token attempt from IP: {client_ip}", "suspicious")
            return jsonify({"error": "Malicious attempt to get token | If you think this is a mistake, report to admin with error code: #MAL-001"}), 400

        # Generate JWT token
        try:
            token = jwt.encode(
                {
                    'client_ip': client_ip,
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).timestamp()
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200
        except Exception as e:
            return jsonify({"error": "Server side issue | Report to admin with error code: #JWT-001"}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error | Report to admin with error code: #GTFM-001"}), 500


# Route returns a token that can be used for malware detection
@app.route('/api/v1/get_token_for_files', methods=['POST'])
def get_token_for_files():
    try:
        try:
            data = request.get_json()
            if 'device_guid' not in data:
                return jsonify({"error": "Missing device_guid"}), 400    
        except Exception as e:
            return jsonify({"error": "Invalid request data | Report to admin with error code: #DATA-002"}), 400

        # Get client IP and device GUID
        try:
            client_ip = request.remote_addr
            device_guid = data.get('device_guid')
        except Exception as e:
            return jsonify({"error": "Error processing your IP address | Report to admin with error code: #IP-002"}), 403

        # Generate encryption key and cipher
        try:
            key = hashlib.sha256(client_ip.encode()).digest()[:16]
            cipher = AES.new(key, AES.MODE_ECB)
            encrypted_ip = base64.b64decode(device_guid)
            decrypted_ip = unpad(cipher.decrypt(encrypted_ip), AES.block_size).decode('utf-8')
        except Exception as e:
            return jsonify({"error": "Server side issue | Report to admin with error code: #AES-002"}), 500

        # Validate decrypted IP matches client IP
        if decrypted_ip != client_ip:
            push_system_alert(f"Malicious token attempt from IP: {client_ip}", "suspicious")
            return jsonify({"error": "Malicious attempt to get token | If you think this is a mistake, report to admin with error code: #MAL-002"}), 400

        # Generate JWT token
        try:
            token = jwt.encode(
                {
                    'client_ip': client_ip,
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).timestamp()
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200
        except Exception as e:
            return jsonify({"error": "Server side issue | Report to admin with error code: #JWT-002"}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error | Report to admin with error code: #GTFF-001"}), 500


# Message detection route
@app.route('/api/v1/message_detection', methods=['POST'])
def message_detection():
    try:
        # Get and validate request data
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid request data"}), 400
        except Exception as e:
            return jsonify({"error": "Error processing request data | Report to admin with error code: #DATA-003"}), 400

        # Check token exists and is valid
        try:
            token = data.get('token')
            if not token:
                return jsonify({"error": "Token is missing"}), 400
            if not validate_token(token):
                return jsonify({"error": "Invalid or expired token"}), 403
        except Exception as e:
            return jsonify({"error": "Error validating token | Report to admin with error code: #TOKEN-001"}), 403

        # Process message and check for phishing
        try:
            message = data.get('message', '')
            if 'free' in message.lower():
                return jsonify({"Report": "Phishing attempt detected"}), 200
            else:
                return jsonify({"message": "Safe SMS | No Phishing attempt detected"}), 200
        except Exception as e:
            return jsonify({"error": "Error processing message | Report to admin with error code: #MSG-001"}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error | Report to admin with error code: #MSGD-001"}), 500


# Malware detection route
@app.route('/api/v1/malware_detection', methods=['POST'])
def malware_detection():
    try:
        # Get and validate request data
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "Invalid request data"}), 400
        except Exception as e:
            return jsonify({"error": "Error processing request data | Report to admin with error code: #DATA-004"}), 400

        # Check token exists and is valid
        try:
            token = data.get('token')
            if not token:
                return jsonify({"error": "Token is missing"}), 400
            if not validate_token(token):
                return jsonify({"error": "Invalid or expired token"}), 403
        except Exception as e:
            return jsonify({"error": "Error validating token | Report to admin with error code: #TOKEN-002"}), 403

        # Process signatures and check for malware
        try:
            signatures = data.get('signatures', [])
            if not signatures:
                return jsonify({"error": "No signatures provided"}), 400
                
            malicious_signatures_json = check_malicious_signatures(signatures)
            return jsonify(json.loads(malicious_signatures_json)), 200
            
        except Exception as e:
            return jsonify({"error": "Error processing signatures | Report to admin with error code: #SIG-001"}), 500

    except Exception as e:
        return jsonify({"error": "Internal server error | Report to admin with error code: #MALD-001"}), 500


# [ DASHBOARD ] Alerts route
@app.route('/api/v1/dev/alerts', methods=['GET', 'DELETE'])
def alerts():
    try:
        if not session.get('logged_in') or session.get('username') != 'admin':
            return jsonify({"error": "Unauthorized access. Admin privileges required."}), 403

        if request.method == 'GET':
            try:
                with open(alerts_file_path, 'r') as file:
                    alerts_data = [alert.strip() for alert in file.readlines() if alert.strip()]
                return jsonify({"alerts": alerts_data}), 200
            except Exception as e:
                return jsonify({"error": f"Error reading alerts file: {str(e)}"}), 500

        elif request.method == 'DELETE':
            try:
                with open(alerts_file_path, 'w') as file:
                    file.truncate(0)
                return jsonify({"message": "Alerts cleared successfully."}), 200
            except Exception as e:
                return jsonify({"error": f"Error clearing alerts file: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# [ DASHBOARD ] Logs route
@app.route('/api/v1/dev/logs', methods=['GET', 'DELETE'])
def logs():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Please log in."}), 403

    if request.method == 'GET':
        try:
            with open(logs_file_path, 'r') as file:
                logs_data = file.readlines()
            filtered_logs = [log.strip() for log in logs_data if log.startswith('[LOG]')]
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


# [ DASHBOARD ] Firewall Blocklist route
@app.route('/api/v1/dev/blocklist', methods=['GET','POST','DELETE'])
def blocklist():
    try:
        if not session.get('logged_in') or session.get('username') != 'admin':
            return jsonify({"error": "Unauthorized access. Please log in."}), 403

        if request.method == 'GET':
            try:
                with open(blocklist_file_path, 'r') as file:
                    blocklist_data = file.readlines()
                return jsonify({"blocklist": blocklist_data}), 200
            except Exception as e:
                return jsonify({"error": f"Error reading blocklist: {str(e)}"}), 500

        elif request.method == 'POST':
            try:
                data = request.get_json()
                ip_address = data.get('ip_address')
                if not ip_address:
                    return jsonify({"error": "IP address is required"}), 400
                    
                with open(blocklist_file_path, 'a') as file:
                    file.write(ip_address + '\n')
                return jsonify({"message": "IP address added successfully"}), 200
            except Exception as e:
                return jsonify({"error": f"Error adding IP to blocklist: {str(e)}"}), 500

        elif request.method == 'DELETE':
            try:
                data = request.get_json()
                ip_address = data.get('ip_address')
                if not ip_address:
                    return jsonify({"error": "IP address was not supplied"}), 400
                    
                ip_address = ip_address.strip()
                with open(blocklist_file_path, 'r') as file:
                    blocklist_data = file.readlines()

                updated_blocklist = [ip.strip() for ip in blocklist_data if ip.strip() != ip_address]

                with open(blocklist_file_path, 'w') as file:
                    file.write('\n'.join(updated_blocklist) + '\n')

                return jsonify({"message": f"IP address {ip_address} removed successfully"}), 200
            except Exception as e:
                return jsonify({"error": f"Error removing IP from blocklist: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# [ DASHBOARD ] Token Requests route
@app.route('/api/v1/dev/pending_requests', methods=['GET', 'POST', 'DELETE'])
def pending_requests():
    try:
        if not session.get('logged_in') or session.get('username') != 'admin':
            return jsonify({"error": "Unauthorized access. Please log in."}), 403

        if request.method == 'GET':
            try:
                with open(requests_file_path, 'r') as file:
                    requests_data = json.load(file)
                return jsonify({"requests": requests_data}), 200
            except Exception as e:
                return jsonify({"error": f"Error reading requests data: {str(e)}"}), 500

        elif request.method == 'POST':
            try:
                # Get the email from the incoming JSON data
                data = request.get_json()
                email = data.get('email')

                # If email is not provided, return an error
                if not email:
                    return jsonify({"error": "Missing email in request data."}), 400

                # Generate a token with a 30-day expiry
                token = jwt.encode(
                    {
                        'email': email,
                        'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).timestamp()
                    },
                    app.config['SECRET_KEY'],
                    algorithm='HS256'
                )

                user = User.query.filter_by(email=email).first()
                user.api_key = token
                db.session.commit()

                # Open the requests_file_path and remove the json for that email since the request was reviewed
                with open(requests_file_path, 'r') as file:
                    requests_data = json.load(file)
                if email in requests_data:
                    del requests_data[email]
                with open(requests_file_path, 'w') as file:
                    json.dump(requests_data, file, indent=4)

                return jsonify({"message": "Token request accepted successfully."}), 200
            except Exception as e:
                return jsonify({"error": f"Error processing token request: {str(e)}"}), 500
        
        elif request.method == 'DELETE':
            try:
                data = request.get_json()
                email = data.get('email', '').strip()
                if not email:
                    return jsonify({"error": "Email is required."}), 400

                with open(requests_file_path, 'r') as file:
                    requests_data = json.load(file)

                if email not in requests_data:
                    return jsonify({"error": "Email not found in requests."}), 404

                del requests_data[email]
                with open(requests_file_path, 'w') as file:
                    json.dump(requests_data, file, indent=4)

                return jsonify({"message": "Email removed successfully."}), 200
            except Exception as e:
                return jsonify({"error": f"Error removing email request: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


# ------------------------------------------------------------------------------------------------------------------------------



# DASHBOARD RELATED STUFFS
# ------------------------------------------------------------------------------------------------------------------------------

# Handle login
@app.route('/dev/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin' and password == 'admin':
            session['logged_in'] = True
            session['username'] = 'admin'
            return redirect('/dev/dashboard/home')
        else:
            return render_template('login.html',error='Incident will be reported')
    return render_template('login.html')

# Handle logout
@app.route('/dev/logout',methods=['GET'])
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/')

@app.route('/dev/dashboard',methods=['GET'])
def dashboard():
    return redirect('/dev/dashboard/home')

# Handle dashboard home
@app.route('/dev/dashboard/home',methods=['GET'])
def dashboard_home():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect('/dev/login')

    return render_template('dashboard_home.html')

# Handle dashboard logs
@app.route('/dev/dashboard/logs',methods=['GET'])
def dashboard_logs():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect('/dev/login')

    return render_template('dashboard_logs.html')

# Handle dashboard firewall
@app.route('/dev/dashboard/firewall',methods=['GET'])
def dashboard_firewall():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect('/dev/login')
            
    return render_template('dashboard_firewall.html')

# Handle dashboard manage token
@app.route('/dev/dashboard/token_request',methods=['GET'])
def dashboard_token_request():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect('/dev/login')
            
    return render_template('dashboard_token_request.html')

# ------------------------------------------------------------------------------------------------------------------------------


# End User Related Routes
# ------------------------------------------------------------------------------------------------------------------------------

@app.route('/',methods=['GET'])
def home():
    if 'logged_in' not in session or not session['logged_in']:
        return render_template('home.html',status="not logged in")
    return render_template('home.html',status="logged in")

@app.route('/services',methods=['GET'])
def services():
    if 'logged_in' not in session or not session['logged_in']:
        return render_template('services.html',status="not logged in")
    return render_template('services.html',status="logged in")

@app.route('/user/register',methods=['GET','POST'])
def user_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('user_register.html',error='Passwords do not match')

        # Check if the email already exists
        if User.query.filter_by(email=email).first():
            return render_template('user_register.html',error='Email already exists')

        # Create the hashed password
        hashed_password = generate_password_hash(password,method='pbkdf2:sha256')

        # Create the user with default values for API fields
        user = User(
            email=email,
            password=hashed_password,
            api_key=None,
            message_api_calls=0,
            file_api_calls=0, 
            threats_detected=0,
            api_key_requested=False
        )
        
        db.session.add(user)
        db.session.commit()

        session['logged_in'] = True
        session['email'] = email
        session['api_key'] = None

        return redirect('/user/myaccount')

    return render_template('user_register.html')


@app.route('/user/login',methods=['GET','POST'])
def user_login():
    message = request.args.get('message', '')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['email'] = email
            if user.api_key:
                session['api_key'] = user.api_key
            return redirect(url_for('user_myaccount'))
        else:
            return render_template('user_login.html', error='Invalid email or password')
            
    return render_template('user_login.html',error=message)


@app.route('/user/request_api_key',methods=['POST'])
def user_request_api_key():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('user_login'))

    email = session['email']
    user = User.query.filter_by(email=email).first()
    user.api_key_requested = True
    db.session.commit()

    # Get request details
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Load existing requests
    with open(requests_file_path, 'r') as f:
        requests_data = json.load(f)

    # Add new request
    requests_data[email] = {
        'email': email,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'timestamp': timestamp
    }

    # Save updated requests
    with open(requests_file_path, 'w') as f:
        json.dump(requests_data, f, indent=4)

    return redirect('/user/myaccount')

    
@app.route('/user/myaccount',methods=['GET'])
def user_myaccount():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect('/user/login')

    email = session['email']
    user = User.query.filter_by(email=email).first()
    return render_template('myaccount.html', user=user)


@app.route('/user/logout',methods=['GET'])
def user_logout():
    session.pop('logged_in', None)
    session.pop('email', None)
    return redirect('/')

@app.route('/user/download_app', methods=['GET'])
def download_app():
    return send_file('static/Fortify.apk', as_attachment=True)

@app.route('/user/portal', methods=['GET', 'POST'])
def portal():
    # First check if they are logged in or not 
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('user_login', message="Please log in to access the portal."))

    email = session['email']
    user = User.query.filter_by(email=email).first()

    # Check if the user has an API key
    if not user.api_key:
        return render_template('portal.html', message="[!] API key not found")

    return render_template('portal.html')


@app.route('/user/portal/filescan',methods=['GET','POST'])
def user_portal_file_scan():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('user_login', message="Please log in to access the portal."))

    email = session['email']
    user = User.query.filter_by(email=email).first()
    token = user.api_key

    if request.method == 'POST':
        file = request.files.get('file')
        
        if not file:
            return jsonify({"error": "No file received"}), 400

        if not token:
            return jsonify({"error": "No token received"}), 400

        # First we find the md5 hash of the file
        file_contents = file.read()
        md5_hash = hashlib.md5(file_contents).hexdigest()
        
        # Format signature as [filename, hash] tuple
        filename = file.filename
        signature = [[filename,md5_hash]]

        user.file_api_calls += 1
        db.session.commit()
        
        # Then we send the signature and token to the backend
        try:
            response = requests.post(f'{base_url}/api/v1/malware_detection', json={
                'token': token,
                'signatures': signature
            })
            response.raise_for_status()
            return response.json(), 200
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"API request failed: {str(e)}"}), 500

    return render_template('user_portal_file_scan.html')


@app.route('/user/portal/urlscan',methods=['GET','POST'])
def user_portal_url_scan():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('user_login', message="Please log in to access the portal."))

    email = session['email']
    user = User.query.filter_by(email=email).first()
    token = user.api_key

    if request.method == 'POST':
        url = request.json.get('url')
        
        if not url:  # Better empty check
            return jsonify({"error": "No URL received"}), 400

        # Increment API call counter
        user.message_api_calls += 1
        db.session.commit()

        # Basic URL validation and security check
        # TODO: Replace with actual API call when available
        if not url.startswith(('https://')):
            return jsonify({
                'website_name': url,
                'status': 'warning',
                'type': 'insecure',
                'details': 'URL lacks HTTPS security certificate'
            }), 200
            
        return jsonify({
            'website_name': url,
            'status': 'success', 
            'type': 'secure',
            'details': 'Website uses HTTPS encryption'
        }), 200
        
    return render_template('user_portal_url_scan.html')

@app.route('/user/portal/ipscan',methods=['GET','POST'])
def user_portal_ip_scan():
    return render_template('user_portal_ip_scan.html')

@app.route('/user/portal/report',methods=['GET','POST'])
def user_portal_report():
    return render_template('user_portal_report.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True,port=5000)


