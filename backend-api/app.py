# ⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
# ⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾
# ⠘⢿⣿⣿⣿⣿⣦⣀⣀⣀⣄⣀⣀⣠⣀⣤⣶⣿⣿⣿⣿⣿
# ⠀⠈⠻⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋
# ⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠋⠀⠀
# ⠀⠀⢠⣿⣿⡏⠆⢹⣿⣿⣿⣿⣿⣿⠒⠈⣿⣿⣿⣇⠀⠀
# ⠀⠀⣼⣿⣿⣷⣶⣿⣿⣛⣻⣿⣿⣿⣶⣾⣿⣿⣿⣿⡀⠀
# ⠀⠀⡁⠀⠈⣿⣿⣿⣿⢟⣛⡻⣿⣿⣿⣟⠀⠀⠈⣿⡇⠀
# ⠀⠀⢿⣶⣿⣿⣿⣿⣿⡻⣿⡿⣿⣿⣿⣿⣶⣶⣾⣿⣿⠀
# ⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆


# Imports for handling Flask-related stuff
from flask import Flask, request, jsonify, render_template , session , redirect , url_for , g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os


# Initializing the app and setting the secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Imports for handling AES encryption and decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import base64


# Imports for token making and related tasks
import jwt
import json
import datetime
import time

# Imports for reading the signatures from the database of hashes
import sqlite3


# Setting up logging
import logging
logs_file_path = os.path.join(app.root_path, 'static', 'logs.txt')
logging.basicConfig(filename=logs_file_path, level=logging.INFO, format='%(message)s - %(asctime)s')


#Setting up alerts
alerts_file_path = os.path.join(app.root_path, 'static', 'alerts.txt')

# Setting up allowlist and blocklist
allowlist_file_path = os.path.join(app.root_path, 'static', 'IP_allowlist.txt')
blocklist_file_path = os.path.join(app.root_path, 'static', 'IP_blocklist.txt')


# Setting up USERS.json for access key handling
requests_file_path = os.path.join(app.root_path, 'static', 'requests.json')

# Initializing the database
# ---------------------------------------------------------------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(120), nullable=True)
    message_api_calls = db.Column(db.Integer, nullable=True)
    file_api_calls = db.Column(db.Integer, nullable=True)
    threats_detected = db.Column(db.Integer, nullable=True)
    api_key_requested = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"User('{self.email}', '{self.api_key}', '{self.message_api_calls}', '{self.file_api_calls}', '{self.threats_detected}')"

with app.app_context():
    db.create_all()




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


def is_ip_blocked(ip_address):
    if os.path.exists(blocklist_file_path):
        with open(blocklist_file_path, 'r') as f:
            blocklist = [ip.strip() for ip in f.readlines()]
            return ip_address in blocklist
    return False


# Function searches through database with MD5 signatures
def check_malicious_signatures(signatures):
    db_path = 'signaturesdb.sqlite'
    
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
            "name": name
        })

    return json.dumps(malicious_hashes, indent=4)


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

    # Log suspicious access attempts
    if '/login' in g.request_path or '/dashboard' in g.request_path:
        with open(alerts_file_path, 'a') as f:
            f.write(f"[ suspicious ] {g.client_ip} tried to access {g.request_path} at {g.timestamp}\n")

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
@app.route('/docs', methods=['GET'])
def docs():
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


# [ DASHBOARD ] Alerts route
@app.route('/api/v1/dev/alerts', methods=['GET', 'DELETE'])
def alerts():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Admin privileges required."}), 403

    if request.method == 'GET':
        with open(allowlist_file_path, 'r') as f:
            allowed_ips = [ip.strip() for ip in f.readlines()]

        with open(alerts_file_path, 'r') as file:
            alerts_data = file.readlines()
            filtered_alerts = []
            for alert in alerts_data:
                alert = alert.strip()
                if alert:
                    ip_start = alert.find(']') + 2
                    ip_end = alert.find('tried') - 1
                    if ip_start > 0 and ip_end > 0:
                        ip = alert[ip_start:ip_end]
                        if ip not in allowed_ips:
                            filtered_alerts.append(alert)

        return jsonify({"alerts": filtered_alerts}), 200

    elif request.method == 'DELETE':
        with open(alerts_file_path, 'w') as file:
            file.truncate(0)

        return jsonify({"message": "Alerts cleared successfully."}), 200


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

# [ DASHBOARD ] Allowlist route
@app.route('/api/v1/dev/allowlist', methods=['GET','POST','DELETE'])
def allowlist():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Please log in."}), 403

    if request.method == 'GET':
        with open(allowlist_file_path, 'r') as file:
            allowlist_data = file.readlines()
        return jsonify({"allowlist": allowlist_data}), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        ip_address = data.get('ip_address')
        with open(allowlist_file_path, 'a') as file:
            file.write(ip_address + '\n')
        return jsonify({"message": "IP address added successfully"}), 200

    elif request.method == 'DELETE':
        data = request.get_json()
        ip_address = data.get('ip_address').strip()  # Strip whitespace/newlines

        with open(allowlist_file_path, 'r') as file:
            allowlist_data = file.readlines()        

        updated_allowlist = [ip.strip() for ip in allowlist_data if ip.strip() != ip_address]
 
        with open(allowlist_file_path, 'w') as file:
            file.write('\n'.join(updated_allowlist) + '\n')

        return jsonify({"message": f"IP address removed successfully"}), 200

# [ DASHBOARD ] Blocklist route
@app.route('/api/v1/dev/blocklist', methods=['GET','POST','DELETE'])
def blocklist():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Please log in."}), 403

    if request.method == 'GET':
        with open(blocklist_file_path, 'r') as file:
            blocklist_data = file.readlines()
        return jsonify({"blocklist": blocklist_data}), 200

    elif request.method == 'POST':
        data = request.get_json()
        ip_address = data.get('ip_address')
        with open(blocklist_file_path, 'a') as file:
            file.write(ip_address + '\n')
        return jsonify({"message": "IP address added successfully"}), 200

    elif request.method == 'DELETE':
        data = request.get_json()
        ip_address = data.get('ip_address').strip() 
        with open(blocklist_file_path, 'r') as file:
            blocklist_data = file.readlines()

        updated_blocklist = [ip.strip() for ip in blocklist_data if ip.strip() != ip_address]

        with open(blocklist_file_path, 'w') as file:
            file.write('\n'.join(updated_blocklist) + '\n')

        return jsonify({"message": f"IP address {ip_address} removed successfully"}), 200


# [ DASHBOARD ] Token Requests route
@app.route('/api/v1/dev/pending_requests', methods=['GET', 'POST', 'DELETE'])
def pending_requests():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized access. Please log in."}), 403

    if request.method == 'GET':
        with open(requests_file_path, 'r') as file:
            requests_data = json.load(file)
        return jsonify({"requests": requests_data}), 200

    elif request.method == 'POST':
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

        return jsonify({"message": "Token request accepted and email request removed successfully."}), 200
    
    elif request.method == 'DELETE':
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


  

# ------------------------------------------------------------------------------------------------------------------------------



# DASHBOARD RELATED STUFFS
# ------------------------------------------------------------------------------------------------------------------------------

# Handle login
@app.route('/dev/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == './admin' and password == 'Engineer$@987':
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
    return redirect('/dev/login')

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
    return render_template('home.html')

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

        return redirect('/user/myaccount')

    return render_template('user_register.html')


@app.route('/user/login',methods=['GET','POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('user_myaccount'))
        else:
            return render_template('user_login.html', error='Invalid email or password')
            
    return render_template('user_login.html')


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
    return redirect('/user/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True,port=5000)


