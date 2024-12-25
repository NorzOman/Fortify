# Imports for handling Flask-related stuff
from flask import Flask, request, jsonify, render_template , redirect , url_for

# Imports for handling AES encryption and decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import base64

# Imports for token making and related tasks
import jwt
import json
import datetime

# Imports for reading the signatures from the database of hashes
import sqlite3

# Initializing the app and setting the secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = 'arshad_number_1_also_this_is_uncrackable_secret_key_try_any_wordlists_idc'


# Token validation function
def validate_token(token):
    try:
        # Decode and validate the token
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

        # Check if the token is expired
        if 'exp' in decoded_token:
            exp_time = datetime.datetime.fromtimestamp(decoded_token['exp'], tz=datetime.timezone.utc)
            if exp_time < datetime.datetime.now(datetime.timezone.utc):
                return False  # Token is expired
        return True  # Token is valid
    except jwt.ExpiredSignatureError:
        return False  # Token is expired
    except jwt.InvalidTokenError:
        return False  # Token is invalid


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


# Root route leads to API documentation
@app.route('/', methods=['GET'])
def home():
    return render_template('docs.html')


# Route returns client IP with 200 OK message to note API is active
@app.route('/check_health', methods=['GET'])
def check_health():
    client_ip = request.remote_addr
    response_data = {
        "status": "Server is running OK",
        "client_ip": client_ip
    }
    return jsonify(response_data), 200


# Route returns a token that can be used for SMS phishing detection
@app.route('/get_token_for_message', methods=['POST'])
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
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).timestamp()  # Returns JWT token that lasts 1 minute
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200  # Returns the client the valid token
        else:
            return jsonify({"message": "Malicious attempt to get token"}), 400
    except Exception as e:
        return jsonify({"error": "Server Side Issue | Report to admin"}), 400


# Route returns a token that can be used for malware detection
@app.route('/get_token_for_files', methods=['POST'])
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
@app.route('/message_detection', methods=['POST'])
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
@app.route('/malware_detection', methods=['POST'])
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
