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

# Initializing the app and setting the secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = 'arshad_number_1_also_this_is_uncrackable_secret_key_try_any_wordlists_idc'

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
                    'exp': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)).timestamp()  # Returns JWT token that lasts 5 minutes
                },
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Valid attempt to get token detected", "token": token}), 200  # Returns the client the valid token
        else:
            return jsonify({"message": "Malicious attempt to get token"}), 400
    except Exception as e:
        return jsonify({"error": "Server Side Issue | Report to admin"}), 400


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


# Message detection route
@app.route('/message_detection', methods=['POST'])
def message_detection():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is missing"}), 400  # Return error if token is missing

    if validate_token(token):
        message = data.get('message', '')
        ''' Sample of message detection for testing purpose'''
        if 'free' in message.lower():
            return jsonify({"Report": "Phishing attempt detected"}), 200
        else:
            return jsonify({"message": "Safe SMS | No Phishing attempt detected"}), 200
    else:
        return jsonify({"error": "Invalid or expired token"}), 401


# Malware detection route
@app.route('/malware_detection', methods=['POST'])
def malware_detection():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({"error": "Token is missing"}), 400  # Return error if token is missing

    if validate_token(token):
        signatures = data.get('signatures', [])
        if not signatures:
            return jsonify({"error": "No signatures provided"}), 400  # If no signatures are provided

        try:
            # Loading the signature database
            with open('signatures.json', 'r') as f:
                signature_db = json.load(f).get("signatures", [])
        except Exception as e:
            return jsonify({"error": f"Failed to open signature database {e}"}), 500  # Handle file errors

        # Map signature hashes from the database for fast lookup
        signature_map = {sig['signature']: sig for sig in signature_db}

        results = []
        for input_signature in signatures:
            match = signature_map.get(input_signature)
            if match:
                results.append({
                    "input_signature": input_signature,
                    "generic_name": match['generic_name'],
                    "generic_detection": match['generic_detection']
                })
            else:
                results.append({
                    "input_signature": input_signature,
                    "result": "No match found"
                })

        return jsonify({"status": "completed", "results": results}), 200  # Return matching results

    else:
        return jsonify({"error": "Invalid or expired token"}), 401  # If token is invalid or expired


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
