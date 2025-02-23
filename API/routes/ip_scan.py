"""
Documentation:

Request:
    Method: POST
    Endpoint: /ip_scan
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "ip_address": "192.168.1.1"
    }

Response:
    Format: JSON
    Example response:
    {
        "result": "safe"
    }
    Note: Result will be either "safe" or "malicious"

Example curl command:
    curl -X POST http://localhost:5000/ip_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzcxMTg1NzV9.5rGCXz9mcX-kCxG-5Z4tUNQaGmZrsIcqkJF64EUwE54", "ip_address": "192.168.1.1"}'

Notes:
- The token must be valid (obtained from /get_token endpoint)
- IP address must be a valid IPv4 address
- Result will indicate if the IP is considered malicious or safe

"""


#routes/ip_scan.py

from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token
import re

ip_scan_blueprint = Blueprint('ip_scan', __name__)

def validate_ipv4(ip):
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(pattern, ip):
        return True
    return False

def scan_ip(ip_address):
    if ip_address == "127.0.0.1":
        return "malicious"
    else:
        return "safe"


@ip_scan_blueprint.route('/ip_scan', methods=['POST'])
def ip_scan():
    try:
        data = request.get_json()
        print(f"[ LOG (ip_scan) ]: Data: {data}")

        if not data:
            print(f"[ LOG (ip_scan) ]: No JSON data provided")
            response = {
                'status': 'error',
                'message': 'No JSON data provided'
            }
            return jsonify(response), 400

        if 'token' not in data or 'ip_address' not in data:
            print(f"[ LOG (ip_scan) ]: Token or IP address was not found in data")
            response = {
                'status': 'error',
                'message': 'Token and IP address are required'
            }
            return jsonify(response), 400

        print(f"[ LOG (ip_scan) ]: Data is valid containing token and IP address")

        # Validate the token
        if not validate_token(data['token']):
            print(f"[ LOG (ip_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'message': 'Invalid token'
            }
            return jsonify(response), 401

        ip_address = data['ip_address']

        if not validate_ipv4(ip_address):
            print(f"[ LOG (ip_scan) ]: IP address is not valid")
            response = {
                'status': 'error',
                'message': 'IP address is not valid'
            }
            return jsonify(response), 400
        
        print(f"[ LOG (ip_scan) ]: IP address is valid")

        result = scan_ip(ip_address)

        response = {
            'result': result
        }

        print(f"[ LOG (ip_scan) ]: Result: {result}")

        return jsonify(response)
    
    except Exception as e:
        print(f"[ LOG (ip_scan) ]: Unexpected error: {str(e)}")
        response = {
            'status': 'error',
            'message': 'Internal server error'
        }
        return jsonify(response), 500