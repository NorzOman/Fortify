#routes/message_scan.py
"""
Documentation:

Request:
    Method: POST
    Endpoint: /message_scan 
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "message": "Hello, please check this message for safety"
    }

Response:
    Format: JSON
    Example response:
    {
        "result": "safe"
    }
    Note: Result will be either "safe" or "malicious"

Example curl command:
    curl -X POST http://localhost:5000/message_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzcxMTg1NzV9.5rGCXz9mcX-kCxG-5Z4tUNQaGmZrsIcqkJF64EUwE54", "message": "Hello, please check this message for safety"}'

Notes:
- The token must be valid (obtained from /get_token endpoint)
- Message cannot be empty
- Result indicates if the message content is considered malicious or safe

"""
from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token

message_scan_blueprint = Blueprint('message_scan', __name__)

def scan_message(message):
    print(f"[ LOG (message_scan) ]: Scanning message: {message}")
    if "free" in message.lower():
        return "malicious"
    return "safe"

@message_scan_blueprint.route('/message_scan', methods=['POST'])
def message_scan():
    try:
        data = request.get_json()
        print(f"[ LOG (message_scan) ]: Got Data: {data}")

        if not data:
            print(f"[ LOG (message_scan) ]: No JSON data provided")
            response = {
                'status': 'error',
                'message': 'No JSON data provided'
            }
            return jsonify(response), 400

        if 'token' not in data or 'message' not in data:
            print(f"[ LOG (message_scan) ]: Token or message were not found in data")
            response = {
                'status': 'error',
                'message': 'Token and message are required'
            }
            return jsonify(response), 400
        
        if not validate_token(data['token']):
            print(f"[ LOG (message_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'message': 'Invalid token'
            }
            return jsonify(response), 401
        
        message = data['message']

        if not message or message.strip() == "":
            print(f"[ LOG (message_scan) ]: Message is empty")
            response = {
                'status': 'error',
                'message': 'Message is required'
            }
            return jsonify(response), 400
        
        result = scan_message(message)
        
        print(f"[ LOG (message_scan) ]: Scan result: {result}")
        return jsonify({'result': result})
    
    except Exception as e:
        print(f"[ LOG (message_scan) ]: Error: {e}")
        response = {
            'status': 'error',
            'message': 'Internal server error'
        }
        return jsonify(response), 500
