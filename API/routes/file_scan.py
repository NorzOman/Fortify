"""
Documentation:

Request:
    Method: POST
    Endpoint: /file_scan
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "hashes": [["filename1", "md5:0987654321"], ["filename2", "md5:0987654321"],....]
    }

Response:
    Format: JSON
    Example response:
    {
        "result": [["filename1", "md5:0987654321", "malware_name"], ...]
    }
    Note: An empty result array ([]) indicates that all scanned files are safe

Example curl command:
    curl -X POST http://localhost:5000/file_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzcxMTg1NzV9.5rGCXz9mcX-kCxG-5Z4tUNQaGmZrsIcqkJF64EUwE54", "hashes": [["file1.txt", "md5:123..."]]}'

Notes:
- The token must be valid (obtained from /get_token endpoint)
- The hashes array should contain arrays with filename and hash pairs
- Hash format should be "algorithm:hash" (currently only md5 supported)
- An empty result array means all scanned files were found to be safe

"""

from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token
import sqlite3
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(current_dir, "..", "data", "md5_hashes.sqlite")
file_scan_blueprint = Blueprint('file_scan', __name__)


def scan_hashes(hashes):
    print(f"[ LOG (file_scan) ]: Scanning hashes : {hashes}")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        results = []
        for filename, hash_value in hashes:
            if not isinstance(hash_value, str) or ':' not in hash_value:
                continue
            hash_type, hash_only = hash_value.split(':')
            if hash_type != 'md5':
                continue
            cursor.execute("SELECT name FROM HashDB WHERE hash = ?", (hash_only,))
            row = cursor.fetchone()
            if row:
                results.append((filename, hash_value, row[0]))

        conn.close()
        print(f"[ LOG (file_scan) ]: Scanning hashes completed successfully")
        return results
    except Exception as e:
        print(f"[ LOG (file_scan) ]: Error scanning hashes: {e}")
        return None


@file_scan_blueprint.route('/file_scan', methods=['POST'])
def file_scan():
    try:
        data = request.get_json()
        
        if not data:
            print(f"[ LOG (file_scan) ]: No JSON data provided")
            response = {
                'status': 'error',
                'message': 'No JSON data provided'
            }
            return jsonify(response), 400

        if 'token' not in data or 'hashes' not in data or not isinstance(data['hashes'], list):
            print(f"[ LOG (file_scan) ]: Token or hashes were not found in data or invalid format")
            response = {
                'status': 'error',
                'message': 'Token and hashes are required. Hashes must be a list.'
            }
            return jsonify(response), 400
        
        print(f"[ LOG (file_scan) ]: Data is valid containing token and hashes")

        # Validate the token
        if not validate_token(data['token']):
            print(f"[ LOG (file_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'message': 'Invalid token'
            }
            return jsonify(response), 401

        hashes = data['hashes']
        result = scan_hashes(hashes)
        print(f"[ LOG (file_scan) ]: Result: {result}")
        
        if result is None:
            print(f"[ LOG (file_scan) ]: Error scanning hashes")
            response = {
                'status': 'error',
                'message': 'Error scanning hashes'
            }
            return jsonify(response), 500

        return jsonify({'result': result})

    except Exception as e:
        print(f"[ LOG (file_scan) ]: Unexpected error: {str(e)}")
        response = {
            'status': 'error',
            'message': 'Internal server error'
        }
        return jsonify(response), 500