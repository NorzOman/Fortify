"""
Documentation:

Request:
    Method: GET
    Endpoint: /get_token
    Parameters: None required
    Headers: None required

Response:
    Format: JSON
    Example response:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }

Example curl command:
    curl -X GET http://localhost:5000/get_token

Note: The token will be valid for 1 hour (3600 seconds)

"""

from flask import Blueprint, request, jsonify
from utils.token_generator import generate_token

get_token_blueprint = Blueprint('get_token', __name__)

@get_token_blueprint.route('/get_token', methods=['GET'])
def get_token():
    token = generate_token(3600)
    if token is None:
        print(f"[ LOG (get_token) ]: Failed to generate token")
        response = {
            'status': 'error',
            'message': 'Failed to generate token'
        }
        return jsonify(response), 500
        
    print(f"[ LOG (get_token) ]: Token sent successfully")
    response = {
        'token': token
    }
    return jsonify(response)
