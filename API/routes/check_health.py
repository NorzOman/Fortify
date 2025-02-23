"""
Documentation:

Request:
    Method: GET
    Endpoint: /check_health
    Parameters: None required
    Headers: None required

Response:
    Format: JSON
    Example response:
    {
        "status": "ok"
    }

Example curl command:
    curl -X GET http://localhost:5000/check_health

"""

from flask import Blueprint, request, jsonify

# Create a blueprint for health checks
check_health_blueprint = Blueprint('check_health', __name__)

@check_health_blueprint.route('/check_health', methods=['GET'])
def health_check():
    response = {
        'status': 'ok'
    }
    return jsonify(response)
