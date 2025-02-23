#routes/url_scan.py
"""
Documentation:

Request:
    Method: POST 
    Endpoint: /url_scan
    Parameters: None required
    Headers: None required

Body:
    Format: JSON
    Example body:
    {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "url": "https://example.com/path"
    }

Response:
    Format: JSON
    Example response:
    {
        "result": {
            "domain_info": {
                "domain_name": "example.com",
                "registrar": "Example Registrar",
                "creation_date": "2020-01-01 00:00",
                "emails": ["admin@example.com"],
                "country": "US"
            },
            "issues": [
                "URL uses non-standard port: 8080"
            ],
            "risk_rating": 2,
            "risk_level": "SAFE",
            "path": "/path",
            "domain": "example.com"
        }
    }
    Note: Risk level will be one of: "SAFE", "CAUTION", or "DANGEROUS"

Example curl command:
    curl -X POST http://localhost:5000/url_scan \
         -H "Content-Type: application/json" \
         -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzcxMTg1NzV9.5rGCXz9mcX-kCxG-5Z4tUNQaGmZrsIcqkJF64EUwE54", "url": "https://example.com/path"}'

Notes:
- The token must be valid (obtained from /get_token endpoint)
- URL must be a valid HTTP/HTTPS URL
- Result includes domain information, security issues found, risk rating (0-10), and risk level
- Domain info may be incomplete if WHOIS lookup fails
- Risk factors include: suspicious TLDs, IP-based URLs, non-standard ports, and suspicious URL patterns

"""


from flask import Blueprint, request, jsonify
from utils.token_validator import validate_token
from urllib.parse import urlparse
import whois
import re

url_scan_blueprint = Blueprint('url_scan', __name__)

def scan_url(url):
    try:
        result_data = {
            "domain_info": {},
            "issues": [],
            "risk_rating": 0,
            "risk_level": "",
            "path": "",
            "domain": ""
        }

        # Parse URL
        try:
            parsed_url = urlparse(url)
            result_data["domain"] = parsed_url.netloc
            result_data["path"] = parsed_url.path if parsed_url.path and parsed_url.path != "/" else "No path specified"
        except Exception as e:
            print(f"[ LOG (url_scan) ]: Error parsing URL: {str(e)}")
            result_data["issues"].append("Invalid URL format")
            return result_data

        # Get domain info
        try:
            domain_info = whois.whois(parsed_url.netloc)
            fields = ["domain_name", "registrar", "registrar_url", "org", "organization", "creation_date", "emails", "dnssec", "country"]
            
            for field in fields:
                try:
                    field_value = domain_info.get(field)
                    if field_value is not None:
                        if field == "creation_date" and isinstance(field_value, list):
                            field_value = [date.strftime("%Y-%m-%d %H:%M") if hasattr(date, 'strftime') else str(date) for date in field_value]
                        result_data["domain_info"][field] = field_value
                except Exception as e:
                    print(f"[ LOG (url_scan) ]: Error processing field {field}: {str(e)}")
                    continue
        except Exception as e:
            print(f"[ LOG (url_scan) ]: Error getting domain info: {str(e)}")
            result_data["issues"].append("Could not retrieve domain information")

        # Check for suspicious patterns
        suspicious_patterns = [
            (r'\.cn$', "Ends with .cn"),
            (r'\.ru$', "Ends with .ru"), 
            (r'\.zip$', "Ends with .zip"),
            (r'@', "Contains @"),
            (r'\/\/.*\/\/', "Contains double slashes"),
            (r'[\w\-\.]+\.tk', "Uses .tk domain"),
            (r'\d{4,}', "Contains long numeric sequence")
        ]

        risk_score = 0
        for pattern, message in suspicious_patterns:
            if re.search(pattern, url):
                result_data["issues"].append(message)
                risk_score += 3

        # Check URL structure
        if re.match(r'^http[s]?:\/\/\d{1,3}(\.\d{1,3}){3}', url):
            result_data["issues"].append("URL uses an IP address instead of a domain name")
            risk_score += 3

        if len(url) > 2083:
            result_data["issues"].append("URL is unusually long")
            risk_score += 1

        if re.search(r':\d+', url):
            try:
                port = int(re.search(r':(\d+)', url).group(1))
                if port not in [80, 443]:
                    result_data["issues"].append(f"URL uses non-standard port: {port}")
                    risk_score += 2
            except Exception as e:
                print(f"[ LOG (url_scan) ]: Error checking port: {str(e)}")

        # Calculate final risk score
        risk_score = max(0, min(10, risk_score))
        result_data["risk_rating"] = risk_score

        if risk_score <= 3:
            result_data["risk_level"] = "SAFE"
        elif risk_score <= 6:
            result_data["risk_level"] = "CAUTION"
        else:
            result_data["risk_level"] = "DANGEROUS"

        return result_data

    except Exception as e:
        print(f"[ LOG (url_scan) ]: Unexpected error in scan_url: {str(e)}")
        return {"error": str(e)}


@url_scan_blueprint.route('/url_scan', methods=['POST'])
def url_scan():
    try:
        data = request.get_json()

        if not data:
            print(f"[ LOG (url_scan) ]: No JSON data provided")
            return jsonify({
                'status': 'error',
                'message': 'No JSON data provided'
            }), 400

        if 'token' not in data or 'url' not in data:
            print(f"[ LOG (url_scan) ]: Token or URL were not found in data")
            response = {
                'status': 'error',
                'message': 'Token and URL are required'
            }
            return jsonify(response), 400

        print(f"[ LOG (url_scan) ]: Data is valid containing token and URL")

        # Validate the token
        if not validate_token(data['token']):
            print(f"[ LOG (url_scan) ]: Token is invalid")
            response = {
                'status': 'error',
                'message': 'Invalid token'
            }
            return jsonify(response), 401

        url = data['url']
        result = scan_url(url)
        return jsonify({'result': result})
    
    except Exception as e:
        print(f"[ LOG (url_scan) ]: Unexpected error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
