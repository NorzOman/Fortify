#routes/token_validator.py

import jwt
import datetime
from flask import current_app

def validate_token(token):
    try:
        jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        print(f"[ LOG (token_validator) ]: Token was found to be valid")
        return True
    except jwt.ExpiredSignatureError:
        print(f"[ LOG (token_validator) ]: Token was found to be expired")
        return False
    except jwt.InvalidTokenError:
        print(f"[ LOG (token_validator) ]: Token was found to be invalid")
        return False
