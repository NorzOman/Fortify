# routes/token_generator.py

"""
Documentation:
    This file is used to generate a token for a given expiration time
"""

import jwt
import datetime
from flask import current_app


def generate_token(expiration_time):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration_time)
        }
        token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        print(f"[ LOG (token_generator) ]: Token generated successfully")
        return token
    except Exception as e:
        print(f"[ LOG (token_generator) ]: Failed to generate token | Caught exception: {e}")
        return None