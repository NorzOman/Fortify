import requests

# RUN THE MAIN.PY FILE FIRST 

APP_URL = 'http://localhost:5001/predict'

def test_predict_phishing(msg):
    payload = {'message': msg}
    response = requests.post(APP_URL, json=payload)
    print('Status Code:', response.status_code)
    print('Response:', response.json())


msg = "Congratulations! You've been selected to win a $1,000 gift card for Walmart! Click the link below to claim your prize: [malicious link]"

test_predict_phishing(msg)
