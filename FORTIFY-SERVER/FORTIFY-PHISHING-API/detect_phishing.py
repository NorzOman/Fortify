import requests

# RUN THE MAIN.PY FILE FIRST 

APP_URL = 'http://127.0.0.1:5000/predict'

def test_predict_phishing(msg):
    payload = {'text': msg}
    response = requests.post(APP_URL, json=payload)
    print('Status Code:', response.status_code)
    print('Response:', response.json())


msg = "Neal lost his idcard, donate  neal 2000$ immediatly"

test_predict_phishing(msg)
