from flask import Flask, request, jsonify
import joblib

model = joblib.load('phishing_detector_model.pkl')
tfidf = joblib.load('tfidf_vectorizer.pkl')

app = Flask(__name__)

def predict_phishing(input_message):
    input_vector = tfidf.transform([input_message])
    prediction = model.predict(input_vector)
    return prediction[0]

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()  # Get the JSON data from the request
    message = data.get('message')  # Extract the message from the JSON data
    
    if message:
        result = predict_phishing(message)
        return jsonify({'message': message, 'prediction': result}), 200  # Return JSON response
    else:
        return jsonify({'error': 'No message provided'}), 400  # Handle missing message

if __name__ == '__main__':
    try:
        print(flask.__version__)
    except Exception as e:
        print(f"Flask not found {e}")
    app.run(debug=False,host='0.0.0.0',port='5001')


