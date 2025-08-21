import pickle
from flask import Flask, request, jsonify

# Initialize the Flask application
app = Flask(__name__)

# --- Load the Trained Model and Vectorizer ---
# These are loaded only once when the application starts.
print("Loading model and vectorizer...")
with open('model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

with open('vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)
print("Model and vectorizer loaded successfully.")

# Define the prediction function
def predict_smishing(message):
    """
    Predicts if a message is 'ham' or 'smishing'.
    """
    # Use the loaded vectorizer to transform the message
    message_tfidf = vectorizer.transform([message])
    
    # Use the loaded model to make a prediction
    prediction_num = model.predict(message_tfidf)[0]
    
    # Get the probabilities
    probabilities = model.predict_proba(message_tfidf)[0]
    
    # Map numerical prediction back to a label
    label = 'ham' if prediction_num == 0 else 'smishing'
    confidence = probabilities[prediction_num]
    
    return {
        'prediction': label,
        'confidence': float(confidence)
    }

# --- Define the API Endpoint ---
@app.route('/predict', methods=['POST'])
def predict():
    # Check if the request contains JSON data
    if not request.json or 'text' not in request.json:
        return jsonify({'error': 'Request must be a JSON with a "text" key'}), 400
        
    # Get the text from the JSON request
    text_message = request.json['text']
    
    # Get the prediction
    result = predict_smishing(text_message)
    
    # Return the result as JSON
    return jsonify(result)

# --- Run the Flask App ---
if __name__ == '__main__':
    # Use host='0.0.0.0' to make the app accessible from your network
    app.run(host='0.0.0.0', port=5000, debug=True)