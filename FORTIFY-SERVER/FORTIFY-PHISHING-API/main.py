# Format : main.py --message <message-goes-here>
# Returns output of whether the message is phishing or not

import joblib
import sys
import warnings

# Supress warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

model = joblib.load('phishing_detector_model.pkl')
tfidf = joblib.load('tfidf_vectorizer.pkl')

def predict_phishing(input_message):
    input_vector = tfidf.transform([input_message])
    prediction = model.predict(input_vector)
    return prediction[0]

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--message":
        print("Usage: main.py --message <message-goes-here>")
        sys.exit(1)

    message = sys.argv[2]
    result = predict_phishing(message)
    print(f"Result: {'Phishing' if result == 1 else 'Not phishing'}")
