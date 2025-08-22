import pickle  # Changed from joblib for loading models
import sys
import argparse
import warnings
import os
import json
from colorama import Fore, Style, init

# Initialize colorama
init()

# Suppress scikit-learn version warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

def print_log(message, level="info"):
    prefix = "> ( ps ) ::"
    if level == "error":
        print(f"\t{Fore.RED}{prefix} {message}{Style.RESET_ALL}")
    else:
        print(f"\t{prefix} {message}")
    sys.stdout.flush()

# --- Define the prediction function (adapted from friend's script) ---
# This function now takes the loaded model and vectorizer as arguments,
# and calculates confidence as per your friend's script.
def predict_message_type(message, model_obj, vectorizer_obj):
    """
    Predicts if a message is 'ham' or 'smishing' and returns confidence.
    """
    # Use the loaded vectorizer to transform the message
    message_tfidf = vectorizer_obj.transform([message])
    
    # Use the loaded model to make a prediction
    prediction_num = model_obj.predict(message_tfidf)[0]
    
    # Get the probabilities
    # model.predict_proba is used to get the confidence scores for each class
    probabilities = model_obj.predict_proba(message_tfidf)[0]
    
    # Map numerical prediction back to a label
    # Assuming 0 corresponds to 'ham' (not malicious) and 1 to 'smishing' (malicious)
    label = 'ham' if prediction_num == 0 else 'smishing'
    confidence = probabilities[prediction_num]
    
    return {
        'prediction_label_internal': label, # Internal label ('ham' or 'smishing')
        'confidence': float(confidence)
    }

def main():
    parser = argparse.ArgumentParser(description="Phishing Scanner")
    parser.add_argument("--src", required=True, help="Path to the input text file.")
    parser.add_argument("--out", required=True, help="Path to the output directory for the result JSON.")
    parser.add_argument("--job_id", required=True, help="A unique job ID for this scan.")
    args = parser.parse_args()

    print_log(f"Started job id: {args.job_id}")

    # --- Input File Handling ---
    if not os.path.exists(args.src):
        print_log(f"Input file not found: {args.src}", level="error")
        sys.exit(1)
    
    try:
        with open(args.src, 'r', encoding='utf-8') as f:
            message = f.read()
        print_log(f"Read message from: {args.src}")
    except Exception as e:
        print_log(f"Failed to read input file: {e}", level="error")
        sys.exit(1)

    # --- Output Directory Handling ---
    if not os.path.exists(args.out):
        try:
            os.makedirs(args.out)
            print_log(f"Created output directory: {args.out}")
        except Exception as e:
            print_log(f"Failed to create output directory: {e}", level="error")
            sys.exit(1)

    output_json_path = os.path.join(args.out, f"{args.job_id}.json")

    # --- Load Model and Vectorizer ---
    model = None
    vectorizer = None
    try:
        # Model and vectorizer are now loaded using pickle, matching your friend's script
        print_log("Loading model and vectorizer...")
        with open('model.pkl', 'rb') as model_file:
            model = pickle.load(model_file)
        with open('vectorizer.pkl', 'rb') as vectorizer_file:
            vectorizer = pickle.load(vectorizer_file)
        print_log("Model and vectorizer loaded successfully.")
    except FileNotFoundError as e:
        print_log(f"Model file not found: {e.filename}. Please ensure model files ('model.pkl', 'vectorizer.pkl') are in the correct directory.", level="error")
        sys.exit(1)
    except Exception as e:
        print_log(f"Failed to load model or vectorizer: {e}", level="error")
        sys.exit(1)

    print_log("Analyzing message...")
    # Call the new prediction function which returns the label and confidence
    prediction_result = predict_message_type(message, model, vectorizer)
    
    # Map friend's internal prediction label ('ham'/'smishing') to your desired output ('Not Phishing'/'Phishing')
    detection_text = 'Not Phishing' if prediction_result['prediction_label_internal'] == 'ham' else 'Phishing'
    
    print_log(f"Prediction: {detection_text} (Confidence: {prediction_result['confidence']:.4f})")

    # Prepare output data including job_id, detection, and the new confidence score
    output_data = {
        "job_id": args.job_id,
        "detection": detection_text,
        "confidence": prediction_result['confidence'] # Added confidence from friend's script
    }

    # --- Save Results ---
    try:
        with open(output_json_path, 'w', encoding='utf-8') as outfile:
            json.dump(output_data, outfile, indent=4)
        print_log(f"Results saved to: {output_json_path}")
    except Exception as e:
        print_log(f"Failed to write output JSON: {e}", level="error")
        sys.exit(1)

    print_log(f"Completed job id: {args.job_id}")

if __name__ == "__main__":
    main()