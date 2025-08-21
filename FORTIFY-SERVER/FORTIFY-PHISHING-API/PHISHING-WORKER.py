
# ======================== IMPORTANT NOTICE ========================
#
#                       DO NOT ALTER THIS CODE.
#
# REASON: This script has been customized by the Team Lead to facilitate a
# system integration. Unauthorized modifications are guaranteed
# to cause project-wide failures.
#
# ACTION: Please implement any required functionality in other modules.
#
# ESCALATION: If a change to this file is unavoidable, you must first
# consult with the Team Lead.
#
# ================================================================


# Format : main.py --src <path-to-input.txt> --out <path-to-output-dir> --job_id <id>
# Reads a message from a file and saves the phishing prediction to a JSON file.

import joblib
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

def predict_phishing(input_message, model, vectorizer):
    """Predicts if a message is phishing using the loaded model and vectorizer."""
    input_vector = vectorizer.transform([input_message])
    prediction = model.predict(input_vector)
    return prediction[0]

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

    if not os.path.exists(args.out):
        try:
            os.makedirs(args.out)
            print_log(f"Created output directory: {args.out}")
        except Exception as e:
            print_log(f"Failed to create output directory: {e}", level="error")
            sys.exit(1)

    output_json_path = os.path.join(args.out, f"{args.job_id}.json")

    try:
        model = joblib.load('phishing_detector_model.pkl')
        tfidf = joblib.load('tfidf_vectorizer.pkl')
    except FileNotFoundError as e:
        print_log(f"Model file not found: {e.filename}. Please ensure model files are in the correct directory.", level="error")
        sys.exit(1)

    print_log("Analyzing message...")
    result = predict_phishing(message, model, tfidf)
    prediction_text = 'Not Phishing' if result == 'ham' else 'Phishing'
    print_log(f"Prediction: {prediction_text}")

    output_data = {
        "job_id": args.job_id,
        "detection": prediction_text
    }

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