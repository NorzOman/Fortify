
# Phishing Detection Script - Python ML Task ( Raahim )

## Objective

Create a single Python script (`detect_phishing.py`) that loads a **custom-trained machine learning model** to analyze a text message for phishing indicators. The script must be a self-contained command-line tool.

---

## Core Requirements

1.  **Input:** The script must accept a single text message as a string argument.
2.  **ML-Powered Processing:**
    *   Load and utilize your own pre-trained machine learning model (e.g., Random Forest, SVM, LSTM) for prediction.
    *   **Strictly no external AI APIs or wrapper libraries** (like OpenAI, Gemini, etc.) are permitted. The entire prediction logic must run locally.
3.  **Structured Output:** The script must print a clear, structured analysis to the console, including:
    *   A final **detection** result (e.g., "Phishing Detected" or "Safe").
    *   A **confidence score** (from 0.0 to 1.0) representing the model's certainty.
    *   A list of specific **flags** or features that strongly influenced the model's decision.

---

## Example Usage

**When running the script from the command line, the interaction should be as follows:**

**Input Command:**
```bash
python detect_phishing.py --message "URGENT: Your account has been locked due to suspicious activity. Click http://bit.ly/2sD4fG to verify now."
```

**Expected Console Output:**
```
Detection: Phishing Detected
Confidence: 0.92
Flags:
- Contains a URL shortener
- Uses words creating urgency
- Mentions a security issue ("account has been locked")
```

---

## Implementation Notes

-   **Custom Machine Learning Model:** You are responsible for training the classification model that this script will use. The script should be designed to load the saved model file (e.g., a `.pkl` or `.h5` file) at runtime.
-   **No API, Just a Script:** The final deliverable is a single, executable Python file. It is not a web API.
-   **Feature Extraction:** The script must contain the same feature extraction logic used during the model's training to process the raw input message before feeding it to the model.
-   **Generating Flags:** The "flags" can be derived either from the most important features the model used for its prediction or from a secondary rule-based check that runs alongside the model.