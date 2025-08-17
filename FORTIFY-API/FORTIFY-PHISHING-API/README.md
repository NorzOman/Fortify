
# Mobile Phishing & Malware Detection API - Phishing API Task ( Raahim )

## Overview
This API suite analyzes messages and APK files for phishing using **custom-built machine learning models**.  
No external AI APIs or pre-trained models are used. All ML is implemented locally from scratch.

---

## 1. Message Phishing Detection API

### Endpoint: `/detect`
- **Method:** POST  
- **Description:** Analyze a text message for phishing.  
- **Request Body Example:**
```json
{
  "message": "Your account has been compromised. Click here to reset password.",
  "metadata": {
    "source": "sms",
    "sender": "unknown",
    "timestamp": "2025-08-17T12:34:56Z"
  }
}
```

- **Response Example:**
```json
{
  "malicious": true,
  "confidence": 0.87,
}
```
---

## Implementation Notes

1. **Machine Learning Models**
   - Must be **self-built**, not using pre-trained AI APIs.
   - Can use classic ML (Random Forest, XGBoost, SVM) or deep learning (custom LSTM/Transformer) trained locally.
   - Feature extraction:
     - Messages: TF-IDF, n-grams, URLs, suspicious keywords, sender metadata.
     - APKs: Permissions analysis, API call frequency, byte patterns.

2. **Flask API Backend**
   - Load trained models at startup.
   - Preprocess input before prediction.
   - Return structured JSON responses with `malicious` and `confidence`.

3. **Security**
   - Input sanitization.
   - HTTPS for production.
   - Rate-limiting optional.

4. **Asynchronous Workflow for APKs**
   - App uploads APK to `/scanApk`, receives `jobId`.
   - App polls `/scanStatus` every 10–15 seconds.
   - Server returns pending/done status.
   - Results cached to allow app reconnection.

---

## Notes for Research Paper
- All ML models are **trained locally**; no external AI service or pre-trained API is used.  
- All detection pipelines are **fully custom**.  
- Confidence scores (`0.0`–`1.0`) represent the model’s internal probability.  
- Can be cited as a **fully self-contained AI system**.
