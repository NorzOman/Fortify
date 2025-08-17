
# Mobile Phishing & Malware Detection - App Developer Tasks (Arshad)

## APK Handling

-   [ ] Allow manual selection of APK files from device storage.
-   [ ] Allow manual sending of messages to test.
-   [ ] **Optional:** Auto-monitor the `Downloads` folder and automatically send new APKs to the server.
-   [ ] **Optional:** Auto-monitor the `Messages`  and automatically send message to the server.


## Server Communication

-   [ ] Send APK files to a configurable backend endpoint: `/scanApk`.
-   [ ] Send incoming messages to the backend endpoint: `/scanMessage`.
-   [ ] Provide an input box to dynamically set or change the server URL.
-   [ ] Handle errors and retries gracefully if the server is unavailable.

## UI/UX

-   **Simple, clean interface (Light Mode):**
    -   [ ] File picker for APK selection.
    -   [ ] Input box to manually send message to test.
    -   [ ] Toggle for the auto-send feature.
    -   [ ] Input box for server URL configuration.
    -   [ ] Status indicators for scanned/sent items of what is send.
-   **Display backend scan results:**
    -   [ ] Clicking on send item logs show the result or show pending.

---

## Malware Scanning Integration

Connect the app to the backend using REST API calls. Implement an **asynchronous scanning workflow**:

1.  **App POSTs APK to `/scanApk` with JWT authorization (take name input for now to create token):**
    ```http
    POST /scanApk
    Headers: Authorization: Bearer <JWT>
    Body: file=example.apk
    ```

2.  **Server stores the job in the database and returns a `jobId`:**
    ```json
    {
      "jobId": "67890"
    }
    ```

3.  **App polls the `/scanStatus` endpoint with a GET request to the server periodically (10-15 sec):**
    ```http
    GET /scanStatus?jobId=12345
    Headers: Authorization: Bearer <JWT>
    ```

    -   **Response if scan is pending:**
        ```json
        {
          "status": "pending",
          "result": null
        }
        ```

    -   **Response when done:**
        ```json
        {
          "status": "done",
          "result": {
            "malicious": true,
            "confidence": 0.87,
            "report": "<text-about-report>"
          }
        }
        ```

-   [ ] Keep the app lightweight and functional; avoid unnecessary features.

---

## Message Scanning Integration

Connect the app to the backend using REST API calls. Implement an **asynchronous scanning workflow**:

1.  **App POSTs a message to `/scanMessage` with JWT authorization (take name input for now to create a token):**
    ```http
    POST /scanMessage
    Headers: Authorization: Bearer <JWT>
    Body:
    {
      "message": "Your account has been compromised. Click here to reset password.",
      "metadata": {
        "source": "sms",
        "sender": "unknown",
        "timestamp": "2025-08-17T12:34:56Z"
      }
    }
    ```

2.  **Server stores the job in the database and returns a `jobId`.**
    ```json
    {
      "jobId": "67890"
    }
    ```

3.  **App polls the `/scanMessageStatus` endpoint with a GET request to the server periodically (10-15 sec):**
    ```http
    GET /scanMessageStatus?jobId=67890
    Headers: Authorization: Bearer <JWT>
    ```

    -   **Response if scan is pending:**
        ```json
        {
          "status": "pending",
          "result": null
        }
        ```

    -   **Response when done:**
        ```json
        {
          "status": "done",
          "result": {
            "malicious": true,
            "confidence": 0.87,
            "report": {}
          }
        }
        ```
