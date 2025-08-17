
# Test Sample APK Creation Tasks (Raahim)

## Objective

Develop three distinct Android applications (`.apk` files) to use as test samples for our malware scanner. Each app should be simple on the surface but its source code must contain numerous suspicious patterns.

---

### **CRITICAL INSTRUCTION: Functionality vs. Code Presence**

**The malicious features listed below DO NOT need to be fully functional.** The primary goal is to ensure the **suspicious code exists within the APK** for the scanner to detect.

For example, you can write a function that prepares to access the camera or send an SMS, but the final command can be commented out or never called. The scanner is looking for the *intent* demonstrated by the code (e.g., requesting dangerous permissions, using risky APIs, containing hardcoded IPs).

---

### APK 1: Network Anomaly & C2 Simulator

**Goal:** The APK's code should *look like* it's trying to communicate with a malicious server and exfiltrate device data.

**Required Suspicious Code Patterns (10-15):**

*   **Permissions:** Request `INTERNET`, `ACCESS_NETWORK_STATE`, `READ_PHONE_STATE`.
*   **Hardcoded IP Address:** Include a hardcoded, non-standard IP address (e.g., `198.51.100.5`) in the source code.
*   **Suspicious Connection Code:** Have code that attempts to establish a `Socket` or `HttpURLConnection` to the hardcoded IP. The connection itself does not need to succeed.
*   **Dynamic DNS URL:** Hardcode a URL from a known dynamic DNS provider (e.g., `some-host.no-ip.biz`).
*   **Device Info Gathering:** Write a function that calls APIs to get the Device ID, Android Version, etc., and stores them in variables. It does not need to send them.
*   **Base64 Encoded Strings:** Store the suspicious IP or URL as a Base64 string and include the code to decode it at runtime.
*   **Anti-Emulator Check:** Include a function that checks for common emulator properties (e.g., `Build.FINGERPRINT` containing "generic").
*   **Fake Command Parser:** Write a function that takes a string and uses a `switch` or `if/else` block to check for mock commands like "GET_CONTACTS" or "UPLOAD_FILES".
*   **Root Check Code:** Add a utility function that checks for the existence of `su` binaries to detect a rooted device.
*   **Disabled Certificate Validation:** Include the code for a custom `TrustManager` that accepts all SSL certificates, even if it's not used by a real network request.
*   **Hidden File I/O:** Add code that creates a hidden file (e.g., `.config`) in the app's local storage.

---

### APK 2: Obfuscation & Hidden Payload Simulator

**Goal:** This APK's code should use common malware techniques to hide its intent, like encryption and dynamic loading.

**Required Suspicious Code Patterns (10-15):**

*   **Permissions:** Request `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `RECEIVE_BOOT_COMPLETED`.
*   **String Encryption:** Encrypt several strings within the code (e.g., file names, URLs) and include the function that decrypts them, even if they aren't used afterward.
*   **Embedded Asset File:** Place a non-descript file (e.g., `data.bin`) in the app's `assets` folder to simulate a hidden payload.
*   **Dynamic Code Loading Logic:** Include code that uses `DexClassLoader`. It can point to the fake asset file and fail gracefully; the presence of the API call is what's important.
*   **Excessive Reflection:** Use Java Reflection to call sensitive APIs (like `TelephonyManager.getDeviceId()`) instead of calling them directly.
*   **Junk Code:** Add useless loops and complex arithmetic operations inside functions to make them harder to analyze.
*   **Packer-like Structure:** Have one class whose only job is to "decode" a string and then call a method in a second class.
*   **Anti-Debugging Code:** Include a check for `Debug.isDebuggerConnected()`.
*   **Startup Receiver:** Implement a `BroadcastReceiver` that listens for the `BOOT_COMPLETED` system event. The receiver can simply write a log message.
*   **Native Code Interface:** Include a basic JNI (`.so` file) with a native function stub.
*   **Confusing Naming:** Use meaningless, short names for classes, methods, and variables (e.g., `class a { void b(String c) { ... } }`).

---

### APK 3: Aggressive Data & Privacy Invasion Simulator

**Goal:** This APK's code should appear to be spyware by requesting invasive permissions and containing functions to access sensitive user data.

**Required Suspicious Code Patterns (10-15):**

*   **Excessive Permissions:** Request a large number of dangerous permissions: `READ_CONTACTS`, `READ_SMS`, `ACCESS_FINE_LOCATION`, `CAMERA`, `RECORD_AUDIO`.
*   **Contact Access Code:** Write a function that queries the `ContactsContract` content provider and iterates through the results. It can just log the contact names to the console.
*   **SMS Reading Code:** Include code that queries the SMS inbox (`content://sms/inbox`).
*   **Location Access Code:** Write a function that uses `LocationManager` to request location updates.
*   **Microphone Access Code:** Include code that prepares `MediaRecorder` to access the `MIC` audio source. It does not need to actually record.
*   **Camera Access Code:** Add code that accesses the `Camera` API. You don't need to display a preview or save a picture.
*   **Accessibility Service Stub:** Define an `AccessibilityService` in the manifest and include the class file. This is a common pattern for keyloggers.
*   **Data Staging Code:** Write a function that appears to collect data (e.g., from contacts) and save it to a local variable or file.
*   **Content Observer Registration:** Include code that registers a `ContentObserver` to monitor changes to the SMS or contacts database.
*   **Silent SMS Sending Code:** Have a function that uses `SmsManager` to prepare an SMS to be sent to a hardcoded number. The final `sendTextMessage` call can be commented out.
*   **Clipboard Access Code:** Add a function that accesses the `ClipboardManager` to read its content.