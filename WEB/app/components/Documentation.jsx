"use client";
import React from "react";

export function Documentation() {
  return (
    <div className="w-full max-w-4xl mx-auto min-h-96 border border-dashed bg-white dark:bg-black border-neutral-200 dark:border-neutral-800 rounded-3xl p-5">
      <h2 className="text-2xl font-bold text-center mb-4">System Documentation</h2>
      
      <section>
        <h3 className="text-xl font-semibold mt-4">1. Overview</h3>
        <p className="dark:text-gray-200 text-gray-700">
          This system provides three key security features: Malware Detection, URL Scanning, and Phishing Message Detection.
          Each of these features is designed to help users identify and prevent malicious content from affecting their devices.
        </p>
      </section>

      <section>
        <h3 className="text-xl font-semibold mt-4">2. Malware Detection</h3>
        <p className="dark:text-gray-200 text-gray-700">
          Malware detection involves identifying harmful software that can damage, disrupt, or steal data from a system. This system utilizes a signature-based approach where files are checked against known malware signatures. 
          If a match is found, the file is flagged as "malicious". Additionally, heuristic analysis can be used to detect new or unknown malware by looking for suspicious behavior patterns in the file.
        </p>
        <ul className="list-disc ml-6">
          <li><strong>Signature-Based Detection:</strong> Files are scanned using known malware signatures from threat intelligence databases.</li>
          <li><strong>Heuristic Analysis:</strong> The system examines the file's behavior for suspicious actions, such as unusual access to sensitive data.</li>
          <li><strong>AI-Powered Detection:</strong> Advanced machine learning models are used to identify new, emerging malware threats.</li>
        </ul>
      </section>

      <section>
        <h3 className="text-xl font-semibold mt-4">3. URL Scanning</h3>
        <p className="dark:text-gray-200 text-gray-700">
          URL scanning checks websites to see if they pose a risk to users. It looks for signs of malicious activity such as phishing, malware distribution, or fraudulent behavior. The system uses databases of known malicious URLs and analyzes new URLs using machine learning models to identify potential threats.
        </p>
        <ul className="list-disc ml-6">
          <li><strong>Domain Information Analysis:</strong> The domain registration information is checked for signs of malicious intent, such as rapid registration or anonymous registrants.</li>
          <li><strong>Phishing Detection:</strong> URLs are analyzed for known patterns of phishing websites, such as mimicking popular websites or using deceptive URLs.</li>
          <li><strong>Malicious Content Detection:</strong> The system checks the content of the website for malware or scam attempts.</li>
        </ul>
      </section>

      <section>
        <h3 className="text-xl font-semibold mt-4">4. Phishing Message Detection</h3>
        <p className="dark:text-gray-200 text-gray-700">
          Phishing is a technique used by malicious actors to trick individuals into providing sensitive information, such as login credentials or personal data. This system scans SMS messages for common signs of phishing, such as fake promises of rewards or urgent requests for personal information.
        </p>
        <ul className="list-disc ml-6">
          <li><strong>Keyword-Based Detection:</strong> Scans messages for common phishing keywords, such as "winner", "urgent", "confirm now", etc.</li>
          <li><strong>Link Analysis:</strong> The system checks if the message contains suspicious or shortened URLs that might lead to malicious websites.</li>
          <li><strong>Message Sentiment Analysis:</strong> Analyzes the tone of the message to detect urgency or alarm, which are common tactics used in phishing attempts.</li>
        </ul>
      </section>

      <section>
        <h3 className="text-xl font-semibold mt-4">5. Technologies and Techniques</h3>
        <p className="dark:text-gray-200 text-gray-700">
          The system leverages a variety of advanced technologies to detect threats. Below are some of the key techniques used:
        </p>
        <ul className="list-disc ml-6">
          <li><strong>Signature-Based Detection:</strong> Matching known malware signatures against incoming files.</li>
          <li><strong>Heuristic Analysis:</strong> Evaluating the behavior of files and URLs to identify new, unknown threats.</li>
          <li><strong>Machine Learning:</strong> Using AI to identify emerging threats and new attack vectors by analyzing vast datasets of past security incidents.</li>
          <li><strong>Real-Time Scanning:</strong> Continuous monitoring of URLs and messages for up-to-the-minute security updates.</li>
        </ul>
      </section>
    </div>
  );
}
