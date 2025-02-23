"use client";
import React, { useState, useEffect } from "react";

export function SmsScanDemo() {
  const [message, setMessage] = useState("");
  const [token, setToken] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // Fetch authentication token on component mount
  useEffect(() => {
    const fetchToken = async () => {
      try {
        const response = await fetch("https://vault-7-rebooted.vercel.app/get_token");
        const data = await response.json();
        console.log("Fetched Token:", data); // Debugging
        setToken(data.token);
      } catch (error) {
        console.error("Error fetching token:", error);
      }
    };
    fetchToken();
  }, []);

  // Handle SMS scan request
  const handleScan = async () => {
    if (!token) {
      alert("Token is not yet fetched");
      return;
    }
    if (!message) {
      alert("Please enter a message");
      return;
    }

    setLoading(true);
    setScanResult(null);

    const payload = {
      token: token,
      message: message,
    };

    console.log("Sending Request:", payload); // Debugging

    try {
      const response = await fetch("https://vault-7-rebooted.vercel.app/message_scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      console.log("Scan Result:", data); // Debugging

      setTimeout(() => {
        setScanResult(data.result);
        setLoading(false);
      }, 2000);
    } catch (error) {
      console.error("Error scanning message:", error);
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto  border border-dashed bg-white dark:bg-black border-neutral-200 dark:border-neutral-800 rounded-3xl p-5">
      <h2 className="text-2xl font-bold text-center mb-4">SMS Scanner</h2>
      <div className="flex items-center gap-4">
        <input
          type="text"
          placeholder="Enter message to scan"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          className="flex-1 p-2 border rounded-md"
        />
        <button
          onClick={handleScan}
          className="px-4 py-2 bg-blue-500 text-white rounded-md"
        >
          Scan
        </button>
      </div>

      {/* Show Loading Animation */}
      {loading && (
        <div className="mt-4 text-center">
          <div className="animate-spin rounded-full h-10 w-10 border-t-4 border-blue-500 mx-auto"></div>
          <p className="text-gray-500 mt-2">Scanning...</p>
        </div>
      )}

      {/* Display Scan Result */}
      {!loading && scanResult && (
        <div className="mt-6 p-4 border rounded-md bg-gray-100 dark:bg-gray-800">
          <h3 className="text-xl font-bold">Scan Result</h3>
          <p><strong>Result:</strong> 
            <span className={scanResult === "safe" ? "text-green-500" : "text-red-500"}>
              {scanResult.toUpperCase()}
            </span>
          </p>
        </div>
      )}
    </div>
  );
}
