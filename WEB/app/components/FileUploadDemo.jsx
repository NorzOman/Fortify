"use client";
import React, { useState, useEffect } from "react";
import { FileUpload } from "@/app/components/ui/file-upload";
import CryptoJS from "crypto-js";

export function FileUploadDemo() {
  const [files, setFiles] = useState([]);
  const [token, setToken] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false); // Loading state
  const [scanTime, setScanTime] = useState(null); // Time tracking

  // Fetch authentication token on component mount
  useEffect(() => {
    const fetchToken = async () => {
      try {
        const response = await fetch("https://vault-7-rebooted.vercel.app/get_token");
        const data = await response.json();
        setToken(data.token);
      } catch (error) {
        console.error("Error fetching token:", error);
      }
    };

    fetchToken();
  }, []);

  // Handle file upload change
  const handleFileUpload = (uploadedFiles) => {
    setFiles(uploadedFiles);
    console.log(uploadedFiles);

    // Automatically trigger file scan after upload
    if (uploadedFiles.length > 0) {
      handleFileScan(uploadedFiles[0]);
    }
  };

  // Handle file scan request
  const handleFileScan = async (file) => {
    if (!token) {
      alert("Token is not yet fetched");
      return;
    }

    setLoading(true); // Start loading
    const startTime = Date.now(); // Start time tracking

    // Read the file as binary and compute MD5 hash
    const fileReader = new FileReader();
    fileReader.onloadend = () => {
      const binaryData = fileReader.result;
      const md5Hash = CryptoJS.MD5(CryptoJS.enc.Latin1.parse(binaryData)).toString(CryptoJS.enc.Hex);

      // Prepare the payload for the POST request
      const payload = {
        token: token,
        hashes: [
          [
            file.name,
            `md5:${md5Hash}`,
          ],
        ],
      };

      // Send the request to the backend
      fetch("https://vault-7-rebooted.vercel.app/file_scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      })
        .then((response) => response.json())
        .then((data) => {
          setTimeout(() => {
            const endTime = Date.now(); // End time tracking
            setScanTime(((endTime - startTime) / 1000).toFixed(2)); // Calculate time taken
            setScanResult({
              fileName: file.name,
              md5Hash: md5Hash,
              scanData: data,
            });
            setLoading(false); // Stop loading after 2 seconds
          }, 2000);
        })
        .catch((error) => {
          console.error("Error scanning file:", error);
          setLoading(false);
        });
    };

    fileReader.readAsBinaryString(file); // Read file as binary
  };

  return (
    <div className="w-full max-w-4xl mx-auto min-h-96 border border-dashed bg-white dark:bg-black border-neutral-200 dark:border-neutral-800 rounded-lg p-6">
      <FileUpload onChange={handleFileUpload} />

      {/* Show Loading Animation */}
      {loading && (
        <div className="mt-4 flex flex-col items-center">
          <div className="animate-spin rounded-full h-10 w-10 border-t-4 border-blue-500"></div>
          <p className="text-gray-500 mt-2">Processing...</p>
        </div>
      )}

      {/* Display scan result after loading */}
      {!loading && scanResult && (
        <div className="mt-4 p-4 border border-gray-300 rounded-lg bg-gray-100 dark:bg-gray-800">
          <h3 className="text-xl font-bold mb-2">Scan Result</h3>
          <p><strong>File Name:</strong> {scanResult.fileName}</p>
          <p><strong>MD5 Hash:</strong> {scanResult.md5Hash}</p>
          {scanTime && <p><strong>Time Taken:</strong> {scanTime} seconds</p>}

          {/* Show scan details if available */}
          {scanResult.scanData.result && scanResult.scanData.result.length > 0 ? (
            <p className="text-red-500 font-semibold mt-2">⚠️ Malicious File Detected</p>
          ) : (
            <p className="text-green-500 font-semibold mt-2">✅ Safe File</p>
          )}

          {/* Show additional metadata if available */}
          {scanResult.scanData.metadata && (
            <div className="mt-3">
              <p><strong>Created By:</strong> {scanResult.scanData.metadata.created_by || "Unknown"}</p>
              <p><strong>Created On:</strong> {scanResult.scanData.metadata.created_on || "Unknown"}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
