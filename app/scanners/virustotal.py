import os
import hashlib
import requests
import time

# Load the API key from .env
API_KEY = os.getenv("VT_API_KEY")

# Set headers and VirusTotal API URLs
HEADERS = {
    "x-apikey": API_KEY
}
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"

# ✅ Function to compute SHA-256 hash of uploaded file
def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# ✅ Upload file → Get analysis → Poll result → Return summary
def scan_with_virustotal(file_path):
    # Step 1: Upload the file to VirusTotal
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(VT_UPLOAD_URL, headers=HEADERS, files=files)

    if response.status_code != 200:
        return {
            "status": "Upload Error",
            "details": response.text
        }

    try:
        analysis_id = response.json()["data"]["id"]
    except Exception:
        return {
            "status": "Upload Error",
            "details": "Could not extract analysis ID"
        }

    # Step 2: Poll analysis results for up to ~60 seconds
    for attempt in range(30):  # 30 × 2s = max 60 seconds
        analysis_response = requests.get(VT_ANALYSIS_URL + analysis_id, headers=HEADERS)

        if analysis_response.status_code != 200:
            time.sleep(2)
            continue

        try:
            data = analysis_response.json()

            # ✅ If conflict error, retry
            if "error" in data:
                if data["error"].get("code") == "ConflictError":
                    time.sleep(3)
                    continue
                return {
                    "status": "Upload Error",
                    "details": data["error"]
                }

            # ✅ When scan is done
            if data["data"]["attributes"]["status"] == "completed":
                stats = data["data"]["attributes"]["stats"]
                return {
                    "status": "Malicious" if stats["malicious"] > 0 else "Safe",
                    "malicious": stats["malicious"],
                    "undetected": stats["undetected"],
                    "scan_summary": stats
                }

        except Exception:
            pass

        time.sleep(2)

    # ✅ Timeout fallback
    return {
        "status": "Scan Timeout",
        "details": "Analysis not completed in time."
    }