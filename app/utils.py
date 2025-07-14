import hashlib
import os
import requests
from fpdf import FPDF
import datetime
import time

# 1️⃣ Generate SHA-256 hash
def get_file_hash(file_stream):
    file_stream.seek(0)
    sha256 = hashlib.sha256()
    while True:
        data = file_stream.read(4096)
        if not data:
            break
        sha256.update(data)
    file_stream.seek(0)
    return sha256.hexdigest()


# 2️⃣ Scan file with VirusTotal
VIRUSTOTAL_API_KEY = "b33440b5f286f668b007310d4148b64366401ce7475bc10814db8e19075b925f"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"

import time

def scan_file_with_virustotal(file_path):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
    }

    # Upload file
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        upload_response = requests.post(VT_UPLOAD_URL, headers=headers, files=files)

    if upload_response.status_code != 200:
        return {
            "error": "Upload failed",
            "status": upload_response.status_code,
            "message": upload_response.text,
        }

    analysis_id = upload_response.json()["data"]["id"]

    # Poll the analysis until it's completed
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(10):  # max 10 tries
        time.sleep(3)  # wait 3 seconds between each try
        result_response = requests.get(analysis_url, headers=headers)
        result_data = result_response.json()

        if result_data.get("data", {}).get("attributes", {}).get("status") == "completed":
            stats = result_data["data"]["attributes"].get("stats", {})
            result_data["scan_summary"] = {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "unsupported": stats.get("type-unsupported", 0)
            }
            return result_data

    # If still not completed after retries
    return {
        "error": "Scan result not ready",
        "status": "timeout",
        "message": f"Scan result was not ready after multiple retries.",
        "scan_id": analysis_id
    }



# 3️⃣ Generate PDF report
def generate_pdf_report(filename, file_hash, scan_result, user):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="SecuGuard-Pro Scan Report", ln=True, align="C")
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Scanned by: {user}", ln=True)
    pdf.cell(200, 10, txt=f"Date: {now}", ln=True)
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Filename: {filename}", ln=True)
    pdf.cell(200, 10, txt=f"SHA256: {file_hash}", ln=True)
    pdf.cell(200, 10, txt=f"Scan Status: {scan_result.get('status', 'Unknown')}", ln=True)
    pdf.ln(10)

    if "scan_summary" in scan_result:
        pdf.cell(200, 10, txt="Scan Summary:", ln=True)
        for key, value in scan_result["scan_summary"].items():
            pdf.cell(200, 10, txt=f"  - {key}: {value}", ln=True)

    # Save report
    reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, f"{filename}_report.pdf")
    pdf.output(report_path)

    return report_path