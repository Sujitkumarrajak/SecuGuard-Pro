
import os

def scan_file(filename):
    # Fake scan logic
    if filename.endswith('.exe') or 'virus' in filename.lower():
        return {
            "status": "Malicious",
            "threat_level": "High",
            "details": "Suspicious executable file detected."
        }
    else:
        return {
            "status": "Safe",
            "threat_level": "Low",
            "details": "No known malicious patterns found."
        }