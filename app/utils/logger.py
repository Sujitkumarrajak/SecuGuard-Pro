
import json
from datetime import datetime

LOG_FILE = 'logs/scan_logs.jsonl'

def log_scan(username, filename, file_hash, result):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user": username,
        "filename": filename,
        "file_hash": file_hash,
        "result": result
    }

    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def get_user_history(username):
    history = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                entry = json.loads(line.strip())
                if entry['user'] == username:
                    history.append(entry)
    except FileNotFoundError:
        pass

    return history[::-1]