# detector.py (partial update)
import json
import os
from datetime import datetime

LOG_FILE = "datasets/cicids_logs.jsonl"
ALERTS_FILE = "logs/live_alerts.jsonl"
CHUNK_SIZE = 250

RULES = {
    "query_spike": lambda x: len(x) > 50,  # High query volume (DNS tunneling)
    "long_response": lambda x: any(e.get("response_time", 0) > 70 for e in x),  # >70ms (DNS tunneling)
    "random_domain": lambda x: any(len(d.get("domain", "").split(".")[0]) > 15 or "xn--" in d.get("domain", "") for d in x)  # DGA-like randomness
}

def process_chunk(chunk):
    alerts = []
    for entry in chunk:
        try:
            timestamp = entry.get("timestamp", 0)
            domain = entry.get("domain", "")
            response_time = entry.get("response_time", 0)
            if not timestamp or not domain:
                continue
            for rule_name, rule_func in RULES.items():
                if rule_func(chunk):
                    alerts.append({
                        "timestamp": timestamp,
                        "domain": domain,
                        "type": rule_name,
                        "score": 1.0 if rule_name == "random_domain" else response_time / 100,
                        "details": f"Rule triggered: {rule_name}"
                    })
        except Exception as e:
            print(f"Error processing entry: {e}")
    return alerts

def main(log_file):
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found")
        return
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(log_file, 'r', encoding='utf-8') as f, open(ALERTS_FILE, 'a', encoding='utf-8') as out:
        chunk = []
        for line in f:
            try:
                entry = json.loads(line.strip())
                chunk.append(entry)
                if len(chunk) >= CHUNK_SIZE:
                    alerts = process_chunk(chunk)
                    if alerts:
                        for alert in alerts:
                            out.write(json.dumps(alert) + '\n')
                    chunk = []
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
        if chunk:
            alerts = process_chunk(chunk)
            if alerts:
                for alert in alerts:
                    out.write(json.dumps(alert) + '\n')

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    main(log_file)
