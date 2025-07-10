import json
import os
from datetime import datetime

# File paths
LOG_FILE = "datasets/cicids_logs.jsonl"
ALERTS_FILE = "logs/live_alerts.jsonl"
CHUNK_SIZE = 1000

# Rule definitions for DNS tunneling
RULES = {
    "dns_tunneling": lambda entry: (
        entry.get("response_time", 0) > 100 or
        len(entry.get("domain", "")) > 50 or
        len(entry.get("domain", "").split(".")) > 4
    )
}

# Process a chunk of entries and apply rules
def process_chunk(chunk):
    alerts = []
    for entry in chunk:
        try:
            timestamp = entry.get("timestamp") or int(datetime.now().timestamp())
            domain = entry.get("domain", "")
            response_time = entry.get("response_time", 0)
            src_ip = entry.get("src_ip", "")
            dst_ip = entry.get("dst_ip", "")

            if not domain:
                continue

            for rule_name, rule_func in RULES.items():
                if rule_func(entry):
                    alerts.append({
                        "timestamp": timestamp,
                        "domain": domain,
                        "response_time": response_time,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "type": rule_name,
                        "score": round(response_time / 100, 2),
                        "details": "Detected DNS tunneling using rule-based logic"
                    })
        except Exception as e:
            print(f"[ERROR] Rule-based detection failed: {e}")
    return alerts

# Main detection routine
def main(log_file):
    if not os.path.exists(log_file):
        print(f"[ERROR] Log file {log_file} not found")
        return

    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)

    with open(log_file, 'r', encoding='utf-8') as f:
        chunk = []
        for line in f:
            try:
                entry = json.loads(line.strip())
                chunk.append(entry)
                if len(chunk) >= CHUNK_SIZE:
                    alerts = process_chunk(chunk)
                    if alerts:
                        with open(ALERTS_FILE, 'a', encoding='utf-8') as out:
                            for alert in alerts:
                                out.write(json.dumps(alert) + '\n')
                    chunk = []
            except json.JSONDecodeError:
                continue

        # Process remaining entries
        if chunk:
            alerts = process_chunk(chunk)
            if alerts:
                with open(ALERTS_FILE, 'a', encoding='utf-8') as out:
                    for alert in alerts:
                        out.write(json.dumps(alert) + '\n')

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    main(log_file)
