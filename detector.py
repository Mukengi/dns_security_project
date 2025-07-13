import json
import os
from datetime import datetime
from send_summary_email import send_summary_email

ALERTS_FILE = "logs/live_alerts.jsonl"
CHUNK_SIZE = 1000

def detect_dns_tunneling(entry):
    domain = entry.get("domain", "")
    response_time = entry.get("response_time", 0)
    return (
        response_time > 200 or
        len(domain.split(".")) > 5 or
        len(domain) > 60
    )

def main(log_file):
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found")
        return

    total_alerts = []
    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)

    with open(log_file, 'r') as f:
        chunk = []
        for line in f:
            try:
                entry = json.loads(line.strip())
                chunk.append(entry)
                if len(chunk) >= CHUNK_SIZE:
                    alerts = process_chunk(chunk)  # Fixed: Call process_chunk
                    total_alerts.extend(alerts)
                    write_alerts(alerts)
                    chunk = []
            except json.JSONDecodeError:
                continue

        if chunk:
            alerts = process_chunk(chunk)  # Fixed: Call process_chunk
            total_alerts.extend(alerts)
            write_alerts(alerts)

    # Summarize and send email (dga_count will be 0 unless ml_detector runs)
    dns_tunnel_count = sum(1 for a in total_alerts if a["type"] == "dns_tunneling")
    dga_count = sum(1 for a in total_alerts if a["type"] == "dga_detected")
    send_summary_email(len(total_alerts), dga_count, dns_tunnel_count, "http://127.0.0.1:5000")

def process_chunk(chunk):
    alerts = []
    for entry in chunk:
        if detect_dns_tunneling(entry):
            alerts.append({
                "timestamp": int(entry.get("timestamp", datetime.now().timestamp())),
                "domain": entry.get("domain", ""),
                "type": "dns_tunneling",
                "score": round(entry.get("response_time", 0) / 100, 2),
                "details": "Rule-based: Suspicious DNS tunneling"
            })
    return alerts

def write_alerts(alerts):
    try:
        with open(ALERTS_FILE, 'a') as out:
            for alert in alerts:
                json.dump(alert, out)
                out.write("\n")
    except IOError as e:
        print(f"Error writing alerts to {ALERTS_FILE}: {e}")

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else "datasets/cicids_logs.jsonl"
    main(log_file)
