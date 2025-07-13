import json
import os
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from send_summary_email import send_summary_email

ALERTS_FILE = "logs/live_alerts.jsonl"
CHUNK_SIZE = 1000

def prepare_features(chunk):
    data = []
    for entry in chunk:
        domain = entry.get("domain", "")
        data.append({
            "timestamp": entry.get("timestamp", int(datetime.now().timestamp())),
            "domain": domain,
            "query_length": len(domain),
            "subdomain_count": len(domain.split(".")) - 1,
            "response_time": entry.get("response_time", 0)
        })
    return pd.DataFrame(data)

def detect_anomalies(df):
    alerts = []
    if df.empty or len(df) < 2:
        return alerts

    model = IsolationForest(contamination=0.01, random_state=42)  # Reduced to 1%
    X = df[["query_length", "response_time", "subdomain_count"]]
    model.fit(X)
    preds = model.predict(X)
    scores = model.decision_function(X)

    for idx, is_outlier in enumerate(preds):
        if is_outlier == -1:
            row = df.iloc[idx]
            alerts.append({
                "timestamp": int(row.get("timestamp", datetime.now().timestamp())),
                "domain": row["domain"],
                "type": "dga_detected",
                "score": float(abs(scores[idx])),
                "details": "ML-Based: DGA domain detected"
            })
    return alerts

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
                    df = prepare_features(chunk)
                    alerts = detect_anomalies(df)
                    total_alerts.extend(alerts)
                    write_alerts(alerts)
                    chunk = []
            except json.JSONDecodeError:
                continue

        if chunk:
            df = prepare_features(chunk)
            alerts = detect_anomalies(df)
            total_alerts.extend(alerts)
            write_alerts(alerts)

    # Summarize and send (dns_tunnel_count will be 0 unless detector.py runs)
    dns_tunnel_count = sum(1 for a in total_alerts if a["type"] == "dns_tunneling")
    dga_count = sum(1 for a in total_alerts if a["type"] == "dga_detected")
    send_summary_email(len(total_alerts), dga_count, dns_tunnel_count, "http://127.0.0.1:5000")

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
