import json
import os
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

LOG_FILE = "datasets/cicids_logs.jsonl"
ALERTS_FILE = "logs/live_alerts.jsonl"
CHUNK_SIZE = 1000

def prepare_data(chunk):
    data = []
    for entry in chunk:
        try:
            domain = entry.get("domain", "")
            features = {
                "timestamp": entry.get("timestamp") or int(datetime.now().timestamp()),
                "query_length": len(domain),
                "response_time": entry.get("response_time", 0),
                "subdomain_count": len(domain.split(".")) - 1,
                "domain": domain,
                "src_ip": entry.get("src_ip", ""),
                "dst_ip": entry.get("dst_ip", "")
            }
            data.append(features)
        except Exception as e:
            print(f"[ERROR] Feature prep: {e}")
    return pd.DataFrame(data)

def detect_anomalies(df):
    if df.empty or len(df) < 2:
        return []
    alerts = []
    model = IsolationForest(contamination=0.1, random_state=42)
    try:
        X = df[["query_length", "response_time", "subdomain_count"]].fillna(0)
        model.fit(X)
        preds = model.predict(X)
        scores = model.decision_function(X)

        for idx, is_outlier in enumerate(preds):
            if is_outlier == -1:
                row = df.iloc[idx]
                alerts.append({
                    "timestamp": int(row["timestamp"]),
                    "domain": row["domain"],
                    "response_time": row["response_time"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "type": "dga_detected",
                    "score": float(abs(scores[idx])),
                    "details": "Detected DGA domain using ML anomaly detection"
                })
    except Exception as e:
        print(f"[ERROR] ML detection: {e}")
    return alerts

def main(log_file):
    if not os.path.exists(log_file):
        print(f"Log file {log_file} not found")
        return

    os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
    with open(log_file, 'r', encoding='utf-8') as f:
        chunk = []
        for line in f:
            try:
                entry = json.loads(line.strip())
                chunk.append(entry)
                if len(chunk) >= CHUNK_SIZE:
                    df = prepare_data(chunk)
                    alerts = detect_anomalies(df)
                    if alerts:
                        with open(ALERTS_FILE, 'a', encoding='utf-8') as out:
                            for alert in alerts:
                                out.write(json.dumps(alert) + '\n')
                    chunk = []
            except json.JSONDecodeError:
                continue
        if chunk:
            df = prepare_data(chunk)
            alerts = detect_anomalies(df)
            if alerts:
                with open(ALERTS_FILE, 'a', encoding='utf-8') as out:
                    for alert in alerts:
                        out.write(json.dumps(alert) + '\n')

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    main(log_file)
