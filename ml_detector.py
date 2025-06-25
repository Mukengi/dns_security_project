
# ml_detector.py
import json
import math
from collections import defaultdict, Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from cryptography.fernet import Fernet
from utils import load_key
from config import LOG_FILE

ALERT_FILE = "logs/ml_alerts.jsonl"

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def extract_features(log_file, time_window=300):
    """Extract features from logs for ML."""
    key = load_key()
    fernet = Fernet(key)
    features = []
    queries = []
    query_counts = defaultdict(int)
    window_start = None

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if log_entry.get("type") == "query":
                    timestamp = log_entry["timestamp"]
                    query_name = fernet.decrypt(log_entry["query_name"].encode()).decode()
                    entropy = calculate_entropy(query_name)
                    query_length = len(query_name)
                    subdomain_count = query_name.count('.') - 1

                    if window_start is None:
                        window_start = timestamp
                    if timestamp > window_start + time_window:
                        query_counts.clear()
                        window_start = timestamp
                    query_counts[query_name] += 1

                    features.append([query_length, entropy, subdomain_count, query_counts[query_name]])
                    queries.append((timestamp, query_name))
            except Exception as e:
                print(f"Error parsing log entry: {e}")
    return np.array(features), queries

def log_alert(alert):
    """Log ML alerts to file."""
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    print(json.dumps(alert, indent=2))

def detect_anomalies(log_file):
    """Detect DGA anomalies using Isolation Forest."""
    features, queries = extract_features(log_file)
    print(f"Extracted {len(features)} feature vectors")
    queries
    if len(features) == 0:
        print("No features extracted")
        return []

    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(features)
    predictions = model.predict(features)

    alerts = []
    for i, pred in enumerate(predictions):
        if pred == -1:  # Anomaly detected
            alert = {
                "timestamp": queries[i][0],
                "query_name": queries[i][1],
                "features": features[i].tolist(),
                "alert": "Potential DGA detected"
            }
            alerts.append(alert)
            log_alert(alert)
    print(f"Total ML Alerts: {len(alerts)}")

    return alerts

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    detect_anomalies(log_file)

