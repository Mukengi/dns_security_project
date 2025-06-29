# ml_detector.py

import json
import math
from collections import defaultdict, Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
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

def digit_ratio(domain):
    """Ratio of digits in domain name."""
    digits = sum(c.isdigit() for c in domain)
    return digits / len(domain) if domain else 0

def consonant_vowel_ratio(domain):
    """Ratio of consonants to vowels in domain name."""
    vowels = set("aeiou")
    v = sum(c in vowels for c in domain.lower())
    c = sum(c.isalpha() and c not in vowels for c in domain.lower())
    return c / (v + 1)  # Avoid division by zero

def extract_features(log_file, time_window=300):
    """Extract features from DNS logs for ML model."""
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
                    digit_ratio_val = digit_ratio(query_name)
                    cv_ratio = consonant_vowel_ratio(query_name)

                    if window_start is None:
                        window_start = timestamp
                    if timestamp > window_start + time_window:
                        query_counts.clear()
                        window_start = timestamp
                    query_counts[query_name] += 1

                    features.append([
                        query_length,
                        entropy,
                        subdomain_count,
                        query_counts[query_name],
                        digit_ratio_val,
                        cv_ratio
                    ])
                    queries.append((timestamp, query_name))
            except Exception as e:
                print(f"Error parsing log entry: {e}")
    return np.array(features), queries

def log_alert(alert):
    """Log machine learning-based anomaly alerts to file."""
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")
    print(json.dumps(alert, indent=2))

def detect_anomalies(log_file):
    """Detect potential DGA attacks using Isolation Forest."""
    features, queries = extract_features(log_file)
    if len(features) == 0:
        print("No features extracted")
        return

    # Normalize features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)

    # Initialize and train the Isolation Forest model
    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(features_scaled)
    predictions = model.predict(features_scaled)

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

