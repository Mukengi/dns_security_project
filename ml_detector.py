```python
# ml_detector.py
import json
import math
from collections import defaultdict, Counter
import numpy as np
from sklearn.ensemble import IsolationForest
from utils import load_key, decrypt_data
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
    query_counts = defaultdict(int)
    window_start = None

    with open(log_file, "r") as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if log_entry["type"] == "query":
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
            except Exception as e:
                print(f"Error processing log entry: {e}")
    return np.array(features)

def log_alert(alert):
    """Log ML alerts to file."""
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    features = extract_features(log_file)
    print(f"Extracted {len(features)} feature vectors")
```
