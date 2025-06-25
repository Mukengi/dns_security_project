
# detector.py
import json
import math
from collections import defaultdict, Counter
import numpy as np
from sklearn.ensemble import IsolationForest
import psutil
import smtplib
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from utils import load_key
from config import LOG_FILE

ALERT_FILE = "logs/alerts.jsonl"
CHUNK_SIZE = 1000
EMAIL_SENDER = "puritymukengi@gmail.com"
EMAIL_PASSWORD = "gity mngn pcst kaai"
EMAIL_RECEIVER = "puritymukengi@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def send_email_alert(alert):
    """Send email alert to admin."""
    msg = MIMEText(json.dumps(alert, indent=2))
    msg["Subject"] = f"DNS Anomaly Alert: {alert['alert']}"
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")

def log_alert(alert, alert_type="rule-based"):
    """Log alerts to file and send email."""
    alert["type"] = alert_type
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(json.dumps(alert, indent=2))
    send_email_alert(alert)

def detect_hybrid(log_file, time_window=300, volume_threshold=100):
    """Apply rule-based and ML-based detection."""
    key = load_key()
    fernet = Fernet(key)
    alerts = []
    query_counts = defaultdict(int)
    window_start = None
    features = []
    queries = []

    print(f"Initial CPU Usage: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%")

    with open(log_file, "r") as f:
        chunk = []
        for i, line in enumerate(f):
            chunk.append(line)
            if (i + 1) % CHUNK_SIZE == 0:
                process_chunk(chunk, fernet, query_counts, window_start, time_window, volume_threshold, alerts, features, queries)
                chunk = []
        if chunk:
            process_chunk(chunk, fernet, query_counts, window_start, time_window, volume_threshold, alerts, features, queries)

    # ML Detection
    if features:
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(np.array(features))
        predictions = model.predict(np.array(features))
        for i, pred in enumerate(predictions):
            if pred == -1:
                alert = {
                    "timestamp": queries[i][0],
                    "query_name": queries[i][1],
                    "features": features[i],
                    "alert": "Potential DGA detected"
                }
                alerts.append(alert)
                log_alert(alert, "ml-based")

    print(f"Final CPU Usage: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%")
    return alerts

def process_chunk(chunk, fernet, query_counts, window_start, time_window, volume_threshold, alerts, features, queries):
    """Process a chunk of log entries."""
    for line in chunk:
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

                # Rule-Based Detection
                if (entropy > 3.5 or query_length > 50 or query_counts[query_name] > volume_threshold):
                    alert = {
                        "timestamp": timestamp,
                        "query_name": query_name,
                        "entropy": entropy,
                        "query_length": query_length,
                        "query_count": query_counts[query_name],
                        "alert": "Potential DNS tunneling detected"
                    }
                    alerts.append(alert)
                    log_alert(alert, "rule-based")

                # Collect Features for ML
                features.append([query_length, entropy, subdomain_count, query_counts[query_name]])
                queries.append((timestamp, query_name))
        except Exception as e:
            print(f"Error processing log entry: {e}")

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    alerts = detect_hybrid(log_file)
    print(f"Total Alerts: {len(alerts)}")

