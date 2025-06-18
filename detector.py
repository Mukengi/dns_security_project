# detector.py
import json
import math
from collections import defaultdict
import psutil
from utils import load_key, decrypt_data
from config import LOG_FILE

ALERT_FILE = "logs/alerts.jsonl"
CHUNK_SIZE = 1000  # Process logs in chunks

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    chars = {}
    for char in text:
        chars[char] = chars.get(char, 0) + 1
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in chars.values())
    return entropy

def log_alert(alert):
    """Log alert to file and print to console."""
    with open(ALERT_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(json.dumps(alert, indent=2))

def detect_tunneling(log_file, time_window=300, volume_threshold=100):
    """Apply rule-based detection for DNS tunneling."""
    key = load_key()
    alerts = []
    query_counts = defaultdict(int)
    window_start = None

    print(f"Initial CPU Usage: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%")

    with open(log_file, "r") as f:
        chunk = []
        for i, line in enumerate(f):
            chunk.append(line)
            if (i + 1) % CHUNK_SIZE == 0:
                process_chunk(chunk, key, query_counts, window_start, time_window, volume_threshold, alerts)
                chunk = []
        if chunk:
            process_chunk(chunk, key, query_counts, window_start, time_window, volume_threshold, alerts)
    
    print(f"Final CPU Usage: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%")
    return alerts

def process_chunk(chunk, key, query_counts, window_start, time_window, volume_threshold, alerts):
    """Process a chunk of log entries."""
    for line in chunk:
        try:
            log_entry = json.loads(line)
            if log_entry["type"] == "query":
                timestamp = log_entry["timestamp"]
                query_name = decrypt_data(log_entry["query_name"], key)
                entropy = calculate_entropy(query_name)
                query_length = len(query_name)

                if window_start is None:
                    window_start = timestamp
                if timestamp > window_start + time_window:
                    query_counts.clear()
                    window_start = timestamp
                query_counts[query_name] += 1

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
                    log_alert(alert)
        except Exception as e:
            print(f"Error processing log entry: {e}")

if __name__ == "__main__":
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    alerts = detect_tunneling(log_file)
    print(f"Total Alerts: {len(alerts)}")
