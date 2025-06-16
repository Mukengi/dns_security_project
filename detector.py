# detector.py
import json
import math
from collections import defaultdict
from utils import load_key, decrypt_data
from config import LOG_FILE

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

def detect_tunneling(log_file, time_window=300, volume_threshold=100):
    """Apply rule-based detection for DNS tunneling."""
    key = load_key()
    alerts = []
    query_counts = defaultdict(int)
    window_start = None

    with open(log_file, "r") as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                if log_entry["type"] == "query":
                    timestamp = log_entry["timestamp"]
                    query_name = decrypt_data(log_entry["query_name"], key)
                    entropy = calculate_entropy(query_name)
                    query_length = len(query_name)

                    # Initialize window
                    if window_start is None:
                        window_start = timestamp

                    # Reset counts if outside window
                    if timestamp > window_start + time_window:
                        query_counts.clear()
                        window_start = timestamp

                    # Update query count
                    query_counts[query_name] += 1

                    # Apply rules
                    if (entropy > 3.5 or query_length > 50 or query_counts[query_name] > volume_threshold):
                        alerts.append({
                            "timestamp": timestamp,
                            "query_name": query_name,
                            "entropy": entropy,
                            "query_length": query_length,
                            "query_count": query_counts[query_name],
                            "alert": "Potential DNS tunneling detected"
                        })
            except Exception as e:
                print(f"Error processing log entry: {e}")
    return alerts

if __name__ == "__main__":
    alerts = detect_tunneling(LOG_FILE)
    for alert in alerts:
        print(json.dumps(alert, indent=2))
