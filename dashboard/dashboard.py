# dashboard.py

from flask import Flask, render_template
import matplotlib
matplotlib.use('Agg')  # Use Agg backend for non-GUI environments
import matplotlib.pyplot as plt
import seaborn as sns
import json
import psutil
from collections import Counter
import os
from datetime import datetime
import time

app = Flask(__name__)

# Resolve log paths relative to current file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILES = [
    os.path.join(BASE_DIR, '../logs/alerts.jsonl'),
    os.path.join(BASE_DIR, '../logs/ml_alerts.jsonl')
]

# Load alerts from files with timestamp-based caching
_alert_cache = {}

def load_alerts():
    all_alerts = []

    for filepath in LOG_FILES:
        if os.path.exists(filepath):
            mtime = os.path.getmtime(filepath)

            if filepath not in _alert_cache or _alert_cache[filepath]['mtime'] < mtime:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = [json.loads(line) for line in f if line.strip()]
                        _alert_cache[filepath] = {'mtime': mtime, 'data': data}
                except Exception as e:
                    print(f"[ERROR] Failed to read {filepath}: {e}")
                    continue

            all_alerts.extend(_alert_cache[filepath]['data'])

    return all_alerts

# Generate structured data for plotting (Chart.js)
def generate_plots(alerts):
    if not alerts:
        return {"alert_types": {}, "timestamps": []}

    # Distribution of alert types
    alert_types = [a.get('type', 'unknown') for a in alerts]
    type_data = dict(Counter(alert_types))

    # Timestamps (rounded to nearest minute)
    timestamps = []
    for a in alerts:
        ts = a.get('timestamp')
        try:
            if isinstance(ts, (int, float)):
                readable = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
                timestamps.append(readable)
        except Exception:
            continue

    return {
        "alert_types": type_data,
        "timestamps": timestamps
    }

# Dashboard route
@app.route('/')
def index():
    alerts = load_alerts()

    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent

    alert_type_counts = Counter(a.get('type', 'unknown') for a in alerts)

    plot_data = generate_plots(alerts)

    return render_template('index.html',
                           cpu_usage=cpu_usage,
                           memory_usage=memory_usage,
                           total_alerts=len(alerts),
                           rule_based=alert_type_counts.get('rule-based', 0),
                           ml_based=alert_type_counts.get('ml-based', 0),
                           plot_data=plot_data)

# Entry point
if __name__ == '__main__':
    # Ensure necessary directories exist
    os.makedirs(os.path.join(BASE_DIR, 'static'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'templates'), exist_ok=True)

    app.run(debug=True, host='0.0.0.0', port=5000)

