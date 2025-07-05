from flask import Flask, render_template, jsonify
import json
import os
from collections import Counter
from datetime import datetime
import psutil

app = Flask(__name__)

ALERTS_FILE = "logs/live_alerts.jsonl"

# Load only DNS tunneling and DGA-related alerts
def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    
    alerts = []
    with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                alert = json.loads(line.strip())
                alert_type = alert.get("type", "")
                if alert_type in ["dns_tunneling", "dga_suspicion", "random_domain", "long_response", "query_spike"]:
                    alerts.append(alert)
            except json.JSONDecodeError:
                continue
    return alerts

def generate_plot_data(alerts):
    # Count types
    type_counts = Counter(alert['type'] for alert in alerts)

    # Group by minute
    timestamp_counts = Counter(
        datetime.fromtimestamp(alert['timestamp']).strftime("%Y-%m-%d %H:%M")
        for alert in alerts if isinstance(alert.get("timestamp"), (int, float))
    )

    return {
        "types": type_counts,
        "timestamps": timestamp_counts
    }

@app.route('/')
def index():
    alerts = load_alerts()
    data = generate_plot_data(alerts)

    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent

    return render_template("index.html",
                           total_alerts=len(alerts),
                           alert_types=data["types"],
                           timestamps=data["timestamps"],
                           cpu_usage=cpu,
                           memory_usage=mem)

# Optional JSON route if needed by frontend
@app.route('/api/alerts')
def api_alerts():
    return jsonify(load_alerts())

if __name__ == '__main__':
    os.makedirs("logs", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    app.run(debug=True, host='127.0.0.1', port=5000)
