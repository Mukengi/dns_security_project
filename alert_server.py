from flask import Flask, jsonify
import os
import json

app = Flask(__name__)
ALERTS_FILE = "logs/live_alerts.jsonl"

@app.route("/alerts")
def get_alerts():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    return jsonify(alerts)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
