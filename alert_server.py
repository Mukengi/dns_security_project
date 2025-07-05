from flask import Flask, jsonify
import os
import json

app = Flask(__name__)
ALERTS_FILE = "logs/live_alerts.jsonl"

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    alerts = []

    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            alerts.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            return jsonify({"error": f"Failed to read alerts: {str(e)}"}), 500

    return jsonify(alerts)

if __name__ == "__main__":
    # Run on all interfaces, so you can connect via 127.0.0.1 or your IP
    app.run(host='0.0.0.0', port=5000)
