from flask import Flask, render_template, send_file
import json
import os

app = Flask(__name__)

ALERTS_FILE = "logs/live_alerts.jsonl"

def load_alerts():
    alerts = []
    dga_count = 0
    dns_tunnel_count = 0

    if not os.path.exists(ALERTS_FILE):
        return alerts, dga_count, dns_tunnel_count

    with open(ALERTS_FILE, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line.strip())
                alerts.append(alert)
                if alert.get("type") == "dga_detected":
                    dga_count += 1
                elif alert.get("type") == "dns_tunneling":
                    dns_tunnel_count += 1
            except json.JSONDecodeError:
                continue

    return alerts, dga_count, dns_tunnel_count

@app.route('/')
def index():
    alerts, dga_count, dns_tunnel_count = load_alerts()

    chart_data = {
        "dns_tunnel_alerts": dns_tunnel_count,
        "dga_alerts": dga_count
    }

    return render_template(
        "dashboard.html",
        total_alerts=len(alerts),
        dga_alerts=dga_count,
        dns_tunnel_alerts=dns_tunnel_count,
        chart_data=json.dumps(chart_data),
        alerts=alerts
    )

@app.route('/download')
def download_alerts():
    if not os.path.exists(ALERTS_FILE):
        return "No alerts to download", 404
    return send_file(ALERTS_FILE, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
