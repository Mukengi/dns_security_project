import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ALERTS_FILE = "logs/live_alerts.jsonl"

def load_dga_list(dga_file="dga_list.txt"):
    """Load a list of known DGA domains."""
    dga_domains = set()
    if os.path.exists(dga_file):
        try:
            with open(dga_file, 'r') as f:
                dga_domains = {line.strip().lower() for line in f if line.strip()}
            logging.info(f"Loaded {len(dga_domains)} DGA domains from {dga_file}")
        except IOError as e:
            logging.error(f"Error reading {dga_file}: {e}")
    else:
        logging.warning(f"{dga_file} not found. Using heuristic validation.")
    return dga_domains

def validate_alerts(alerts, dga_domains):
    """Validate alerts against DGA list or heuristics."""
    true_positives = 0
    total_alerts = len(alerts)

    for alert in alerts:
        domain = alert.get("domain", "").lower()
        alert_type = alert.get("type", "")
        is_true = False

        if alert_type == "dga_detected":
            if dga_domains and domain in dga_domains:
                is_true = True
            elif len(domain) > 15 and domain.count(".") < 2:  # Heuristic: Long domain, few subdomains
                is_true = True
        elif alert_type == "dns_tunneling":
            if len(domain.split(".")) > 4 or len(domain) > 50:  # Match detection rule
                is_true = True

        if is_true:
            true_positives += 1

    accuracy = true_positives / total_alerts if total_alerts > 0 else 0.0
    return accuracy, true_positives, total_alerts

def main():
    if not os.path.exists(ALERTS_FILE):
        logging.error(f"Alert file {ALERTS_FILE} not found")
        return

    alerts = []
    try:
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError as e:
                    logging.error(f"Failed to parse alert: {e}")
                    continue
    except IOError as e:
        logging.error(f"Error reading {ALERTS_FILE}: {e}")
        return

    dga_domains = load_dga_list()
    accuracy, true_positives, total_alerts = validate_alerts(alerts, dga_domains)

    logging.info(f"Total alerts: {total_alerts}")
    logging.info(f"True positives: {true_positives}")
    logging.info(f"Estimated accuracy: {accuracy*100:.2f}%")

    # Save sample for manual review
    with open("accuracy_sample.csv", 'w') as out:
        out.write("domain,type,is_true\n")
        for alert in alerts[:50]:  # First 50 alerts
            is_true = "True" if validate_alerts([alert], dga_domains)[0] == 1.0 else "False"
            out.write(f"{alert.get('domain')},{alert.get('type')},{is_true}\n")

if __name__ == "__main__":
    main()
