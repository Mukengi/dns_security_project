import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load credentials from environment variables or defaults
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "puritymukengi@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "zfya ihyc jjbi lwqv")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL", "puritymukengi@gmail.com")

def send_summary_email(total, dga, tunnel, dashboard_link):
    msg = MIMEMultipart()
    msg["Subject"] = "DNS IDS Alert Summary"
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    body = f"""
    <h2>Summary of Detected DNS Alerts</h2>
    <ul>
        <li><strong>Total Alerts:</strong> {total}</li>
        <li><strong>DGA Alerts:</strong> {dga}</li>
        <li><strong>DNS Tunneling Alerts:</strong> {tunnel}</li>
    </ul>
    <p>🔗 <a href="{dashboard_link}">View Full Dashboard</a></p>
    """
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
        logging.info("Summary email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

if __name__ == "__main__":
    send_summary_email(10, 4, 6, "http://127.0.0.1:5000")  # Test call


 




