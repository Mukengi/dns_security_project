# email_alert.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_EMAIL = 'puritymukengi@gmail.com'
SENDER_PASSWORD = 'zfya ihyc jjbi lwqv'  
RECIPIENT_EMAIL = 'recipient@example.com'

def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[✔] Email alert sent to {RECIPIENT_EMAIL}")
    except Exception as e:
        print(f"[✖] Failed to send email: {e}")
