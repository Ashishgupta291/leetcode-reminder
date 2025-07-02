# leetcode_reminder_app/email_utils.py

import smtplib
import ssl
import uuid
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import quote_plus

# CONFIGURE THIS
SENDER_EMAIL = "ansuashish291@gmail.com"
SENDER_PASSWORD = "qjeh fdag ylan lgzw"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

# Replace with your hosted server domain if not running locally
BASE_URL = "http://localhost:5000"

def generate_token(email):
    return str(uuid.uuid4())

def send_verification_email(recipient_email, token, deactivation=False):
    subject = "Deactivate Your LeetCode Reminder" if deactivation else "Verify Your LeetCode Reminder Activation"
    action_url = f"{BASE_URL}/deactivate/confirm/{quote_plus(token)}" if deactivation else f"{BASE_URL}/verify/{quote_plus(token)}"
    action_text = "Deactivate Reminder" if deactivation else "Activate Reminder"

    body = f"""
    <html>
    <body>
        <p>Hi there,</p>
        <p>{'Click below to deactivate your daily reminder' if deactivation else 'Click below to activate your daily LeetCode reminder:'}</p>
        <p><a href="{action_url}">{action_text}</a></p>
        <p>If you didn’t request this, you can ignore this email.</p>
    </body>
    </html>
    """

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = SENDER_EMAIL
    message["To"] = recipient_email
    message.attach(MIMEText(body, "html"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
