# leetcode_reminder_app/scheduler.py
from dotenv import load_dotenv
import requests
import psycopg2
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import ssl
import time
import schedule
load_dotenv()
# Email config
SENDER_EMAIL = "ansuashish291@gmail.com"
SENDER_PASSWORD = "qjeh fdag ylan lgzw"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

# Load DB connection string from env
DB_URL = os.getenv("DATABASE_URL")

def get_connection():
    return psycopg2.connect(DB_URL, sslmode='require')

# ✅ Fetch today's challenge slug
def get_today_challenge_title():
    url = "https://leetcode.com/graphql"
    payload = {
        "operationName": "questionOfToday",
        "query": """
        query questionOfToday {
          activeDailyCodingChallengeQuestion {
            question {
              title
              titleSlug
            }
          }
        }
        """,
        "variables": {}
    }
    headers = {"Content-Type": "application/json"}
    res = requests.post(url, json=payload, headers=headers)
    return res.json()['data']['activeDailyCodingChallengeQuestion']['question']['titleSlug']

# ✅ Check if user has solved today's challenge
def has_solved_today(username, today_slug):
    url = "https://leetcode.com/graphql"
    payload = {
        "operationName": "recentAcSubmissions",
        "variables": {"username": username, "limit": 20},
        "query": """
        query recentAcSubmissions($username: String!, $limit: Int!) {
          recentAcSubmissionList(username: $username, limit: $limit) {
            titleSlug
            timestamp
          }
        }
        """
    }
    res = requests.post(url, json=payload)
    subs = res.json()['data']['recentAcSubmissionList']
    today = datetime.utcnow().date()
    for sub in subs:
        sub_date = datetime.utcfromtimestamp(int(sub['timestamp'])).date()
        if sub_date == today and sub['titleSlug'] == today_slug:
            return True
    return False

# ✅ Send email reminder
def send_reminder_email(recipient_email, username):
    subject = "⏰ LeetCode Daily Challenge Reminder"
    body = f"""
    <html>
    <body>
      <p>Hi {username},</p>
      <p>You haven’t completed today’s LeetCode daily challenge yet.</p>
      <p><a href='https://leetcode.com/problemset/all/'>Go solve it now »</a></p>
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

# ✅ Core reminder logic
def check_all_users():
    now = datetime.utcnow()
    five_min_ago = now - timedelta(minutes=5)

    start = five_min_ago.strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    today_slug = get_today_challenge_title()

    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT username, email FROM users
            WHERE verified = 1
              AND alarm_time_utc BETWEEN %s AND %s
            ORDER BY alarm_time_utc ASC
        """, (start, end))

        users = c.fetchall()

        for username, email in users:
            try:
                if not has_solved_today(username, today_slug):
                    send_reminder_email(email, username)
                    print(f"📩 Sent reminder to {username}")
                else:
                    print(f"✅ {username} already solved today’s challenge.")
            except Exception as e:
                print(f"❌ Error processing {username}: {e}")

    except Exception as db_err:
        print(f"❌ DB error: {db_err}")
    finally:
        if conn:
            conn.close()

# 🕓 Run every 5 mins
if __name__ == "__main__":
    schedule.every(5).minutes.do(check_all_users)
    print("📬 Scheduler running every 5 minutes...")
    while True:
        schedule.run_pending()
        time.sleep(1)
