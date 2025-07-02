# leetcode_reminder_app/db.py

import sqlite3

DB_PATH = "verify.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            alarm_time TEXT NOT NULL,
            timezone TEXT NOT NULL,
            token TEXT NOT NULL,
            alarm_time_utc TEXT,
            verified INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

from datetime import datetime
import pytz

def add_user(username, email, alarm_time, timezone, token):
    # Convert local alarm_time + timezone to UTC timestamp
    local = pytz.timezone(timezone)
    now = datetime.now(local)
    local_time = datetime.strptime(alarm_time, "%H:%M").replace(
        year=now.year, month=now.month, day=now.day
    )
    localized_time = local.localize(local_time)
    utc_time = localized_time.astimezone(pytz.utc)
    utc_str = utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO users (username, email, alarm_time, timezone, token, alarm_time_utc) VALUES (?, ?, ?, ?, ?, ?)",
              (username, email, alarm_time, timezone, token, utc_str))
    conn.commit()
    conn.close()

def user_exists(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()
    return result is not None

def get_user_by_token(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE token = ?", (token,))
    result = c.fetchone()
    conn.close()
    return result

def verify_user(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET verified = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def deactivate_user(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def get_verified_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, email, alarm_time, timezone FROM users WHERE verified = 1")
    result = c.fetchall()
    conn.close()
    return result
def get_existing_token(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT token FROM users WHERE email = ?", (email,))
    result = c.fetchone()
    conn.close()
    return result[0]
