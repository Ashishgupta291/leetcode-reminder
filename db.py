# leetcode_reminder_app/db.py

import psycopg2
import os
from datetime import datetime
import pytz

DB_URL = os.getenv("DATABASE_URL")

def get_connection():
    return psycopg2.connect(DB_URL, sslmode='require')


def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            alarm_time TEXT NOT NULL,
            timezone TEXT NOT NULL,
            token TEXT NOT NULL,
            alarm_time_utc TEXT,
            verified INTEGER DEFAULT 0,
            UNIQUE (email, username, alarm_time_utc)
        )
    ''')
    conn.commit()
    conn.close()


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

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO users (username, email, alarm_time, timezone, token, alarm_time_utc, verified)
        VALUES (%s, %s, %s, %s, %s, %s, 0)
        ON CONFLICT (email, username, alarm_time_utc) DO NOTHING
    """, (username, email, alarm_time, timezone, token, utc_str))
    conn.commit()
    conn.close()


def user_exists(email):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE email = %s", (email,))
    result = c.fetchone()
    conn.close()
    return result is not None


def get_user_by_token(token):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE token = %s", (token,))
    result = c.fetchone()
    conn.close()
    return result


def verify_user(token):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET verified = 1 WHERE token = %s", (token,))
    conn.commit()
    conn.close()


def deactivate_user(token):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE token = %s", (token,))
    conn.commit()
    conn.close()


def get_verified_users():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT username, email, alarm_time, timezone, alarm_time_utc FROM users WHERE verified = 1")
    result = c.fetchall()
    conn.close()
    return result


def get_existing_token(email):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT token FROM users WHERE email = %s", (email,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None
