import os
import psycopg2
from flask import flash
from flask import Flask, request, session, redirect, url_for,render_template, render_template_string, jsonify
from flask_session import Session
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlencode
import requests
from datetime import datetime
from pytz import all_timezones
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-key")
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# ------------------- DB CONNECTION --------------------
DB_URL = os.getenv("DATABASE_URL")
def get_connection():
    return psycopg2.connect(DB_URL, sslmode='require')

# ------------------- EMAIL VERIFICATION ----------------
s = URLSafeTimedSerializer(app.secret_key)

def generate_verification_token(email, password_hash, username):
    return s.dumps({"email": email, "password_hash": password_hash, "username": username}, salt="verify")

def confirm_verification_token(token, max_age=3600):
    try:
        data = s.loads(token, salt="verify", max_age=max_age)
        return data
    except Exception:
        return None

# ------------------- GOOGLE OAUTH -----------------------
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI" )

# --------------------------------------------------------
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


def send_verification_email(email, verification_link):
    sender_email = os.environ.get("EMAIL")
    sender_password = os.environ.get("EMAIL_PASSWORD")
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Verify your email for Leetcode Reminder"
    message["From"] = sender_email
    message["To"] = email

    text = f"""\
    Hi,
    Please click the link below to verify your email address and activate your account:
    {verification_link}
    """
    html = f"""\
    <html>
      <body>
        <p>Hi,<br><br>
           Please verify your email address by clicking the link below:<br>
           <a href="{verification_link}">Verify Email</a>
        </p>
      </body>
    </html>
    """

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    message.attach(part1)
    message.attach(part2)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
            print(f"✅ Verification email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send email to {email}: {e}")

# ------------------- ROUTES -----------------------------

@app.route("/")
def home():
    if 'user_id' in session:
        return redirect("/dashboard")
    return redirect("/login")

# ====== Signup ======
@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template("signup.html")

@app.route("/signup", methods=["POST"])
def signup():
    email = request.form.get("email")
    password = request.form.get("password")
    username = request.form.get("username")

    if not email or not password:
        flash("Email and password are required.", "danger")
        return redirect("/signup")

    hashed_pw = generate_password_hash(password)
    token = generate_verification_token(email, hashed_pw, username)

    verification_link = f"{request.host_url}verify?token={token}"
    send_verification_email(email, verification_link)

    flash("Verification email sent. Please check your inbox.", "success")
    return redirect("/login")


@app.route("/verify")
def verify_email():
    token = request.args.get("token")
    data = confirm_verification_token(token)
    if not data:
        return "Invalid or expired token"

    email = data["email"]
    hashed_pw = data["password_hash"]
    username = data["username"]
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    if cur.fetchone():
        return "Email already verified"

    cur.execute("INSERT INTO users (email, username, password) VALUES (%s, %s, %s)", (email, username, hashed_pw))
    conn.commit()
    cur.close()
    conn.close()
    return "Email verified. You can now login."

# ====== Login ======
@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row or not check_password_hash(row[2], password):
        flash("Invalid email or password", "danger")
        print("invalid")
        return redirect("/login")

    session["user_id"] = row[0]
    session["username"] = row[1]
    session["email"] = email

    return redirect("/dashboard")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect("/login")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, leetcode_username, local_alarm_time, timezone FROM schedules
        WHERE user_id = %s
    """, (session['user_id'],))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    schedules = [
        {
            "id": r[0],
            "leetcode_username": r[1],
            "local_alarm_time": r[2].strftime("%H:%M"),
            "timezone": r[3]
        }
        for r in rows
    ]

    return render_template("dashboard.html",
                           schedules=schedules,
                           username=session.get("username"),
                           timezones=all_timezones)



@app.route("/add_schedule", methods=["POST"])
def add_schedule():
    if 'user_id' not in session:
        return redirect("/login")

    leetcode_username = request.form["leetcode_username"]
    local_time = request.form["local_alarm_time"]
    timezone = request.form["timezone"]

    from pytz import timezone as tz, utc
    local = tz(timezone)
    naive_time = datetime.strptime(local_time, "%H:%M")
    localized = local.localize(datetime.combine(datetime.utcnow().date(), naive_time.time()))
    utc_time = localized.astimezone(utc).time()

    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO schedules (user_id, leetcode_username, local_alarm_time, timezone, utc_time)
            VALUES (%s, %s, %s, %s, %s)
        """, (session['user_id'], leetcode_username, local_time, timezone, utc_time))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return "Duplicate schedule", 409
    finally:
        cur.close()
        conn.close()

    return redirect("/dashboard")


@app.route("/delete_schedule", methods=["POST"])
def delete_schedule():
    if 'user_id' not in session:
        return redirect("/login")

    schedule_id = request.form["schedule_id"]

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM schedules WHERE id=%s AND user_id=%s", (schedule_id, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()

    return redirect("/dashboard")


def send_password_reset_email(email, reset_link):
    sender_email = os.environ.get("EMAIL")
    sender_password = os.environ.get("EMAIL_PASSWORD")

    message = MIMEMultipart("alternative")
    message["Subject"] = "Reset your password - Leetcode Reminder"
    message["From"] = sender_email
    message["To"] = email

    text = f"Hi,\nClick the link below to reset your password:\n{reset_link}"
    html = f"""\
    <html>
      <body>
        <p>Hi,<br><br>
           Click the link below to reset your password:<br>
           <a href="{reset_link}">Reset Password</a>
        </p>
      </body>
    </html>
    """

    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
            print(f"✅ Reset email sent to {email}")
    except Exception as e:
        print(f"❌ Failed to send reset email to {email}: {e}")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token")
    if request.method == "GET":
        return render_template("reset_password.html", token=token)

    token = request.form.get("token")
    new_password = request.form.get("password")
    if not token:
        flash("You are Unauthorised for this activity!!", "danger")
        return redirect("/login")
    if not new_password:
        flash("Password missing!!", "danger")
        return render_template("reset_password.html", token=token)
    try:
        email = s.loads(token, salt="reset-password", max_age=3600)
    except:
        flash("Invalid or expired token.", "danger")
        return redirect("/forgot_password")

    hashed_pw = generate_password_hash(new_password)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_pw, email))
    conn.commit()
    cur.close()
    conn.close()

    flash("Password reset successful. Please log in.", "success")
    return redirect("/login")

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    email = request.form.get("email")
    if not email:
        flash("Please enter your email address.", "danger")
        return redirect("/forgot_password")

    # Check if the user exists
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        flash("Email is not registered.", "danger")
        return redirect("/forgot_password")

    # Generate reset token
    token = s.dumps(email, salt="reset-password")

    reset_link = f"{request.host_url}reset_password?token={token}"
    send_password_reset_email(email, reset_link)

    flash("A reset link has been sent to email.", "info")
    return redirect("/login")


# ------------------- GOOGLE LOGIN ROUTES ------------------------

@app.route("/google-login")
def google_login():
    query = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "scope": "openid email profile",
        "response_type": "code",
        "access_type": "offline"
    }
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(query)}")

@app.route("/oauth2callback")
def oauth2callback():
    code = request.args.get("code")

    # Exchange code for token
    res = requests.post("https://oauth2.googleapis.com/token", data={
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    })
    tokens = res.json()
    id_token = tokens["id_token"]

    # Decode token to get user info
    user_info = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }).json()

    email = user_info["email"]
    username = user_info.get("name", "")
    print(email, username)
    # Ensure user exists in DB
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    row = cur.fetchone()

    if row:
        user_id = row[0]
    else:
        cur.execute("INSERT INTO users (email, username, password) VALUES (%s, %s, %s) RETURNING id", (email, username, "google-oauth"))
        user_id = cur.fetchone()[0]
        conn.commit()

    cur.close()
    conn.close()

    session['user_id'] = user_id
    session['username'] = username
    session['email'] = email
    return redirect("/dashboard")

# ------------------- MAIN -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
