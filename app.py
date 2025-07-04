from flask import Flask, render_template, request
from email_utils import send_verification_email, generate_token
from db import init_db, add_user, verify_user, get_user_by_token, deactivate_user, user_exists, get_existing_token
import os
init_db()
app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/activate", methods=["POST"])
def activate():
    username = request.form['username']
    email = request.form['email']
    time = request.form['alarm_time']
    timezone = request.form['timezone']
    token = get_existing_token(email) if user_exists(email) else generate_token(email)
    add_user(username, email, time, timezone, token)
    send_verification_email(email, token)
    return "Verification email sent. Please check your inbox."

@app.route("/verify/<token>")
def verify(token):
    user = get_user_by_token(token)
    if user:
        verify_user(token)
        return "✅ Your reminders are now active!"
    return "❌ Invalid or expired token."

@app.route("/deactivate", methods=["POST"])
def deactivate():
    email = request.form['email']
    if not user_exists(email):
        return "No schedule found."
    token = get_existing_token(email)
    send_verification_email(email, token, deactivation=True)
    return "Verification email sent to deactivate."

@app.route("/deactivate/confirm/<token>")
def confirm_deactivation(token):
    user = get_user_by_token(token)
    if user:
        deactivate_user(token)
        return "✅ Your schedules deactivated successfully."
    return "❌ Invalid deactivation link."

@app.route("/admin/schedules")
def view_schedules():
    from db import get_verified_users
    users = get_verified_users()
    if not users:
        return "No active reminders found."
    return "<br>".join([f"{u[0]} | {u[1]} | {u[2]} | {u[3]}" for u in users])

if __name__ == "__main__":
    app.run(debug=True)
