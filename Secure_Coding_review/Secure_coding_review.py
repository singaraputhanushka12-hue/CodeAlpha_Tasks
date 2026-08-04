"""
Sample Application: Simple User Management API (Flask)
--------------------------------------------------------
NOTE: This application intentionally contains security vulnerabilities.
It exists ONLY as a subject for the secure-coding review exercise
(see security_review_report.md). Do not deploy this code as-is.
"""

import sqlite3
import subprocess
import hashlib
import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# --- VULNERABILITY: Hardcoded secret key ---
app.secret_key = "supersecret123"

# --- VULNERABILITY: Hardcoded database credentials / config ---
DB_PATH = "users.db"
ADMIN_PASSWORD = "admin123"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # --- VULNERABILITY: SQL Injection ---
    # User input concatenated directly into the SQL query.
    conn = get_db()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor = conn.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "user": user})
    return jsonify({"status": "failed"}), 401


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    email = request.form.get("email")

    # --- VULNERABILITY: Weak hashing algorithm (MD5, no salt) ---
    hashed_pw = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
        (username, hashed_pw, email),
    )
    conn.commit()
    return jsonify({"status": "registered"})


@app.route("/profile/<username>")
def profile(username):
    # --- VULNERABILITY: Reflected XSS ---
    # User-supplied 'username' rendered directly into HTML without escaping.
    template = f"<h1>Welcome, {username}!</h1>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # --- VULNERABILITY: OS Command Injection ---
    # User input passed to shell via os.system/subprocess with shell=True.
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})


@app.route("/export")
def export_data():
    filename = request.args.get("file", "export.csv")

    # --- VULNERABILITY: Path Traversal ---
    # No validation that 'filename' stays within an intended directory.
    filepath = os.path.join("exports", filename)
    with open(filepath, "r") as f:
        content = f.read()
    return content


@app.route("/admin")
def admin_panel():
    # --- VULNERABILITY: Broken access control ---
    # "Authentication" via a query parameter compared to a hardcoded password.
    # No session/token check, no rate limiting on guesses.
    if request.args.get("password") == ADMIN_PASSWORD:
        return jsonify({"status": "welcome admin"})
    return jsonify({"status": "denied"}), 403


@app.errorhandler(500)
def server_error(e):
    # --- VULNERABILITY: Verbose error disclosure ---
    return jsonify({"error": str(e), "debug": True}), 500


if __name__ == "__main__":
    init_db()
    # --- VULNERABILITY: Debug mode enabled, binds to all interfaces ---
    app.run(host="0.0.0.0", port=5000, debug=True)