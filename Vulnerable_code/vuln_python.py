# ═══════════════════════════════════════════════════════════════
# TEST FILE: vuln_python.py
# EXPECTED: 8 findings (all True Positives)
# ═══════════════════════════════════════════════════════════════

import os
import subprocess
import pickle
import hashlib
import sqlite3
import requests
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# ── VULN 1: SQL Injection (CWE-89) ──────────────────────────
# EXPECTED: Critical — f-string in execute()
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchone())


# ── VULN 2: Command Injection (CWE-78) ──────────────────────
# EXPECTED: Critical — user input passed to os.system()
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    os.system("ping -c 4 " + host)
    return "Done"


# ── VULN 3: Insecure Deserialization (CWE-502) ──────────────
# EXPECTED: Critical — pickle.loads on user data
@app.route("/load", methods=["POST"])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)


# ── VULN 4: XSS / SSTI (CWE-79) ────────────────────────────
# EXPECTED: High — render_template_string with user input
@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    return render_template_string(f"<h1>Hello {name}</h1>")


# ── VULN 5: Path Traversal (CWE-22) ─────────────────────────
# EXPECTED: High — user input in file open path
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(os.path.join("/var/data", filename)) as f:
        return f.read()


# ── VULN 6: Hardcoded Secret (CWE-798) ──────────────────────
# EXPECTED: High — API key hardcoded in source
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
DATABASE_PASSWORD = "SuperSecret123!"


# ── VULN 7: SSRF (CWE-918) ──────────────────────────────────
# EXPECTED: High — user-controlled URL in requests.get()
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text


# ── VULN 8: Weak Hash (CWE-328) ─────────────────────────────
# EXPECTED: Medium — MD5 for password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


if __name__ == "__main__":
    app.run(debug=True)
