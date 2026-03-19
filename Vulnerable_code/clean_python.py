# ═══════════════════════════════════════════════════════════════
# TEST FILE: clean_python.py
# EXPECTED: 0 findings (ZERO false positives)
# Every pattern here LOOKS dangerous but is actually safe.
# If the scanner flags anything here, it's a false positive.
# ═══════════════════════════════════════════════════════════════

import os
import sqlite3
import hashlib
import subprocess
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)


# SAFE: Parameterized query — not SQL injection
def get_user_safe(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result


# SAFE: Array-based subprocess — not command injection
def ping_safe(host):
    result = subprocess.run(
        ["ping", "-c", "4", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout


# SAFE: Using secrets module — not weak random
def generate_token():
    return secrets.token_hex(32)


# SAFE: SHA-256 — not weak hash
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()


# SAFE: Bcrypt for passwords
def hash_password_safe(password):
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


# SAFE: Path validation — not path traversal
def read_file_safe(filename):
    base = os.path.realpath("/var/data")
    full = os.path.realpath(os.path.join(base, filename))
    if not full.startswith(base + os.sep):
        raise ValueError("Path traversal blocked")
    with open(full) as f:
        return f.read()


# SAFE: Environment variable — not hardcoded secret
API_KEY = os.environ.get("API_KEY")
DB_PASSWORD = os.getenv("DB_PASSWORD")


# SAFE: Using render_template (not render_template_string)
@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    return jsonify({"message": f"Hello {name}"})


# SAFE: URL validation for SSRF prevention
@app.route("/fetch")
def fetch_safe():
    import requests
    from urllib.parse import urlparse

    ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
    url = request.args.get("url", "")
    parsed = urlparse(url)

    if parsed.hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "Host not allowed"}), 403

    response = requests.get(url, timeout=10)
    return jsonify({"status": response.status_code})


if __name__ == "__main__":
    app.run(debug=False)
