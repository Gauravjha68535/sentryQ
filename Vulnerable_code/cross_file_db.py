# ═══════════════════════════════════════════════════════════════
# TEST FILE: cross_file_db.py
# EXPECTED: 3 SQL Injection findings
# Without AI Smart Taint (Phase 3A): scanner sees f-string SQL
#   but doesn't know uid/query/user_id come from user input.
# With AI Smart Taint: traces back to cross_file_routes.py
#   and confirms these are user-controlled → True Positive.
# ═══════════════════════════════════════════════════════════════

import sqlite3

DB_PATH = "app.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def get_user(uid):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    result = cursor.fetchone()
    conn.close()
    return result


def search_users(query):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
    results = cursor.fetchall()
    conn.close()
    return results


def delete_user(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
