# POSITIVE: SQL injection — should trigger py-sql-injection, py-sql-injection-fstring
import sqlite3
from flask import request

def get_user():
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    user_id = request.args.get('id')
    
    # Unsafe: string concatenation
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    # Unsafe: f-string
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_id}'")
    # Unsafe: % formatting
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
