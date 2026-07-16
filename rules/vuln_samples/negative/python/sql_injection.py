# NEGATIVE: Safe SQL — should NOT trigger sql injection rules
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # Safe: ORM equivalent
    cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
