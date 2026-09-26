import sqlite3
def get_user(username):
    conn = sqlite3.connect("app.db")
    # SAFE: parameterized query
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
