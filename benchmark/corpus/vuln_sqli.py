import sqlite3
def get_user(username):
    conn = sqlite3.connect("app.db")
    # VULN: user input formatted directly into SQL
    query = "SELECT * FROM users WHERE username = '%s'" % username
    return conn.execute(query).fetchall()
