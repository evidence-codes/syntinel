import sqlite3


def get_user_by_name(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
