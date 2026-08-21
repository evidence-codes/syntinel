import sqlite3


def get_user_by_name(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    # VULNERABLE: string-concatenated SQL — classic injection.
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    return cursor.fetchone()
