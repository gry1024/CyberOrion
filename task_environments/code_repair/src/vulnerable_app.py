import sqlite3


def find_user(database_path: str, username: str) -> tuple:
    connection = sqlite3.connect(database_path)
    try:
        query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
        return connection.execute(query).fetchone()
    finally:
        connection.close()
