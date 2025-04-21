import sqlite3

# Connect to (or create) the users database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create the `users` table in `users.db`
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    otp_secret TEXT NOT NULL
)
""")

# Commit changes and close connection
conn.commit()
conn.close()

print("`users.db` setup completed! Table `users` is ready.")
