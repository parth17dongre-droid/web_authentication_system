import sqlite3


conn = sqlite3.connect('users.db')
cursor = conn.cursor()


cursor.execute('''
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    user_email TEXT UNIQUE NOT NULL,
    otp TEXT
);
''')
cursor.execute('''
CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    jti TEXT UNIQUE,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(username) REFERENCES accounts(username)
);
''')

conn.commit()
conn.close()

print("Database and table created successfully!")