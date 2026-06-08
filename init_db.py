import sqlite3

# 🔌 Connect to the database (it creates the file if it doesn't exist)
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# 🏗️ Execute the SQL command to create your table
cursor.execute('''
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
''')

# 💾 Save changes and close the connection
conn.commit()
conn.close()

print("Database and table created successfully!")