import sqlite3

conn = sqlite3.connect("audit_logs.sqlite3")
conn.row_factory = sqlite3.Row

cursor = conn.execute("SELECT name, email, role FROM users")

print("\nUsers in database:\n")

for row in cursor.fetchall():
    print(dict(row))

conn.close()