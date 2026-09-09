import sqlite3

conn = sqlite3.connect("audit_logs.sqlite3")

conn.execute("""
UPDATE users
SET role = 'admin'
WHERE email = 'admin@secureai.local'
""")

conn.commit()

print("Role updated!")

conn.close()