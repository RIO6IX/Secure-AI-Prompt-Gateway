"""Provision the first administrator from the local console, never over HTTP."""
import getpass
from datetime import datetime, timezone
from uuid import uuid4

try:
    from .app import connect, init_db, password_hash, RegisterIn, security
except ImportError:
    from app import connect, init_db, password_hash, RegisterIn, security


def main():
    name = input("Administrator name: ").strip()
    email = input("Administrator email: ").strip().lower()
    password = getpass.getpass("Password (12-128 characters): ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    RegisterIn(name=name, email=email, password=password)
    if not name or "@" not in email:
        raise SystemExit("A name and valid email are required")
    init_db()
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users WHERE role='admin' AND active=1").fetchone():
            raise SystemExit("An active administrator already exists; use Admin Panel")
        identifier = "USR-" + uuid4().hex[:10].upper()
        db.execute("INSERT INTO users(id,name,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
                   (identifier, name, email, password_hash(password), "admin", datetime.now(timezone.utc).isoformat()))
        security.change(db, email, "ADMIN_BOOTSTRAPPED", identifier, {})
    print("Administrator created. Sign in using the existing login page.")


if __name__ == "__main__":
    main()
