"""Local operator setup for synthetic demo accounts in an empty database."""
from datetime import datetime, timezone
from pathlib import Path
import secrets

from .app import connect, init_db, password_hash, security


def main():
    init_db()
    credentials_path = Path(__file__).resolve().parents[1] / ".local-demo" / "credentials.txt"
    with connect() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise SystemExit("Accounts already exist. No accounts were changed; use the existing login or bootstrap procedure.")
        password = secrets.token_urlsafe(20)
        digest = password_hash(password)
        rows = []
        for role in ("admin", "user", "approver", "auditor"):
            identifier = "DEMO-" + role.upper()
            email = f"{role}@component3.example.test"
            db.execute("INSERT INTO users(id,name,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
                       (identifier, f"Demo {role.title()}", email, digest, role, datetime.now(timezone.utc).isoformat()))
            security.change(db, "local-demo-operator", "DEMO_ACCOUNT_CREATED", identifier, {"role": role})
            rows.append(f"{role}: {email}")
        credentials_path.parent.mkdir(exist_ok=True)
        credentials_path.write_text("LOCAL SYNTHETIC DEMO ONLY - DO NOT COMMIT OR SHARE\n\n" + "\n".join(rows) + f"\n\nPassword for these local demo accounts: {password}\n", encoding="utf-8")
    print("Four synthetic demo accounts created. Credentials saved in ignored .local-demo/credentials.txt.")


if __name__ == "__main__":
    main()
