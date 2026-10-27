import argparse
import os
from sqlalchemy import select
from backend.db import SessionLocal, User, audit
from backend.security import password_hash


def create_admin():
    username, password = (
        os.getenv("ADMIN_USERNAME", ""),
        os.getenv("ADMIN_PASSWORD", ""),
    )
    if not username or len(password) < 12:
        raise SystemExit(
            "Set ADMIN_USERNAME and ADMIN_PASSWORD (at least 12 characters) in your environment or .env first."
        )
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == username)):
            raise SystemExit(
                "User already exists; use reset-password to revoke sessions and replace password."
            )
        db.add(
            User(username=username, password_hash=password_hash(password), role="admin")
        )
        audit(db, "setup", "admin_created", username=username)
        db.commit()
    print("Administrator created. Credentials were not printed.")


def reset_password():
    from backend.db import Session

    username, password = (
        os.getenv("ADMIN_USERNAME", ""),
        os.getenv("ADMIN_PASSWORD", ""),
    )
    if not username or len(password) < 12:
        raise SystemExit(
            "Set administrator environment variables; password must contain at least 12 characters."
        )
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            raise SystemExit("User not found")
        user.password_hash = password_hash(password)
        for session in db.scalars(select(Session).where(Session.user_id == user.id)):
            db.delete(session)
        audit(db, "setup", "password_reset", username=username)
        db.commit()
    print("Password changed and all user sessions revoked.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-admin", "reset-password"])
    args = parser.parse_args()
    create_admin() if args.command == "create-admin" else reset_password()
