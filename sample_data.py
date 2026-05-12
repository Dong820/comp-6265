"""
Run this script once to populate the database with sample users and consent records.

Usage:
    python sample_data.py
"""

from app import app
from models import db, User, ConsentRecord

# Sample users — each represents a different consent profile
USERS = [
    {"name": "Alice Mercer",  "email": "alice@example.com"},
    {"name": "Bob Tanaka",    "email": "bob@example.com"},
    {"name": "Carol Osei",    "email": "carol@example.com"},
]

# (user index, purpose, allowed) — index matches the USERS list above
CONSENTS = [
    # Alice consents to research and analytics but not advertising
    (0, "research",    True),
    (0, "analytics",   True),
    (0, "advertising", False),
    # Bob opts in to all three purposes
    (1, "research",    True),
    (1, "analytics",   True),
    (1, "advertising", True),
    # Carol declines everything
    (2, "research",    False),
    (2, "analytics",   False),
    (2, "advertising", False),
]


def populate():
    """Drop existing data and insert fresh sample records."""
    with app.app_context():
        # Wipe tables so the script is idempotent when re-run
        ConsentRecord.query.delete()
        User.query.delete()
        db.session.commit()

        # Insert users and keep references for linking consent records
        user_objects = []
        for u in USERS:
            user = User(name=u["name"], email=u["email"])
            db.session.add(user)
            user_objects.append(user)

        # Flush so that auto-generated IDs are available before we create FKs
        db.session.flush()

        # Insert consent records using the flushed user IDs
        for user_index, purpose, allowed in CONSENTS:
            record = ConsentRecord(
                user_id=user_objects[user_index].id,
                purpose=purpose,
                allowed=allowed,
            )
            db.session.add(record)

        db.session.commit()

        # Print a summary so the user can verify the inserted data
        print("Sample data inserted successfully.\n")
        for user in user_objects:
            records = ConsentRecord.query.filter_by(user_id=user.id).all()
            consent_summary = ", ".join(
                f"{r.purpose}={'yes' if r.allowed else 'no'}" for r in records
            )
            print(f"  [{user.id}] {user.name} <{user.email}> — {consent_summary}")


if __name__ == "__main__":
    populate()
