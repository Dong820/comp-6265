from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    """Represents a registered user in the system."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)

    # Relationships
    consent_records = db.relationship("ConsentRecord", backref="user", lazy=True)
    audit_logs = db.relationship("AuditLog", backref="user", lazy=True)

    def to_dict(self):
        """Return a JSON-serialisable representation of this user."""
        return {"id": self.id, "name": self.name, "email": self.email}


class ConsentRecord(db.Model):
    """Stores a single purpose-level consent decision for one user."""
    __tablename__ = "consent_records"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Purpose identifies the category of data use (e.g. "analytics", "research")
    purpose = db.Column(db.String(64), nullable=False)
    # allowed=True means the user has opted in for this purpose
    allowed = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # valid_until is optional; if set, consent is treated as expired after this datetime
    valid_until = db.Column(db.DateTime, nullable=True)
    # cascade ensures category rows are deleted when the parent ConsentRecord is deleted
    data_categories = db.relationship(
        "ConsentDataCategory", backref="consent_record",
        lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        """Return a JSON-serialisable representation of this consent record."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "purpose": self.purpose,
            "allowed": self.allowed,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class ConsentDataCategory(db.Model):
    """
    Records which specific data fields a user has consented to share
    for a given ConsentRecord (user + purpose pair).

    Allowed categories: email, age_group, purchase_history, location
    """
    __tablename__ = "consent_data_categories"

    id = db.Column(db.Integer, primary_key=True)
    consent_id = db.Column(db.Integer, db.ForeignKey("consent_records.id"), nullable=False)
    # category names the individual data field type the user permits
    category = db.Column(db.String(64), nullable=False)

    def to_dict(self):
        """Return a JSON-serialisable representation of this data category entry."""
        return {"id": self.id, "consent_id": self.consent_id, "category": self.category}


class AuditLog(db.Model):
    """Immutable record of every access-request decision made by the policy engine."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    purpose = db.Column(db.String(64), nullable=False)
    # decision is the outcome: "allowed", "partially_allowed", or "denied"
    decision = db.Column(db.String(32), nullable=False)
    # reason is the human-readable explanation produced by the policy engine
    reason = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # previous_hash links this entry to its predecessor, forming a tamper-evident chain
    previous_hash = db.Column(db.String(64), nullable=True)
    # entry_hash is sha256(this entry's data + previous_hash)
    entry_hash = db.Column(db.String(64), nullable=True)

    def to_dict(self):
        """Return a JSON-serialisable representation of this audit log entry."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "purpose": self.purpose,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }
