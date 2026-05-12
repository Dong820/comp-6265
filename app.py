from flask import Flask, request, jsonify, render_template
from models import db, User, ConsentRecord, AuditLog, ConsentDataCategory
from policy_engine import PolicyEngine
from audit_chain import compute_hash, verify_chain, GENESIS_HASH
from datetime import datetime
from sqlalchemy import inspect as sa_inspect, text
from werkzeug.exceptions import HTTPException
import traceback

app = Flask(__name__)

# Use a local SQLite database stored in the project directory
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///consent.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Bind SQLAlchemy to this Flask app instance
db.init_app(app)

def migrate_db():
    """
    Add columns that were introduced after the initial db.create_all().
    SQLite supports ALTER TABLE ... ADD COLUMN but not DROP/MODIFY, so this
    is safe to run repeatedly — it skips columns that already exist.
    """
    inspector = sa_inspect(db.engine)
    existing_tables = inspector.get_table_names()

    # consent_records gained valid_until in iteration 2
    if "consent_records" in existing_tables:
        cr_cols = {c["name"] for c in inspector.get_columns("consent_records")}
        with db.engine.connect() as conn:
            if "valid_until" not in cr_cols:
                conn.execute(text("ALTER TABLE consent_records ADD COLUMN valid_until DATETIME"))
                print("[migrate] Added consent_records.valid_until")
            conn.commit()

    # audit_logs gained decision width change + hash columns in iterations 3-4
    # SQLite cannot change column type, but widening String is a no-op in SQLite
    # (all text is stored as TEXT regardless), so only the missing columns matter.
    if "audit_logs" in existing_tables:
        al_cols = {c["name"] for c in inspector.get_columns("audit_logs")}
        with db.engine.connect() as conn:
            if "previous_hash" not in al_cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN previous_hash VARCHAR(64)"))
                print("[migrate] Added audit_logs.previous_hash")
            if "entry_hash" not in al_cols:
                conn.execute(text("ALTER TABLE audit_logs ADD COLUMN entry_hash VARCHAR(64)"))
                print("[migrate] Added audit_logs.entry_hash")
            conn.commit()

    # consent_data_categories is a new table — db.create_all() handles it
    if "consent_data_categories" not in existing_tables:
        print("[migrate] consent_data_categories table will be created by db.create_all()")


# Create any missing tables, then patch any missing columns on existing tables
with app.app_context():
    db.create_all()
    migrate_db()

policy = PolicyEngine()


@app.errorhandler(Exception)
def handle_exception(e):
    """
    Convert any unhandled exception to a JSON error response.
    Without this, Flask returns an HTML 500 page which breaks JSON clients.
    The full traceback is printed to stdout so it appears in the terminal.
    """
    # Let Werkzeug's built-in HTTP exceptions (404, 405, etc.) pass through
    if isinstance(e, HTTPException):
        return e
    traceback.print_exc()
    return jsonify({"error": type(e).__name__, "detail": str(e)}), 500


@app.route("/")
def index():
    """Serve the main consent management UI."""
    # Provide the list of users so the frontend can populate dropdowns
    users = User.query.all()
    return render_template("index.html", users=[u.to_dict() for u in users])


@app.route("/consent", methods=["POST"])
def save_consent():
    """
    Save or update a user's consent preferences.

    Expected JSON body:
        {
            "user_id": 1,
            "consents": {
                "research":    true,
                "analytics":   false,
                "advertising": true
            },
            "data_categories": ["email", "age_group"],   (optional)
            "valid_until": "2026-12-31T23:59:59"         (optional, ISO 8601)
        }
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    consents = data.get("consents", {})
    data_categories = data.get("data_categories", [])

    # Parse the optional expiry date; ignore malformed values rather than 500-ing
    valid_until = None
    raw_expiry = data.get("valid_until")
    if raw_expiry:
        try:
            valid_until = datetime.fromisoformat(raw_expiry)
        except ValueError:
            return jsonify({"error": "valid_until must be an ISO 8601 datetime string"}), 400

    # Validate that the referenced user actually exists
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Upsert: update existing record or create a new one for each purpose
    for purpose, allowed in consents.items():
        record = ConsentRecord.query.filter_by(
            user_id=user_id, purpose=purpose
        ).first()
        if record:
            record.allowed = bool(allowed)
            record.updated_at = datetime.utcnow()
            record.valid_until = valid_until
        else:
            record = ConsentRecord(
                user_id=user_id, purpose=purpose, allowed=bool(allowed),
                valid_until=valid_until,
            )
            db.session.add(record)
            # Flush so the new record gets an id before we create its category rows
            db.session.flush()

        # Replace all category entries for this record with the submitted list
        ConsentDataCategory.query.filter_by(consent_id=record.id).delete()
        for cat in data_categories:
            db.session.add(ConsentDataCategory(consent_id=record.id, category=cat))

    db.session.commit()
    return jsonify({"message": "Consent saved successfully"}), 200


@app.route("/consent/<int:user_id>", methods=["GET"])
def get_consent(user_id):
    """
    Return all consent records for a specific user.

    URL parameter:
        user_id — integer primary key of the user
    """
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    records = ConsentRecord.query.filter_by(user_id=user_id).all()
    return jsonify({
        "user": user.to_dict(),
        "consents": [r.to_dict() for r in records],
    }), 200


@app.route("/request", methods=["POST"])
def data_request():
    """
    Check whether a data-access request is permitted under the user's consent.

    Expected JSON body:
        {
            "user_id": 1,
            "purpose": "analytics",
            "requested_fields": ["email", "age_group"]   (optional)
        }

    Returns:
        {
            "decision":        "allowed" | "partially_allowed" | "denied",
            "allowed":         true | false,
            "allowed_fields":  [...],
            "redacted_fields": [...],
            "reason":          "..."
        }

    The policy engine evaluates the request and the decision is logged to the
    audit trail regardless of outcome.
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    purpose = data.get("purpose")
    requested_fields = data.get("requested_fields", [])

    if not user_id or not purpose:
        return jsonify({"error": "user_id and purpose are required"}), 400

    # Delegate the consent and field-level minimisation check to the policy engine
    result = policy.evaluate(user_id, purpose, requested_fields)

    # Fetch the most recent entry's hash to use as previous_hash for the new entry
    last_entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = (
        last_entry.entry_hash
        if (last_entry and last_entry.entry_hash)
        else GENESIS_HASH
    )

    # Persist the decision in the audit log (decision may be partially_allowed)
    log_entry = AuditLog(
        user_id=user_id,
        purpose=purpose,
        decision=result["decision"],
        reason=result["reason"],
        timestamp=datetime.utcnow(),
        previous_hash=previous_hash,
    )
    db.session.add(log_entry)
    # Flush to obtain the auto-assigned id before hashing — id is part of the content
    db.session.flush()

    entry_data = {
        "id": log_entry.id,
        "user_id": log_entry.user_id,
        "purpose": log_entry.purpose,
        "decision": log_entry.decision,
        "reason": log_entry.reason,
        "timestamp": log_entry.timestamp.isoformat() if log_entry.timestamp else None,
    }
    log_entry.entry_hash = compute_hash(entry_data, previous_hash)

    db.session.commit()

    return jsonify(result), 200


@app.route("/audit/verify", methods=["GET"])
def audit_verify():
    """
    Verify the integrity of the hash chain across all AuditLog entries.

    Returns {"valid": true/false, "message": "..."}.
    A false result means at least one entry was altered or the chain was broken.
    """
    result = verify_chain()
    return jsonify(result), 200


@app.route("/audit", methods=["GET"])
def audit_log():
    """
    Return the full audit log as a JSON array, ordered newest-first.

    Optional query parameter:
        user_id — filter entries to a single user
    """
    user_id = request.args.get("user_id", type=int)

    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    if user_id:
        query = query.filter_by(user_id=user_id)

    entries = query.all()
    return jsonify([e.to_dict() for e in entries]), 200


if __name__ == "__main__":
    app.run(debug=True)
