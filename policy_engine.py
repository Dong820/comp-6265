from datetime import datetime
from models import User, ConsentRecord, ConsentDataCategory

# Recognised purposes that the system understands
VALID_PURPOSES = {"research", "analytics", "advertising"}


class PolicyEngine:
    """
    Evaluates data-access requests against a user's stored consent preferences.

    All decisions are pure reads — writing to the audit log is the caller's
    responsibility (see app.py /request route).
    """

    def evaluate(self, user_id: int, purpose: str, requested_fields: list = None) -> dict:
        """
        Decide whether a data-access request should be allowed, and which
        specific data fields may be returned (data minimisation).

        Steps:
            1. Verify the user exists.
            2. Reject unknown purposes immediately.
            3. Look up the ConsentRecord for (user_id, purpose).
            4. Deny if no record exists (opt-in model — silence means no).
            5. Reject if the consent window has passed.
            6. Deny if the user explicitly withheld consent for this purpose.
            7. Apply field-level minimisation against ConsentDataCategory rows.

        Args:
            user_id:          Integer primary key of the requesting user.
            purpose:          Category of data use (e.g. "analytics").
            requested_fields: Optional list of specific data fields being requested
                              (e.g. ["email", "age_group"]). When omitted, only the
                              coarse purpose-level check is performed.

        Returns:
            A dict with keys:
                "decision"        (str)  — "allowed", "partially_allowed", or "denied".
                "allowed"         (bool) — True when decision is not "denied".
                "allowed_fields"  (list) — Fields the requester may access.
                "redacted_fields" (list) — Fields withheld due to missing consent.
                "reason"          (str)  — Human-readable explanation.
        """
        # Helper so every early-exit path returns the full response shape
        def deny(reason):
            return {
                "decision": "denied",
                "allowed": False,
                "allowed_fields": [],
                "redacted_fields": list(requested_fields) if requested_fields else [],
                "reason": reason,
            }

        # Step 1 — ensure the user exists in the database
        user = User.query.get(user_id)
        if not user:
            return deny(f"User {user_id} does not exist.")

        # Step 2 — reject purposes the system does not recognise
        if purpose not in VALID_PURPOSES:
            return deny(
                f"'{purpose}' is not a recognised purpose. "
                f"Valid purposes are: {', '.join(sorted(VALID_PURPOSES))}."
            )

        # Step 3 — fetch the specific consent record
        record = ConsentRecord.query.filter_by(user_id=user_id, purpose=purpose).first()

        # Step 4 — no record means the user never gave consent (opt-in default)
        if record is None:
            return deny(
                f"No consent record found for user {user_id} and "
                f"purpose '{purpose}'. Access denied by default."
            )

        # Step 5 — reject if the consent window has passed
        if record.valid_until and datetime.utcnow() > record.valid_until:
            return deny(
                f"Consent for '{purpose}' by user {user_id} expired on "
                f"{record.valid_until.strftime('%Y-%m-%d %H:%M:%S')} UTC."
            )

        # Step 6 — deny if the user explicitly withheld consent for this purpose
        if not record.allowed:
            return deny(f"User {user_id} has explicitly withheld consent for '{purpose}'.")

        # Step 7 — apply field-level data minimisation when specific fields were requested
        if requested_fields:
            consented = {c.category for c in record.data_categories}
            allowed_fields  = [f for f in requested_fields if f in consented]
            redacted_fields = [f for f in requested_fields if f not in consented]

            if not allowed_fields:
                return {
                    "decision": "denied",
                    "allowed": False,
                    "allowed_fields": [],
                    "redacted_fields": redacted_fields,
                    "reason": (
                        f"None of the requested fields are covered by user {user_id}'s "
                        f"consent for '{purpose}'."
                    ),
                }

            if redacted_fields:
                return {
                    "decision": "partially_allowed",
                    "allowed": True,
                    "allowed_fields": allowed_fields,
                    "redacted_fields": redacted_fields,
                    "reason": (
                        f"User {user_id} has partial field-level consent for '{purpose}': "
                        f"{len(redacted_fields)} field(s) redacted."
                    ),
                }

            return {
                "decision": "allowed",
                "allowed": True,
                "allowed_fields": allowed_fields,
                "redacted_fields": [],
                "reason": (
                    f"User {user_id} has consented to all requested fields for '{purpose}'."
                ),
            }

        # No field-level check requested — return the coarse purpose-level decision
        updated = record.updated_at.strftime("%Y-%m-%d %H:%M:%S") if record.updated_at else "unknown"
        return {
            "decision": "allowed",
            "allowed": True,
            "allowed_fields": [],
            "redacted_fields": [],
            "reason": (
                f"User {user_id} has consented to '{purpose}' (last updated {updated})."
            ),
        }
