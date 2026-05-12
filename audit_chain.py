import hashlib
import json

from models import AuditLog

# Sentinel used as the previous_hash for the very first entry in the chain.
# Using 64 zeros mirrors the "genesis block" convention and is unambiguous.
GENESIS_HASH = "0" * 64


def compute_hash(entry_data: dict, previous_hash: str) -> str:
    """
    Return the SHA-256 hex digest that identifies one audit log entry.

    The input is the deterministic JSON serialisation of the entry's
    substantive fields (id, user_id, purpose, decision, reason, timestamp)
    concatenated with the previous entry's hash.  Sorting the JSON keys
    ensures the digest is stable regardless of dict insertion order.

    Args:
        entry_data:     Dict of the entry's fields (must NOT include the hash
                        columns themselves, so the calculation is reproducible).
        previous_hash:  The entry_hash of the immediately preceding log entry,
                        or GENESIS_HASH for the first entry.

    Returns:
        64-character lowercase hex digest string.
    """
    content = json.dumps(entry_data, sort_keys=True) + previous_hash
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def verify_chain() -> dict:
    """
    Verify the integrity of all AuditLog entries that carry a stored hash.

    Entries whose entry_hash is NULL or empty are silently skipped — they
    pre-date hash-chaining and cannot be verified.  The first entry that
    *does* have a hash is treated as the head of the verifiable chain; its
    previous_hash is accepted as given (it may point to GENESIS_HASH or to
    a legacy entry we skipped).

    For every hashed entry two checks are performed in insertion order:
        1. previous_hash equals the entry_hash of the immediately preceding
           hashed entry (chain linkage).
        2. Recomputing compute_hash(entry_data, previous_hash) matches the
           stored entry_hash (content integrity).

    Returns:
        {"valid": True,  "message": "..."} when all hashed entries are consistent.
        {"valid": False, "message": "..."} at the first broken link.
    """
    all_entries = AuditLog.query.order_by(AuditLog.id.asc()).all()

    if not all_entries:
        return {"valid": True, "message": "Audit log is empty — nothing to verify."}

    # Keep only entries that have a stored hash; skip legacy rows silently
    hashed_entries = [e for e in all_entries if e.entry_hash]
    skipped = len(all_entries) - len(hashed_entries)

    if not hashed_entries:
        return {
            "valid": True,
            "message": (
                f"No hashed entries found ({skipped} legacy entr"
                f"{'y' if skipped == 1 else 'ies'} skipped). "
                "Nothing to verify."
            ),
        }

    # The first hashed entry's previous_hash is accepted as the chain anchor
    expected_previous = hashed_entries[0].previous_hash

    for entry in hashed_entries:
        entry_data = {
            "id": entry.id,
            "user_id": entry.user_id,
            "purpose": entry.purpose,
            "decision": entry.decision,
            "reason": entry.reason,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        }

        # Check 1 — chain linkage
        if entry.previous_hash != expected_previous:
            return {
                "valid": False,
                "message": (
                    f"Chain broken at entry #{entry.id}: "
                    f"previous_hash does not match the preceding hashed entry."
                ),
            }

        # Check 2 — content integrity
        recomputed = compute_hash(entry_data, entry.previous_hash)
        if entry.entry_hash != recomputed:
            return {
                "valid": False,
                "message": (
                    f"Chain broken at entry #{entry.id}: "
                    f"entry_hash mismatch — this entry may have been tampered with."
                ),
            }

        expected_previous = entry.entry_hash

    skip_note = f" ({skipped} unhashed legacy entr{'y' if skipped == 1 else 'ies'} skipped)" if skipped else ""
    return {
        "valid": True,
        "message": f"Audit chain valid. {len(hashed_entries)} entr{'y' if len(hashed_entries) == 1 else 'ies'} verified{skip_note}.",
    }
