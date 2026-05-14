# Consent-Based Data Access Control Prototype

## 1. Project Overview

This prototype demonstrates a consent-based data access control system built on GDPR
principles. It allows users to register fine-grained consent preferences across multiple
processing purposes (research, analytics, advertising) and individual data categories
(email, age group, purchase history, location). A policy engine enforces purpose
limitation and data minimisation at request time — access to a user's data is granted,
partially granted, or denied based solely on what the user has explicitly consented to.
Every decision is recorded in a hash-chained audit log that detects tampering, providing
a tamper-evident trail suitable for accountability and compliance review.

**Team:** Team 18 — Boyao Pang, Ke Ning, Xinrui Dong, Hanbing Cheng  
**Module:** COMP6265 Data Economy

---

## 2. System Architecture

| Component | Description |
|---|---|
| **Flask API** (`app.py`) | REST endpoints for consent registration, access requests, audit retrieval, and chain verification. Includes automatic schema migration at startup. |
| **Policy Engine** (`policy_engine.py`) | Evaluates each access request against stored consent records. Enforces purpose limitation (coarse) and data minimisation (field-level), returning `allowed`, `partially_allowed`, or `denied`. |
| **SQLite Database** (`instance/consent.db`) | Stores users, per-purpose consent records, per-field data categories, and the audit log. Managed via SQLAlchemy. This file is created automatically at first run. |
| **Audit Chain** (`audit_chain.py`) | Computes SHA-256 hashes over each audit log entry, chaining them so any after-the-fact modification to a row breaks all subsequent hashes. |
| **Frontend Dashboard** (`templates/index.html`) | Single-page UI for registering consent, submitting access requests, viewing the audit table, and verifying chain integrity. |

---

## 3. Prerequisites

- Python 3.8 or higher
- pip

---

## 4. Installation

```bash
git clone <repository-url>
cd comp6265-team18
pip install -r requirements.txt
```

---

## 5. Running the Application

**Step 1 — seed the database with sample users and consent records:**

```bash
python sample_data.py
```

Expected output:

```
Sample data inserted successfully.

  [1] Alice Mercer <alice@example.com> — research=yes, analytics=yes, advertising=no
  [2] Bob Tanaka <bob@example.com>     — research=yes, analytics=yes, advertising=yes
  [3] Carol Osei <carol@example.com>   — research=no,  analytics=no,  advertising=no
```

**Step 2 — start the Flask development server:**

```bash
python app.py
```

The application will be available at **http://127.0.0.1:5000**

---

## 6. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the frontend dashboard (`index.html`). |
| `POST` | `/consent` | Register or update a user's consent preferences. Accepts `user_id`, `consents` (purpose → bool map), `data_categories` (list of permitted field names, applied uniformly to all purposes in this request), and optional `valid_until` (ISO 8601). |
| `GET` | `/consent/<user_id>` | Retrieve all consent records for a given user. |
| `POST` | `/request` | Submit a data access request. Accepts `user_id`, `purpose`, and optional `requested_fields`. Returns `decision`, `allowed_fields`, `redacted_fields`, and `reason`. |
| `GET` | `/audit` | Return the full audit log as JSON, newest-first. Accepts optional `?user_id=` filter. |
| `GET` | `/audit/verify` | Verify the integrity of the hash chain. Returns `{"valid": true/false, "message": "..."}`. |

### Request / response examples

**POST /consent**

> The `data_categories` list is applied uniformly to all purposes submitted in the same request. If different purposes require different permitted fields, submit them in separate requests.

```json
{
  "user_id": 1,
  "consents": { "analytics": true, "advertising": false },
  "data_categories": ["email", "age_group"],
  "valid_until": "2027-12-31T23:59:59"
}
```

**POST /request**
```json
{
  "user_id": 1,
  "purpose": "analytics",
  "requested_fields": ["email", "age_group", "location"]
}
```
```json
{
  "decision": "partially_allowed",
  "allowed": true,
  "allowed_fields": ["email", "age_group"],
  "redacted_fields": ["location"],
  "reason": "User 1 has partial field-level consent for 'analytics': 1 field(s) redacted."
}
```

---

## 7. Test Scenarios

### Scenario 1 — Normal allow
Alice (user 1) has consented to `analytics` with categories `email` and `age_group`.

```json
POST /request  →  { "user_id": 1, "purpose": "analytics", "requested_fields": ["email", "age_group"] }
```
**Expected:** `decision: "allowed"` — all requested fields are covered by consent.

---

### Scenario 2 — No consent (deny)
Carol (user 3) has withheld consent for all purposes.

```json
POST /request  →  { "user_id": 3, "purpose": "research", "requested_fields": ["email"] }
```
**Expected:** `decision: "denied"` — user has explicitly withheld consent for `research`.

---

### Scenario 3 — Field over-request (partial deny / data minimisation)
Alice has consented to `analytics` for `email` and `age_group` only.

```json
POST /request  →  { "user_id": 1, "purpose": "analytics", "requested_fields": ["email", "purchase_history", "location"] }
```
**Expected:** `decision: "partially_allowed"` — `email` is returned; `purchase_history` and `location` are redacted.

---

### Scenario 4 — Expired consent (deny)
Any user whose consent record has a `valid_until` date in the past.

```json
POST /consent  →  { "user_id": 2, "consents": { "advertising": true }, "valid_until": "2020-01-01T00:00:00" }
POST /request  →  { "user_id": 2, "purpose": "advertising" }
```
**Expected:** `decision: "denied"` — consent window has passed.

---

## 8. File Structure

```
comp6265-team18/
├── app.py               # Flask application — routes, startup migration, error handling
├── models.py            # SQLAlchemy models: User, ConsentRecord, ConsentDataCategory, AuditLog
├── policy_engine.py     # PolicyEngine.evaluate() — purpose and field-level consent checks
├── audit_chain.py       # compute_hash() and verify_chain() — tamper-evident audit trail
├── sample_data.py       # Seeds the database with 3 test users and sample consent records
├── requirements.txt     # Python dependencies (Flask, Flask-SQLAlchemy)
├── templates/
│   └── index.html       # Single-page frontend dashboard
└── instance/
    └── consent.db       # SQLite database (auto-created at first run, not committed to git)
```
