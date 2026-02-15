# 19 — Data Retention Matrix (v0)

Stand: 2026-02-11  
Principle: retain minimum data for minimum time; default deny/storage-avoidance.

---

## 1) Field-Level Matrix

| Data Class | Example Field | Location | Allowed? | TTL | Notes |
|---|---|---|---|---|---|
| Raw PII | full name, DOB, passport no. | Verifier logs | No | 0 | Must never be written |
| Raw PII | full name, DOB, passport no. | Wallet local store | Yes (user-controlled) | User-defined / policy | Encrypted at rest |
| Derived Claim | `age_gte=18` | Verifier decision context | Yes | Request lifetime + short audit need | No underlying attribute |
| Binding Data | nonce, requestHash, audience | Nonce store | Yes | Short TTL (e.g. 5-15 min) | Needed for anti-replay |
| Decision Metadata | decision, decisionCode, timestamp | WORM receipt | Yes | Audit retention policy | No stable cross-RP user ID |
| RP Identity | rp.id | Verifier ops logs | Yes | Operational TTL | Service-level, not user-level profiling |
| Device/session ephemeral IDs | request/session id | Runtime memory / temp store | Yes | Very short TTL | Rotate frequently |
| Cryptographic keys (private) | wallet signing key | Wallet secure storage | Yes | Until rotate/destroy | User root of trust |
| Cryptographic keys (public) | verifier public key refs | Config store | Yes | Until rotated | Versioned key metadata only |

---

## 2) Normative Rules
- Raw PII is forbidden in verifier/server logs.
- Any unknown field with potential PII must be dropped or denied by policy.
- Retention applies per field class, not per payload blob.
- No stable cross-RP user identifier may be persisted.
- If classification is uncertain, treat as sensitive and deny/purge.

---

## 3) Deletion & Purge Behavior
- Nonce store: auto-expire by TTL + periodic sweeper.
- Temporary verification artifacts: purge immediately after decision/receipt.
- WORM receipts: retained by explicit audit policy; must remain PII-minimal.
- Key destruction events must be auditable (without revealing key material).

---

## 4) Controls & Verification
- Log sink redaction filters tested in CI.
- PII canary strings in test payloads to verify non-persistence.
- Periodic retention compliance job validates TTL behavior.
- Privacy review sign-off required before pilot.

---

## 5) Open Parameters (set via ADR)
- Exact nonce TTL window
- WORM receipt retention duration per jurisdiction
- Timestamp precision policy (to reduce linkability)
- Degraded-mode data handling during outages
