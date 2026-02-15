# 20 — Canonicalization & Binding Spec v0

Stand: 2026-02-11  
Status: Draft (make normative after ADR-004 acceptance)

---

## 1) Purpose
Define deterministic request canonicalization and binding validation to prevent replay, forwarding, and context-swap attacks.

---

## 2) Canonicalization Rules (Request Hash Input)

## 2.1 Included fields (exact)
- `version`
- `requestId`
- `rp.id`
- `rp.audience`
- `purpose`
- `claims` (ordered list)
- `policyRef`
- `binding.nonce`
- `binding.expiresAt`

`binding.requestHash` is excluded from the hash input by definition.

## 2.2 Serialization
- UTF-8 encoding.
- Canonical JSON object key ordering: lexicographic ascending.
- No insignificant whitespace.
- Numbers in normalized JSON representation.
- Strings normalized to NFC.
- Arrays are order-sensitive and must preserve sender order.

## 2.3 Hash
- Algorithm: SHA-256 (v0 baseline).
- Output encoding: base64url (no padding).
- Field name in payload: `binding.requestHash`.

---

## 3) Binding Validation Rules

Verifier must validate in this order:
1. `binding.nonce` present and unconsumed.
2. `binding.expiresAt` not expired (after skew handling).
3. `rp.audience` equals target audience.
4. recomputed request hash equals `binding.requestHash`.
5. nonce marked consumed atomically.

Any failure => deny with deterministic code.

---

## 4) Clock Skew Policy
- Allowed clock skew window: ±90 seconds (initial default).
- If outside skew window: `DENY_BINDING_EXPIRED`.
- Skew window configurable per deployment; must be logged in config metadata.

---

## 5) Nonce Store Semantics
- Nonce uniqueness scope: `(audience, nonce)`.
- Nonce TTL: 10 minutes default.
- Nonce consumption must be atomic.
- Reuse (within TTL or after consume) => `DENY_BINDING_NONCE_REPLAY`.

---

## 6) Error Mapping
- Missing nonce/hash/expiry => `DENY_SCHEMA_MISSING_FIELD`
- Hash mismatch => `DENY_BINDING_HASH_MISMATCH`
- Audience mismatch => `DENY_BINDING_AUDIENCE_MISMATCH`
- Expired/outside skew => `DENY_BINDING_EXPIRED`
- Nonce replay => `DENY_BINDING_NONCE_REPLAY`

---

## 7) Test Vectors (to add)
Add at least 10 normative vectors:
- valid baseline
- modified field causes hash mismatch
- reordered object keys produce same hash
- changed array order produces different hash
- NFC normalization edge case
- replay same nonce same audience
- replay same nonce different audience
- expiry boundary inside/outside skew

---

## 8) Security Notes
- No global correlation IDs in canonicalized fields.
- Avoid embedding user-unique stable values.
- Hash algorithm agility required in future versions.
