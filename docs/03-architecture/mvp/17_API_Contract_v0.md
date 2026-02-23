# 17 — API Contract v0 (Requester ↔ Verifier ↔ Wallet Boundary)

Stand: 2026-02-11  
Status: Draft v0 (normative for MVP once ADR-008 is Accepted)

---

## 1) Design Rules
- Fail closed on any schema mismatch or missing required field.
- Requests must be purpose-bound and audience-bound.
- Proofs must be nonce-bound and expiry-bound.
- No raw PII in verifier logs or receipts.

---

## 2) Verification Request (RP -> Verifier)

```json
{
  "version": "v0",
  "requestId": "uuid",
  "rp": {
    "id": "rp.example",
    "audience": "rp.example"
  },
  "purpose": "age_gate_checkout",
  "claims": [
    { "type": "predicate", "name": "age_gte", "value": 18 },
    { "type": "predicate", "name": "residency_eq", "value": "AT" }
  ],
  "binding": {
    "nonce": "base64url",
    "requestHash": "hex-or-base64url",
    "expiresAt": "2026-02-11T10:00:00Z"
  },
  "policyRef": "policy-v0-age-residency",
  "meta": {
    "channel": "web",
    "traceLevel": "minimal"
  }
}
```

### Required Fields
- `version`, `requestId`, `rp.id`, `rp.audience`, `purpose`, `claims[]`, `binding.nonce`, `binding.requestHash`, `binding.expiresAt`, `policyRef`

### Deny Conditions (non-exhaustive)
- Missing or unknown required fields
- Unknown claim type/name
- Expired request
- Audience mismatch
- Binding mismatch
- Unsupported policy version

---

## 3) Wallet Proof Submission (Wallet -> Verifier)

```json
{
  "version": "v0",
  "requestId": "uuid",
  "audience": "rp.example",
  "proofBundle": {
    "format": "sd-jwt-vc",
    "proof": "opaque-proof-material",
    "disclosures": ["minimal-disclosure-only"],
    "keyId": "kid-ephemeral",
    "alg": "EdDSA"
  },
  "binding": {
    "nonce": "base64url",
    "requestHash": "hex-or-base64url",
    "expiresAt": "2026-02-11T10:00:00Z"
  }
}
```

### Required Validation
1. Schema validate
2. Binding validate (nonce/hash/audience/expiry)
3. Policy evaluate (least disclosure + purpose)
4. Crypto verify
5. Write WORM decision receipt

---

## 4) Verification Response (Verifier -> RP)

```json
{
  "version": "v0",
  "requestId": "uuid",
  "decision": "ALLOW",
  "decisionCode": "ALLOW_MINIMAL_PROOF_VALID",
  "claimsSatisfied": [
    { "name": "age_gte", "value": 18 },
    { "name": "residency_eq", "value": "AT" }
  ],
  "receiptRef": "aqdr:2026-02-11:abc123",
  "verifiedAt": "2026-02-11T09:00:01Z"
}
```

### DENY Example

```json
{
  "version": "v0",
  "requestId": "uuid",
  "decision": "DENY",
  "decisionCode": "DENY_BINDING_AUDIENCE_MISMATCH",
  "claimsSatisfied": [],
  "receiptRef": "aqdr:2026-02-11:def456",
  "verifiedAt": "2026-02-11T09:00:01Z"
}
```

---

## 5) Decision Code Taxonomy (v0 baseline)

### Allow
- `ALLOW_MINIMAL_PROOF_VALID`

### Deny (schema/policy/binding/security)
- `DENY_SCHEMA_MISSING_FIELD`
- `DENY_SCHEMA_UNKNOWN_FIELD`
- `DENY_POLICY_UNSUPPORTED_VERSION`
- `DENY_POLICY_UNKNOWN_PREDICATE`
- `DENY_POLICY_MINIMIZATION_VIOLATION`
- `DENY_BINDING_NONCE_REPLAY`
- `DENY_BINDING_HASH_MISMATCH`
- `DENY_BINDING_AUDIENCE_MISMATCH`
- `DENY_BINDING_EXPIRED`
- `DENY_CRYPTO_VERIFY_FAILED`
- `DENY_RATE_LIMIT_EXCEEDED`
- `DENY_INTERNAL_SAFE_FAILURE`

---

## 6) Logging Constraints (Normative)
- Never log raw PII attributes.
- Never log stable cross-RP identifiers.
- Keep timestamps at minimum precision needed for operations.
- WORM receipts store decision evidence, not identity payload.

---

## 7) Versioning Rules
- `version` is mandatory in all request/response payloads.
- Backward-incompatible changes require new major contract version.
- Verifier must deny unknown major versions by default.

---

## 8) Open Implementation Choices (must be closed by ADR)
- Final proof `format` for MVP and fallback
- Canonicalization algorithm for `requestHash`
- Revocation/status protocol details
- Clock-skew tolerance window
