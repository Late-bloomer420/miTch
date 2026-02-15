# 28 — Test Vector Pack v0 (Canonicalization + Binding)

Stand: 2026-02-11  
Purpose: normative vectors for deterministic requestHash and binding validation behavior.

---

## Conventions
- Hash algorithm: SHA-256
- Encoding: base64url (no padding)
- Canonical JSON: sorted keys, UTF-8, NFC, no insignificant whitespace

---

## TV-01 Baseline Valid Request
- Input profile: valid fields, valid nonce/audience/expiry
- Expected: hash matches, decision path continues

## TV-02 Key Reordering Invariance
- Mutation: reorder object keys only
- Expected: same canonical form and same hash as TV-01

## TV-03 Array Order Sensitivity
- Mutation: reorder `claims[]`
- Expected: different hash, binding hash mismatch if old hash used
- Decision: `DENY_BINDING_HASH_MISMATCH`

## TV-04 Unicode Normalization
- Mutation: equivalent Unicode string forms (NFD vs NFC)
- Expected: same canonicalized string and same hash

## TV-05 Request Field Tamper
- Mutation: change `purpose`
- Expected: hash mismatch
- Decision: `DENY_BINDING_HASH_MISMATCH`

## TV-06 Audience Mismatch
- Mutation: proof submitted to different audience than request
- Expected: audience check fails
- Decision: `DENY_BINDING_AUDIENCE_MISMATCH`

## TV-07 Expiry Boundary (Inside Skew)
- Mutation: request near expiry but within ±90s skew
- Expected: accepted for binding step

## TV-08 Expiry Boundary (Outside Skew)
- Mutation: request outside skew window
- Decision: `DENY_BINDING_EXPIRED`

## TV-09 Nonce Replay Same Audience
- Mutation: reuse consumed nonce
- Decision: `DENY_BINDING_NONCE_REPLAY`

## TV-10 Nonce Replay Different Audience
- Mutation: reuse nonce on another audience where scope is `(audience, nonce)`; if nonce policy forbids global reuse, deny accordingly
- Expected (v0): deny replay according to store policy

---

## Implementation Note
Store concrete JSON examples and expected hash outputs in machine-readable fixtures (e.g., `tests/vectors/*.json`) once code scaffolding exists.
