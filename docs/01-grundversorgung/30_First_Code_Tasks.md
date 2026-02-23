# 30 — First Code Tasks (Top 10)

Stand: 2026-02-11

## T1 — Request schema v0 (JSON Schema)
- Build `request.v0.schema.json`
- Cover all required fields from `17_API_Contract_v0.md`
- Add negative fixtures

## T2 — Response schema v0
- Build allow/deny response schemas
- Enforce decisionCode presence on DENY

## T3 — Canonicalizer implementation
- Implement deterministic canonical JSON (sorted keys, NFC, UTF-8)
- Add vector tests from `28_Test_Vector_Pack_v0.md`

## T4 — Request hash function
- SHA-256 + base64url
- Hash excludes `binding.requestHash` itself

## T5 — Binding validator
- Nonce present/unconsumed
- Audience match
- Expiry + skew handling
- Request hash match

## T6 — Nonce store adapter
- In-memory v0 + interface for persistent backend later
- Atomic consume API
- TTL sweeper

## T7 — Deny code mapper
- Map all known error paths to `21_Deny_Reason_Code_Catalog.md`
- Unknown exceptions -> `DENY_INTERNAL_SAFE_FAILURE`

## T8 — Policy evaluator skeleton
- Predicate recognition + fail-closed behavior
- Minimization checks

## T9 — Verifier route orchestration
- Gate order: rate-limit -> schema -> binding -> policy -> crypto -> receipt
- Produce decision response object

## T10 — WORM receipt writer
- Append-only write path
- PII redaction checks on receipt payload

---

## Done definition for this batch
- 20+ automated tests green
- 1 happy-path allow test (mock proof)
- 1 replay deny test
- 1 hash mismatch deny test
- 1 minimization violation deny test
