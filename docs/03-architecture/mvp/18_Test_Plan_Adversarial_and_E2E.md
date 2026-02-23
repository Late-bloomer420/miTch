# 18 — Test Plan (Adversarial + E2E)

Stand: 2026-02-11  
Scope: MVP verification path (RP request -> wallet proof -> verifier decision -> receipt).

---

## 1) Test Objectives
- Prove fail-closed behavior on malformed/ambiguous inputs.
- Prove replay/context-swap resistance.
- Prove deterministic deny reason mapping.
- Prove no raw PII leakage in logs/receipts.
- Establish baseline performance (p50/p95).

---

## 2) Test Categories

## A. Schema Validation Tests
1. Missing required field (`binding.nonce`) -> `DENY_SCHEMA_MISSING_FIELD`
2. Unknown top-level field -> `DENY_SCHEMA_UNKNOWN_FIELD`
3. Unsupported `version` -> `DENY_POLICY_UNSUPPORTED_VERSION`
4. Wrong data type (e.g., `claims` not array) -> `DENY_SCHEMA_MISSING_FIELD` or strict type deny

## B. Policy Evaluation Tests
1. Unknown predicate name -> `DENY_POLICY_UNKNOWN_PREDICATE`
2. Request asks for unnecessary attribute -> `DENY_POLICY_MINIMIZATION_VIOLATION`
3. Purpose mismatch against policy -> deny
4. Ambiguous policy path -> explicit deny (`DENY_INTERNAL_SAFE_FAILURE` allowed if unmapped)

## C. Binding / Replay Tests
1. Nonce replay same audience -> `DENY_BINDING_NONCE_REPLAY`
2. Nonce replay different audience -> `DENY_BINDING_NONCE_REPLAY`
3. Request hash mismatch -> `DENY_BINDING_HASH_MISMATCH`
4. Audience mismatch -> `DENY_BINDING_AUDIENCE_MISMATCH`
5. Expired request -> `DENY_BINDING_EXPIRED`
6. Clock-skew boundary tests (inside/outside tolerance)

## D. Crypto Verification Tests
1. Invalid signature/proof bytes -> `DENY_CRYPTO_VERIFY_FAILED`
2. Wrong key id or algorithm mismatch -> `DENY_CRYPTO_VERIFY_FAILED`
3. Corrupted disclosure bundle -> `DENY_CRYPTO_VERIFY_FAILED`

## E. Rate Limiting / Abuse
1. Exceed request budget in window -> `DENY_RATE_LIMIT_EXCEEDED`
2. Burst traffic with valid payloads still blocked as configured
3. Verify no fail-open path under load

## F. Privacy / Logging Tests
1. Raw PII fuzz payload must never appear in logs
2. Stable cross-RP identifier should be absent from logs/receipts
3. Receipt content includes decision evidence only, no identity payload

## G. E2E Happy Path
1. Age predicate success -> `ALLOW_MINIMAL_PROOF_VALID`
2. Age + residency success -> `ALLOW_MINIMAL_PROOF_VALID`
3. Receipt produced and retrievable via `receiptRef`

---

## 3) Adversarial Scenario Pack
- Token forwarding attack (proof generated for RP-A reused at RP-B)
- Delayed replay after partial expiry
- Request canonicalization mismatch across clients
- Mixed-case/Unicode key confusion in JSON keys
- Oversized payload DoS attempt
- Concurrent replay race conditions (same nonce multi-submit)

Expected outcome: all scenarios deny safely, reason codes deterministic.

---

## 4) Performance Baselines (Pilot Targets)
- Verification p50 <= 500ms
- Verification p95 <= 1500ms
- Deny-path processing <= allow-path p95 for malformed requests
- Receipt logging overhead bounded and measured

---

## 5) Evidence Artifacts to Produce
- Test run report (pass/fail per case)
- Decision code distribution snapshot
- Replay attack report
- Privacy leakage scan report
- Latency histogram and percentile summary

---

## 6) Exit Criteria
- 100% pass for critical deny-path tests
- Replay success rate = 0 in defined suite
- No raw PII findings in logs/receipts
- E2E flows stable for 2 predicates and 2 RPs
