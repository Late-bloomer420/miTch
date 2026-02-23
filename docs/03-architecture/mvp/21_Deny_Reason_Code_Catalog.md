# 21 - Deny Reason Code Catalog (Normative v0)

Stand: 2026-02-11
Purpose: single source of truth for all deny outcomes across API, engine, tests, and logs.

---

## 1) Structure
Each deny result must provide:
- `decision = DENY`
- `decisionCode` (from this catalog)
- optional `detailCode` (implementation-specific, non-PII)

---

## 2) Catalog

## Schema
- `DENY_SCHEMA_MISSING_FIELD` - required field absent
- `DENY_SCHEMA_UNKNOWN_FIELD` - field not recognized by schema policy
- `DENY_SCHEMA_TYPE_MISMATCH` - field type invalid

## Policy
- `DENY_POLICY_UNSUPPORTED_VERSION` - policy version unknown/unsupported
- `DENY_POLICY_UNKNOWN_PREDICATE` - predicate not recognized
- `DENY_POLICY_MINIMIZATION_VIOLATION` - request exceeds least-disclosure rule
- `DENY_POLICY_PURPOSE_MISMATCH` - purpose not allowed by policy

## Binding
- `DENY_BINDING_NONCE_REPLAY` - nonce reused or already consumed
- `DENY_BINDING_HASH_MISMATCH` - canonical request hash mismatch
- `DENY_BINDING_AUDIENCE_MISMATCH` - audience mismatch
- `DENY_BINDING_EXPIRED` - expired request or outside skew window

## Crypto
- `DENY_CRYPTO_VERIFY_FAILED` - proof/signature verification failed
- `DENY_CRYPTO_UNSUPPORTED_ALG` - algorithm not allowed
- `DENY_CRYPTO_KEY_STATUS_INVALID` - key revoked/invalid status

## Abuse / Platform
- `DENY_RATE_LIMIT_EXCEEDED` - requester over quota
- `DENY_REAUTH_REQUIRED` - high-risk prompt frequency threshold reached; recent re-auth required
- `DENY_REAUTH_PROOF_INVALID` - re-auth evidence provided but invalid under configured strong re-auth mode
- `DENY_JURISDICTION_INCOMPATIBLE` - requester/runtime jurisdiction mismatch or missing jurisdiction when strict matching is enabled
- `DENY_CREDENTIAL_REVOKED` - credential identifier or status-list index is listed as revoked by configured status source
- `DENY_CREDENTIAL_STATUS_INVALID` - malformed or unsafe credential status reference (e.g., invalid URL/index)
- `DENY_RESOLVER_QUORUM_FAILED` - multi-resolver key lookup returned inconsistent/no-quorum result
- `DENY_STATUS_SOURCE_UNAVAILABLE` - key/credential status source unavailable or timed out
- `DENY_INTERNAL_SAFE_FAILURE` - internal error handled fail-closed

---

## 3) Mapping Requirements
- Each reject path in code must map to exactly one catalog code.
- Tests must assert code stability for each scenario.
- Unknown internal exceptions must map to `DENY_INTERNAL_SAFE_FAILURE`.

---

## 4) Logging Constraints
- Do not include raw payload fragments containing potential PII in deny details.
- `detailCode` must be bounded and non-identifying.

---

## 5) Change Control
- New codes require ADR reference and version update.
- Removing/renaming codes is backward-incompatible.
