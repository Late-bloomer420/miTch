# Dry-Run #01 Findings

**Date:** 2026-03-04  
**Source:** `docs/pilot/PILOT_DRY_RUN_01.md`

---

## Critical Findings (Must Fix Before Pilot)

### F-01: Legacy `resolveDID()` exposes mock fallback in production
**Severity:** 🔴 HIGH  
**Location:** `shared-crypto/src/did.ts` — `getDefaultResolver()` uses `allowMockFallback: true`  
**Risk:** Any code using the deprecated `resolveDID()` function will generate mock DID documents for unknown DID methods instead of failing closed.  
**Fix:** Remove `allowMockFallback: true` from default resolver, or delete the legacy API entirely. All callers should use `new DIDResolver()` (defaults to `allowMockFallback: false`).

### F-02: `did:web:localhost` resolves over HTTP — no production guard
**Severity:** 🔴 HIGH  
**Location:** `shared-crypto/src/did.ts` — `didWebToUrl()` line: `host === 'localhost'` → `http://`  
**Risk:** A `did:web:localhost%3A3002` DID resolves over plain HTTP. In production, this could allow MITM if a verifier claims a localhost DID.  
**Fix:** Add environment guard: when `NODE_ENV=production` (or pilot mode), reject `did:web:localhost*` DIDs entirely.

### F-03: Low-risk grace period returns ALLOW on stale cache
**Severity:** 🟡 MEDIUM (pilot scoping question)  
**Location:** `revocation-statuslist/src/index.ts` — `handleFetchFailure()` with `riskTier='low'`  
**Risk:** If status list is unreachable but cached data exists within 1h grace, the system returns ALLOW based on stale data. A revocation during the grace window would be missed.  
**Decision needed:** For pilot, should ALL tiers be high-risk (no grace)? Or is 1h acceptable?

---

## Medium Findings

### F-04: WebAuthn timeout deny code ambiguity
**Severity:** 🟡 MEDIUM  
**Issue:** When WebAuthn times out, it's unclear whether the system emits `DENY_PRESENCE_REQUIRED` or `DENY_REAUTH_REQUIRED`. These have different user messages.  
**Fix:** Document and test the mapping explicitly in the step-up module.

### F-05: Audit export schema undefined
**Severity:** 🟡 MEDIUM  
**Issue:** Step 9 (export audit evidence) has no defined output schema. The dry-run assumes certain fields exist (requestHash, policyVersion, matchedRule, etc.) but there's no type definition.  
**Fix:** Create `AuditRecord` type in `@mitch/shared-types` with all required fields.

### F-06: `DENY_POLICY_MISMATCH` vs `DENY_NO_MATCHING_RULE` overlap
**Severity:** 🟢 LOW  
**Issue:** Both codes seem to cover "verifier doesn't match policy." `NO_MATCHING_RULE` is for pattern mismatch; `POLICY_MISMATCH` is for constraint violation after match. The distinction is clear in audit messages but should be tested.  
**Fix:** Add a unit test that triggers each independently.

---

## Observations (No Action Required)

- **Anti-oracle design is solid.** 26 of 31 deny codes map to the same verifier message (`BUCKET_GENERIC`). Only rate-limit, user-action, and infra have distinct buckets. An attacker probing the verifier API gets zero signal about why a request failed.
- **Nonce consume is atomic.** `validateBinding()` checks expiry and audience BEFORE consuming the nonce, avoiding wasted nonces on bad requests.
- **SD-JWT VC issuance includes `age_over_18` as non-disclosable.** This is correct for pilot — age predicate doesn't need selective disclosure.
- **Revocation checker deduplicates batch fetches.** Privacy-preserving: one fetch per unique status list URL regardless of how many credentials reference it.

---

## Action Item Tracker

| ID | Finding | Owner | Status |
|---|---|---|---|
| AI-01 | Block `did:web:localhost` in production (F-02) | — | ⬜ TODO |
| AI-02 | Remove legacy `resolveDID()` mock fallback (F-01) | — | ⬜ TODO |
| AI-03 | Decide pilot risk tier for grace period (F-03) | — | ⬜ DECIDE |
| AI-04 | Define WebAuthn timeout → deny code mapping (F-04) | — | ⬜ TODO |
| AI-05 | Create `AuditRecord` type (F-05) | — | ⬜ TODO |
| AI-06 | Test `POLICY_MISMATCH` vs `NO_MATCHING_RULE` independently (F-06) | — | ⬜ TODO |
