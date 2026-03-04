# Pilot Dry-Run Tabletop #01

**Date:** 2026-03-04  
**Scope:** Single end-to-end pilot flow — Happy path + failure scenarios  
**Codebase state:** consolidation branch  
**Deny code source:** `@mitch/policy-engine/deny-reason-codes.ts` (31 codes, 4 verifier buckets)

---

## Verifier Bucket Legend

All verifier-facing messages are bucketed to prevent oracle attacks:

| Bucket ID | Verifier sees |
|---|---|
| `BUCKET_GENERIC` | "Verification could not be completed." |
| `BUCKET_RATE` | "Request rate exceeded." |
| `BUCKET_USER_ACTION` | "User action required." |
| `BUCKET_INFRA` | "Service temporarily unavailable." |

---

## Step 1 — Verifier Creates Request

Verifier constructs a `PresentationRequest` with nonce, expiry, audience, purpose, claims, and request hash.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 1.1 | Valid request, known verifier, reasonable claims | **PASS** (request created) | — | — | Request created; nonce issued, hash computed | Happy path |
| 1.2 | Missing required fields (no `purpose`, no `claims`) | **REJECT** at schema level | — | — | `DENY_SCHEMA_MISSING_FIELD` — missing required field | `validateBinding()` checks required fields before anything else |
| 1.3 | Verifier not in policy trust list | Request created but will fail at Step 4 | — | — | — | Request creation is verifier-side; trust check is wallet-side |
| 1.4 | Claims include fields wallet policy denies | Request created but will fail at Step 4 | — | — | — | Verifier doesn't know wallet policy at request time |

---

## Step 2 — Wallet Receives Request

Wallet parses the `PresentationRequest`, validates schema, checks `binding.expiresAt`.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 2.1 | Valid request, within expiry window | **CONTINUE** | — | — | Request accepted for processing | Happy path |
| 2.2 | Request expired (`binding.expiresAt` in the past) | **DENY** | "Die Anfrage ist abgelaufen. Bitte starte den Vorgang neu." | BUCKET_GENERIC | `DENY_BINDING_EXPIRED`: Request timestamp outside acceptable skew window. | Fail-fast before DID resolution |
| 2.3 | Malformed JSON / unparseable | **DENY** | "Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut." | BUCKET_GENERIC | `DENY_BINDING_FAILED`: Request binding verification failed — generic binding error. | |
| 2.4 | `expiresAt` is not a valid ISO 8601 date | **DENY** | "Die Anfrage ist abgelaufen. Bitte starte den Vorgang neu." | BUCKET_GENERIC | `DENY_BINDING_EXPIRED`: expiresAt parsed as NaN. | `validateBinding()` line: `isNaN(expiresAtMs)` → DENY |

---

## Step 3 — DID Resolution + Signature Verification

`DIDResolver.resolve()` fetches verifier's DID Document; `extractVerificationKey()` gets the public key; signature is verified.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 3.1 | `did:web` resolves, valid ES256 key, sig valid | **CONTINUE** | — | — | DID resolved from `did:web`, key extracted, sig verified | Happy path |
| 3.2 | Resolver network timeout (10s) | **DENY** | "Sicherheitsprüfung konnte nicht abgeschlossen werden." | BUCKET_INFRA | `DENY_RESOLVER_QUORUM_FAILED`: Multi-resolver quorum not reached — inconsistent key resolution. | `DIDResolutionError` thrown, caught → DENY |
| 3.3 | DID Document missing `verificationMethod` | **DENY** | "Sicherheitsprüfung fehlgeschlagen." | BUCKET_GENERIC | `DENY_CRYPTO_VERIFY_FAILED`: Cryptographic proof/signature verification failed. | `DIDKeyExtractionError`: No verificationMethod entries |
| 3.4 | DID Document has no `publicKeyJwk` | **DENY** | "Sicherheitsprüfung fehlgeschlagen." | BUCKET_GENERIC | `DENY_CRYPTO_VERIFY_FAILED`: verificationMethod has no publicKeyJwk | |
| 3.5 | Unsupported DID method (not `did:web` / `did:mitch`) + `allowMockFallback=false` | **DENY** | "Sicherheitsprüfung fehlgeschlagen." | BUCKET_GENERIC | `DENY_CRYPTO_VERIFY_FAILED`: Unsupported DID method | Production config: mock fallback disabled |
| 3.6 | Signature doesn't match extracted key | **DENY** | "Sicherheitsprüfung fehlgeschlagen." | BUCKET_GENERIC | `DENY_CRYPTO_VERIFY_FAILED`: Cryptographic proof/signature verification failed. | |
| 3.7 | Algorithm is not in allowed set (e.g., RS256 instead of ES256) | **DENY** | "Nicht unterstützter Sicherheitsstandard." | BUCKET_GENERIC | `DENY_CRYPTO_UNSUPPORTED_ALG`: Algorithm not in allowed algorithm set. | |
| 3.8 | DID resolves but HTTP 404 | **DENY** | "Sicherheitsprüfung konnte nicht abgeschlossen werden." | BUCKET_INFRA | `DENY_RESOLVER_QUORUM_FAILED` or `DENY_STATUS_SOURCE_UNAVAILABLE` | `DIDResolutionError`: HTTP 404 from URL |
| 3.9 | `did:web` → localhost in production context | **DENY** | "Sicherheitsprüfung fehlgeschlagen." | BUCKET_GENERIC | `DENY_CRYPTO_VERIFY_FAILED` | ⚠️ **ACTION ITEM:** No explicit localhost block in `did.ts` — `did:web:localhost` resolves over HTTP. See findings. |

---

## Step 4 — Policy Gate Decision

Policy engine evaluates: verifier trust, purpose match, claim allowlists, layer violations, minimization.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 4.1 | Known verifier, allowed purpose, claims within allowlist, correct layer | **ALLOW** (or **PROMPT** if `requiresUserConsent`) | — | — | Policy rule matched; all constraints satisfied | Happy path |
| 4.2 | Unknown verifier DID, `blockUnknownVerifiers=true` | **DENY** | "Dieser Service ist nicht bekannt. Fortfahren auf eigenes Risiko." | BUCKET_GENERIC | `DENY_UNKNOWN_VERIFIER`: Verifier DID not matched by any rule and blockUnknownVerifiers=true. | |
| 4.3 | Verifier known but requesting claims in `deniedClaims` | **DENY** | "Der Service fragt Daten ab, die deine Policy nicht erlaubt." | BUCKET_GENERIC | `DENY_CLAIM_NOT_ALLOWED`: Requested claims not in allowedClaims or explicitly in deniedClaims. | |
| 4.4 | Verifier asks for Layer 2 data but only has Layer 1 trust | **DENY** | "Dieser Service ist nicht für diese Datenkategorie autorisiert." | BUCKET_GENERIC | `DENY_LAYER_VIOLATION`: Verifier minimumLayer insufficient for requested data layer. | |
| 4.5 | No policy manifest loaded (null) | **DENY** | "Keine Sicherheitsrichtlinie geladen. Bitte starte die App neu." | BUCKET_GENERIC | `DENY_POLICY_MISSING`: PolicyManifest was null/undefined — fail-closed to DENY. | Critical fail-closed path |
| 4.6 | Policy version not recognized | **DENY** | "Deine App benötigt ein Update für diese Anfrage." | BUCKET_GENERIC | `DENY_POLICY_UNSUPPORTED_VERSION`: Policy version not in KNOWN_POLICY_VERSIONS set. | |
| 4.7 | No rule pattern matches verifier ID | **DENY** | "Für diesen Service gibt es keine passende Regel." | BUCKET_GENERIC | `DENY_NO_MATCHING_RULE`: No policy rule verifierPattern matched request.verifierId. | |
| 4.8 | Multiple rules match, one says DENY | **DENY** | "Eine Sicherheitsregel blockiert diese Anfrage." | BUCKET_GENERIC | `DENY_CONFLICT_RESOLUTION`: Multiple rules matched; at least one produced DENY — deny-wins applied. | Deny-wins conflict resolution |
| 4.9 | Minimization violation (too many claims) | **DENY** | "Der Service fragt zu viele Daten ab." | BUCKET_GENERIC | `DENY_POLICY_MINIMIZATION_VIOLATION`: Request exceeds least-disclosure rule. | |
| 4.10 | Credential issuer DID not in `trustedIssuers` | **DENY** | "Der Aussteller deines Nachweises wird nicht akzeptiert." | BUCKET_GENERIC | `DENY_UNTRUSTED_ISSUER`: Credential issuer DID not in policy trustedIssuers. | |
| 4.11 | No suitable credential in wallet for requested type | **DENY** | "Du hast keinen passenden Nachweis für diese Anfrage." | BUCKET_GENERIC | `DENY_NO_SUITABLE_CREDENTIAL`: No credential in wallet matches requirement. | |
| 4.12 | Credential expired | **DENY** | "Dein Nachweis ist abgelaufen. Bitte erneuere ihn." | BUCKET_GENERIC | `DENY_CREDENTIAL_EXPIRED`: Credential expired: expiresAt < evaluation timestamp. | |
| 4.13 | Credential `issuedAt` in the future | **DENY** | "Ein Nachweis hat ein ungültiges Ausstellungsdatum." | BUCKET_GENERIC | `DENY_FUTURE_ISSUANCE`: Credential issuedAt is in the future — clock skew or forgery. | |
| 4.14 | Credential too old per `maxCredentialAgeDays` | **DENY** | "Dein Nachweis ist zu alt für diese Anfrage. Bitte aktualisiere ihn." | BUCKET_GENERIC | `DENY_CREDENTIAL_TOO_OLD`: Credential age exceeds maxCredentialAgeDays. | |
| 4.15 | Internal error during evaluation | **DENY** | "Ein interner Fehler ist aufgetreten. Bitte versuche es später." | BUCKET_GENERIC | `DENY_INTERNAL_SAFE_FAILURE`: Internal error caught and handled fail-closed. | Catch-all fail-closed |
| 4.16 | Jurisdiction mismatch | **DENY** | "Dieser Dienst ist in deiner Region nicht verfügbar." | BUCKET_GENERIC | `DENY_JURISDICTION_INCOMPATIBLE`: Jurisdiction mismatch. | |

---

## Step 5 — Step-Up (WebAuthn) If Needed

If policy returns PROMPT or high-risk threshold reached, user must re-authenticate via WebAuthn / biometrics.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 5.1 | Policy says PROMPT, user confirms via WebAuthn | **CONTINUE** | — | — | User consent obtained; presence proof verified | Happy path |
| 5.2 | Policy says PROMPT, user declines | **DENY** | "Deine Zustimmung wird benötigt." | BUCKET_USER_ACTION | `DENY_CONSENT_REQUIRED`: Policy rule requires explicit user consent (requiresUserConsent=true). | |
| 5.3 | Biometric required, user fails verification | **DENY** | "Biometrische Bestätigung erforderlich." | BUCKET_USER_ACTION | `DENY_PRESENCE_REQUIRED`: Presence proof required (accessibility active or high-risk). | |
| 5.4 | Re-auth required (high-risk threshold) | **DENY** (until re-auth) | "Erneute Authentifizierung erforderlich." | BUCKET_USER_ACTION | `DENY_REAUTH_REQUIRED`: Re-authentication required — high-risk prompt threshold reached. | |
| 5.5 | WebAuthn timeout | **DENY** | "Biometrische Bestätigung erforderlich." | BUCKET_USER_ACTION | `DENY_PRESENCE_REQUIRED` | ⚠️ **ACTION ITEM:** Verify WebAuthn timeout maps to PRESENCE_REQUIRED vs a separate code. See findings. |

---

## Step 6 — Presentation Created and Sent

Wallet creates VP (SD-JWT with selective disclosure), binds to nonce, sends to verifier.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 6.1 | All checks passed, presentation created with correct disclosures | **ALLOW** | — | Presentation verified successfully | Presentation created; nonce consumed; disclosures: [givenName, familyName] | Happy path |
| 6.2 | Request hash doesn't match after canonicalization | **DENY** | "Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut." | BUCKET_GENERIC | `DENY_BINDING_HASH_MISMATCH`: Canonical request hash does not match expected value. | MITM tamper detection |
| 6.3 | Audience field doesn't match verifier's own ID | **DENY** | "Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut." | BUCKET_GENERIC | `DENY_BINDING_AUDIENCE_MISMATCH`: DecisionCapsule audience does not match expected wallet app ID. | |
| 6.4 | Signing key revoked since issuance | **DENY** | "Sicherheitsschlüssel ungültig." | BUCKET_GENERIC | `DENY_CRYPTO_KEY_STATUS_INVALID`: Signing key revoked or status invalid. | |
| 6.5 | Agent delegation attempted, agent not authorized | **DENY** | "Diese automatische Aktion ist nicht erlaubt." | BUCKET_GENERIC | `DENY_AGENT_NOT_AUTHORIZED`: Agent DID not in delegationRules.allowed_agent_dids. | |
| 6.6 | Agent delegation, exceeds max claims per request | **DENY** | "Zu viele Daten für eine automatische Freigabe." | BUCKET_GENERIC | `DENY_AGENT_LIMIT_EXCEEDED`: Agent request exceeds max_claims_per_request delegation limit. | |

---

## Step 7 — Replay Attempt → Must DENY

Attacker (or verifier) re-submits the same presentation with same nonce.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 7.1 | Same nonce re-submitted after consumption | **DENY** | "Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut." | BUCKET_GENERIC | `DENY_BINDING_NONCE_REPLAY`: Nonce already consumed — replay attack detected. | **Critical anti-replay test** |
| 7.2 | Nonce expired (past TTL) | **DENY** | "Die Anfrage ist abgelaufen. Bitte starte den Vorgang neu." | BUCKET_GENERIC | `DENY_BINDING_EXPIRED`: Request timestamp outside acceptable skew window. | Nonce store handles expiry + replay atomically |
| 7.3 | Nonce store full (LRU eviction) — evicted nonce replayed | **DENY** | "Sicherheitsprüfung fehlgeschlagen. Bitte versuche es erneut." | BUCKET_GENERIC | `DENY_BINDING_NONCE_REPLAY` or `DENY_BINDING_FAILED` | Evicted nonce = unknown nonce = DENY |
| 7.4 | Rate limit exceeded (>10 req/60s from same verifier) | **DENY** | "Zu viele Anfragen. Bitte warte einen Moment." | BUCKET_RATE | `DENY_RATE_LIMIT_EXCEEDED`: Verifier exceeded rate limit: >10 requests per 60s window. | Different verifier bucket! |

---

## Step 8 — Revocation Flip → Must DENY

Issuer marks the credential as revoked in StatusList2021; next verification must fail.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 8.1 | Issuer sets bit at `statusListIndex` → revoked | **DENY** | "Dein Nachweis wurde zurückgezogen. Bitte kontaktiere den Aussteller." | BUCKET_GENERIC | `DENY_CREDENTIAL_REVOKED`: Credential revoked: status-list index marked revoked by issuer. | **Critical revocation test** |
| 8.2 | Status list URL unreachable, high-risk tier | **DENY** | "Ein externer Dienst ist nicht erreichbar. Bitte versuche es später." | BUCKET_INFRA | `DENY_STATUS_SOURCE_UNAVAILABLE`: Status source unavailable or timed out. | No grace period for high-risk |
| 8.3 | Status list URL unreachable, low-risk tier, within grace | **ALLOW** (stale cache) | — | — | Stale cache used within offline grace period (1h) | `graceMode=true` in result |
| 8.4 | Status list URL unreachable, low-risk tier, beyond grace | **DENY** | "Ein externer Dienst ist nicht erreichbar. Bitte versuche es später." | BUCKET_INFRA | `DENY_STATUS_SOURCE_UNAVAILABLE` | Grace period expired |
| 8.5 | Status list returned but `encodedList` missing | **DENY** | "Ein interner Fehler ist aufgetreten. Bitte versuche es später." | BUCKET_GENERIC | `DENY_INTERNAL_SAFE_FAILURE`: Invalid status list: missing encodedList. | Fetch validation |
| 8.6 | Status list index out of range | **DENY** | "Ein interner Fehler ist aufgetreten. Bitte versuche es später." | BUCKET_GENERIC | `DENY_INTERNAL_SAFE_FAILURE`: Index out of range — fail-closed. | |
| 8.7 | Status list type is not `StatusList2021` | **DENY** | "Ein interner Fehler ist aufgetreten. Bitte versuche es später." | BUCKET_GENERIC | `DENY_INTERNAL_SAFE_FAILURE`: type is not StatusList2021. | |

---

## Step 9 — Export Audit Evidence

System exports audit trail: hashes, policy snapshot, audience-split reasons, timestamps.

| # | Input Condition | Expected Verdict | User Reason | Verifier Reason | Audit Reason | Notes |
|---|---|---|---|---|---|---|
| 9.1 | Successful flow — export complete audit record | **N/A** | — | — | Full audit trail: requestHash, policyVersion, matchedRule, verdict=ALLOW, nonce consumed, disclosures list, timestamps | Happy path |
| 9.2 | Denied flow — export audit with deny code | **N/A** | — | — | Full audit trail: requestHash, policyVersion, verdict=DENY, denyCode=`DENY_*`, all three audience messages recorded | |
| 9.3 | Audit log includes all three audience messages | **N/A** | Stored separately | Stored separately | All three stored; access-controlled by audience | Anti-oracle preserved in storage |
| 9.4 | Unknown deny code at export time | **N/A** | Falls back to `DENY_INTERNAL_SAFE_FAILURE` user msg | Falls back to `DENY_INTERNAL_SAFE_FAILURE` verifier msg | `getDenyMessage()` fallback: unknown code → INTERNAL_SAFE_FAILURE | `getDenyMessage()` fail-closed fallback |

---

## Summary: All 31 Deny Codes Coverage

| Deny Code | Covered in Step(s) |
|---|---|
| `DENY_CREDENTIAL_EXPIRED` | 4.12 |
| `DENY_CREDENTIAL_REVOKED` | 8.1 |
| `DENY_CREDENTIAL_TOO_OLD` | 4.14 |
| `DENY_NO_SUITABLE_CREDENTIAL` | 4.11 |
| `DENY_FUTURE_ISSUANCE` | 4.13 |
| `DENY_POLICY_MISMATCH` | 4.1 (implicit) |
| `DENY_POLICY_MISSING` | 4.5 |
| `DENY_POLICY_UNSUPPORTED_VERSION` | 4.6 |
| `DENY_NO_MATCHING_RULE` | 4.7 |
| `DENY_CLAIM_NOT_ALLOWED` | 4.3 |
| `DENY_POLICY_MINIMIZATION_VIOLATION` | 4.9 |
| `DENY_LAYER_VIOLATION` | 4.4 |
| `DENY_UNKNOWN_VERIFIER` | 4.2 |
| `DENY_UNTRUSTED_ISSUER` | 4.10 |
| `DENY_BINDING_FAILED` | 2.3 |
| `DENY_BINDING_NONCE_REPLAY` | 7.1, 7.3 |
| `DENY_BINDING_HASH_MISMATCH` | 6.2 |
| `DENY_BINDING_AUDIENCE_MISMATCH` | 6.3 |
| `DENY_BINDING_EXPIRED` | 2.2, 7.2 |
| `DENY_CRYPTO_VERIFY_FAILED` | 3.3, 3.4, 3.5, 3.6 |
| `DENY_CRYPTO_UNSUPPORTED_ALG` | 3.7 |
| `DENY_CRYPTO_KEY_STATUS_INVALID` | 6.4 |
| `DENY_AGENT_NOT_AUTHORIZED` | 6.5 |
| `DENY_AGENT_LIMIT_EXCEEDED` | 6.6 |
| `DENY_RATE_LIMIT_EXCEEDED` | 7.4 |
| `DENY_CONSENT_REQUIRED` | 5.2 |
| `DENY_PRESENCE_REQUIRED` | 5.3, 5.5 |
| `DENY_REAUTH_REQUIRED` | 5.4 |
| `DENY_STATUS_SOURCE_UNAVAILABLE` | 8.2, 8.4 |
| `DENY_RESOLVER_QUORUM_FAILED` | 3.2, 3.8 |
| `DENY_JURISDICTION_INCOMPATIBLE` | 4.16 |
| `DENY_CONFLICT_RESOLUTION` | 4.8 |
| `DENY_INTERNAL_SAFE_FAILURE` | 4.15, 8.5, 8.6, 8.7, 9.4 |

**All 31 deny codes exercised.** ✅

---

## Action Items (Flagged as Unclear)

| ID | Issue | Step | Priority |
|---|---|---|---|
| AI-01 | `did:web:localhost` resolves over HTTP — no explicit block for production | 3.9 | HIGH |
| AI-02 | WebAuthn timeout → which deny code? `PRESENCE_REQUIRED` vs `REAUTH_REQUIRED` unclear | 5.5 | MEDIUM |
| AI-03 | `DENY_POLICY_MISMATCH` has no explicit scenario — may overlap with `NO_MATCHING_RULE` | 4.x | LOW |
| AI-04 | Audit export format not yet specified — what fields, what schema? | 9.x | MEDIUM |
| AI-05 | Grace period for low-risk + stale cache (8.3) returns ALLOW — is this acceptable for pilot? | 8.3 | HIGH |
| AI-06 | `DIDResolver` default instance uses `allowMockFallback=true` — legacy API still exposed | 3.5 | HIGH |
