# Evidence Pack — P0 Blockers (G-01 through G-06)

> **Generated:** 2026-03-04  
> **Branch:** consolidation (merged to master)  
> **Purpose:** Auditable evidence for pilot readiness review  
> **Author:** miTch team

---

## G-01 — DID Resolution + Signature Verification

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** MITM / key spoofing / impersonation

### 1) Spec Anchor (normative)

- **Doc:** W3C DID Core (https://www.w3.org/TR/did-core/), W3C DID Resolution (https://w3c-ccg.github.io/did-resolution/)
- **Section:** §7 (DID Document), §8 (DID Resolution)
- **Normative rule:**
  - MUST resolve DID to DID Document over HTTPS (did:web) or trusted backend (did:mitch)
  - MUST extract verification key from `verificationMethod` using `assertionMethod` or `authentication` relationship
  - MUST verify JWT signature against resolved key
  - MUST NOT accept credentials if resolution fails (fail-closed)
  - SHOULD cache resolved documents with configurable TTL

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/shared-crypto/src/did.ts` — `DIDResolver` class: resolution, caching, key extraction
  - `src/packages/shared-crypto/src/did-verification.ts` — `DIDSignatureVerifier` class: combined resolve + verify
- **Decision points:**
  - `DIDResolver.resolve()` — throws `DIDResolutionError` on any failure (HTTP error, timeout, malformed doc, unsupported method)
  - `DIDResolver.extractVerificationKey()` — throws `DIDKeyExtractionError` if no verificationMethod or missing publicKeyJwk
  - `DIDSignatureVerifier.verifyPresentation()` — returns `{ verified: false, errorCode }` on ANY failure; never throws
- **Fail-closed behavior:**
  - `DIDSignatureVerifier` constructor forces `allowMockFallback: false` — mock DIDs rejected in verification path
  - Unsupported DID methods → `DIDResolutionError` (not a silent fallback)
  - Network timeout (configurable, default 10s) → `DIDResolutionError`
  - Malformed DID Document (missing `id`, missing `@context`) → `DIDResolutionError`
  - Key import failure → `DIDKeyExtractionError`
  - Signature mismatch → `errorCode: 'SIGNATURE_INVALID'`

### 3) Tests (prove it)

- **Unit/Integration:** `src/packages/shared-crypto/test/did.test.ts`
- **Negative tests (fail-closed):**
  - `DENY on HTTP error (fail-closed)` — resolver returns 404 → `DIDResolutionError`
  - `DENY on network error (fail-closed)` — fetch throws → `DIDResolutionError`
  - `DENY on malformed DID document (missing id)` — doc without `id` → rejection
  - `DENY on malformed DID document (missing @context)` — doc without `@context` → rejection
  - `DENY on unsupported DID method (no mock fallback)` — `did:key:...` → `Unsupported DID method`
  - `DENY on timeout (fail-closed)` — slow server → abort → `DIDResolutionError`
  - `DENY when DID resolution fails` — verifier returns `{ verified: false, errorCode: 'RESOLUTION_FAILED' }`
  - `DENY on key mismatch (signed with different key)` — JWT signed with key A, DID resolves key B → `SIGNATURE_INVALID`
  - `DENY on malformed DID document` (via verifier) — garbage JSON → `RESOLUTION_FAILED`
  - `DENY on network timeout` (via verifier) — slow fetch → `RESOLUTION_FAILED`
  - `DENY when no verificationMethod` — empty array → `DIDKeyExtractionError`
  - `DENY when no publicKeyJwk` — missing JWK → `DIDKeyExtractionError`
- **Positive tests:**
  - `resolves did:web successfully` — valid doc cached
  - `caches resolved documents` — second call uses cache (1 fetch total)
  - `re-resolves after cache expiry` — expired TTL triggers re-fetch
  - `verifies valid JWT signed with DID-resolved key → ALLOW` — full E2E with ES256 keypair

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| MITM intercepts DID Document fetch | did:web uses HTTPS; localhost uses HTTP only for dev | DNS poisoning could redirect HTTPS; mitigated by certificate pinning (future G-27 multi-resolver quorum) |
| Attacker publishes malicious DID Document | Document validation: requires `@context`, `id`, valid `verificationMethod` with JWK | Compromised web server hosting `did.json` could serve attacker keys; mitigated by key rotation + cache eviction |
| Key substitution (sign with different key) | JWT `jwtVerify()` against DID-resolved key — mismatch = `SIGNATURE_INVALID` | None for ES256; algorithm confusion attacks mitigated by explicit alg in JWT header |
| Replay of stale DID Document | TTL cache (default 1h); `evict()` method for forced re-resolution | Stale cache within TTL window could miss key rotation; acceptable for pilot |
| Mock fallback in production | `DIDSignatureVerifier` hardcodes `allowMockFallback: false` | Legacy `resolveDID()` function still allows mock — marked `@deprecated` |

### 5) Operational semantics

- **Versioning / compatibility:** DID Documents follow W3C DID Core v1.0. `JsonWebKey2020` verification method type.
- **Rotation / TTL / cache:** Default 1h TTL. `evict(did)` forces re-resolution. `clearCache()` for full reset.
- **Failure mode:** All resolution/verification failures return structured error (never throws from verifier). Caller receives `{ verified: false, errorCode, error }`.
- **Audit evidence:** `DIDVerificationResult` contains `did`, `verified`, `errorCode`, `error`, `payload` — suitable for audit logging.

### 6) Evidence checklist

- [x] Spec exists + is coherent (W3C DID Core + DID Resolution)
- [x] Mechanism is enforceable (`DIDSignatureVerifier` with fail-closed, no mock fallback)
- [x] Negative tests exist — 12 distinct fail-closed tests
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `did.ts` (resolver), `did-verification.ts` (verifier), `did.test.ts` (tests)

---

## G-02 — StatusList2021 Revocation (Fail-Closed)

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** Revocation bypass / use-after-revoke

### 1) Spec Anchor (normative)

- **Doc:** W3C VC Status List 2021 (https://www.w3.org/TR/vc-status-list/)
- **Section:** §4 (StatusList2021Entry), §5 (StatusList2021Credential)
- **Normative rule:**
  - MUST fetch status list credential from `statusListCredential` URL
  - MUST decode Base64 bitstring and check bit at `statusListIndex` (MSB-first)
  - MUST NOT allow credential use if bit is set (revoked)
  - MUST DENY if status list is unreachable for high-risk tiers (fail-closed)
  - SHOULD cache status lists with TTL to preserve privacy (batch fetch)

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/revocation-statuslist/src/index.ts` — `StatusListRevocationChecker` class
  - `src/packages/revocation-statuslist/src/types.ts` — type definitions
- **Decision points:**
  - `checkRevocation(statusEntry, riskTier)` — returns `RevocationCheckResult` with `decision: 'ALLOW' | 'DENY'`
  - `checkRevocationBatch()` — deduplicates fetches per URL (privacy-preserving)
- **Fail-closed behavior:**
  - **High-risk tier:** Fetch failure/timeout → `DENY` immediately with `DENY_STATUS_SOURCE_UNAVAILABLE`. No stale cache fallback.
  - **Low-risk tier:** Fetch failure → stale cache within grace period (default 1h) → DENY beyond grace period.
  - Invalid status list (missing `encodedList`, wrong `type`) → fetch throws → DENY
  - Invalid index (negative, out of range, NaN) → `DENY` with `DENY_INTERNAL_SAFE_FAILURE`
  - Revoked bit set → `DENY` with `DENY_CREDENTIAL_REVOKED`

### 3) Tests (prove it)

- **Unit/Integration:** `src/packages/revocation-statuslist/src/__tests__/checker.test.ts`
- **Negative tests (fail-closed):**
  - `returns DENY with STATUS_SOURCE_UNAVAILABLE for high-risk` — network error → DENY
  - `returns DENY on timeout for high-risk` — fetch timeout → DENY
  - `returns DENY with REVOKED reason for revoked index` — bit set at index 5 → DENY
  - `returns DENY for another revoked index` — bit set at index 10 → DENY
  - `high-risk: DENY immediately even with stale cache` — expired cache + fetch fail → DENY (no grace)
  - `low-risk: DENY beyond grace period` — no cache + fetch fail → DENY
  - `invalid index (out of range) → DENY` — index 999 in 4-byte list → DENY
  - `negative index → DENY` — index -1 → DENY
- **Positive tests:**
  - `returns ALLOW for non-revoked index` — index 0 not in revoked set
  - `low-risk: uses stale cache within grace period` — offline grace allows stale cache
  - `uses cached status list when fresh` — second check uses cache
  - `deduplicates fetches for same URL` — batch of 3 entries, 1 fetch

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Use credential after issuer revokes it | Bitstring check at `statusListIndex`; revoked bit = DENY | Cache TTL window (max 5min default) — credential usable until cache expires |
| Block status list fetch to force ALLOW | High-risk: DENY on any fetch failure. Low-risk: grace period then DENY | Low-risk tier has 1h grace window with stale data |
| Privacy attack: correlate per-credential revocation checks | Batch fetch of entire list; never per-credential queries | Status list URL itself may be a correlation signal (mitigated by shared lists) |
| Malformed status list to bypass check | Validates `type === 'StatusList2021'` and `encodedList` presence; parse failure = DENY | Sophisticated malformed list that passes validation but has wrong encoding — mitigated by MSB-first bit parsing per spec |
| Index manipulation (out-of-bounds) | Bounds check: `byteIndex >= bitstring.length` → DENY; negative/NaN → DENY | None identified |

### 5) Operational semantics

- **Versioning / compatibility:** StatusList2021 per W3C spec. `encodedList` is Base64 (standard + URL-safe handled).
- **Rotation / TTL / cache:** Default 5min cache TTL. Grace period for low-risk: 1h. Cache keyed by status list URL.
- **Failure mode:** `RevocationCheckResult` always returned (never throws). Contains `decision`, `revoked`, `reason`, `denyCode`, `fromCache`, `graceMode`.
- **Audit evidence:** Result includes `listUrl`, `checkedAt`, `fromCache`, `graceMode` — full audit trail.

### 6) Evidence checklist

- [x] Spec exists + is coherent (W3C StatusList2021)
- [x] Mechanism is enforceable (risk-tiered fail-closed, DENY on fetch failure for high-risk)
- [x] Negative tests exist — 8 fail-closed tests including the critical "DENY on unreachable" regression
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `revocation-statuslist/src/index.ts`, `checker.test.ts`

---

## G-03 — Deny Reason Codes (3-Audience Anti-Oracle Split)

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** Oracle attack / policy probing

### 1) Spec Anchor (normative)

- **Doc:** Internal spec 108 (Policy Engine Deterministic Evaluation), spec 21 (Deny Reason Code Catalog)
- **Section:** Conflict resolution, audience-split reason codes
- **Normative rule:**
  - MUST provide 3 audience-specific messages per deny code: user, verifier, audit
  - MUST NOT reveal policy internals to verifiers (anti-oracle)
  - MUST map multiple distinct deny reasons to the same verifier-facing bucket message
  - MUST resolve policy conflicts deterministically: ANY DENY → DENY, ANY PROMPT (no DENY) → PROMPT, ALL ALLOW → ALLOW
  - MUST DENY on missing policy or unknown policy version (fail-closed)

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/policy-engine/src/deny-reason-codes.ts` — `DenyReasonCode` enum (35 codes), `DENY_REASON_CATALOG`, `getDenyMessage()`, `getVerifierDenyMessage()`
  - `src/packages/policy-engine/src/conflict-resolver.ts` — `resolveConflict()`, `validatePolicyOrDeny()`, `isPolicyVersionKnown()`
- **Decision points:**
  - `resolveConflict(verdicts[])` — deterministic deny-wins: DENY > PROMPT > ALLOW
  - `validatePolicyOrDeny(policy)` — missing/null policy → DENY; unknown version → DENY
  - `getDenyMessage(code, audience)` — unknown code falls back to `INTERNAL_SAFE_FAILURE` (fail-closed)
- **Anti-oracle enforcement:**
  - 4 verifier bucket messages only: `'Verification could not be completed.'`, `'Request rate exceeded.'`, `'User action required.'`, `'Service temporarily unavailable.'`
  - All 35 deny codes map to one of these 4 buckets
  - Verifier cannot distinguish EXPIRED from REVOKED from POLICY_MISMATCH from BINDING_FAILED — all return `'Verification could not be completed.'`

### 3) Tests (prove it)

- **Unit:** `src/packages/policy-engine/test/denial.test.ts`
- **Negative tests (anti-oracle / fail-closed):**
  - `should gracefully handle unknown reason codes` — unknown code → falls back to `NO_MATCHING_RULE` default
  - `should map UNKNOWN_VERIFIER to critical severity with actions` — verifier gets generic message, user gets actionable message
  - `should perform string interpolation in messages` — user message includes verifier ID; verifier message does NOT
- **Structural anti-oracle proof:**
  - `DENY_REASON_CATALOG` maps 27+ codes to `VERIFIER_BUCKET_GENERIC` — verifier cannot distinguish them
  - Binding-related codes (`NONCE_REPLAY`, `HASH_MISMATCH`, `AUDIENCE_MISMATCH`, `BINDING_EXPIRED`, `BINDING_FAILED`) all map to same verifier bucket
  - Policy codes (`POLICY_MISMATCH`, `POLICY_MISSING`, `NO_MATCHING_RULE`, `CLAIM_NOT_ALLOWED`) all map to same verifier bucket
- **Conflict resolution (implicit in engine tests):**
  - `resolveConflict([])` → DENY (no matching rules = fail-closed)
  - `resolveConflict([DENY, ALLOW])` → DENY (deny-wins)
  - `resolveConflict([PROMPT, ALLOW])` → PROMPT

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Verifier probes policy rules by observing different error messages | All deny codes map to 4 generic verifier buckets; indistinguishable | Timing side-channels (different code paths may have different latency) — not yet mitigated |
| Policy ambiguity exploited to get ALLOW | Deny-wins conflict resolution: ANY DENY in matched rules → final DENY | None — deterministic, pure function |
| Unknown policy version bypasses checks | `isPolicyVersionKnown()` rejects unknown versions → DENY | New version must be explicitly added to `KNOWN_POLICY_VERSIONS` set |
| Missing policy → default ALLOW | `validatePolicyOrDeny()` returns DENY for null/undefined/missing-version policy | None — explicit null check |
| User confused by generic error | User audience gets German-language actionable messages (e.g., "Dein Nachweis ist abgelaufen. Bitte erneuere ihn.") | Localization limited to German for pilot |

### 5) Operational semantics

- **Versioning / compatibility:** Known versions: `1.0.0`, `1.1.0` in `KNOWN_POLICY_VERSIONS` set. Adding new version requires code change.
- **Rotation / TTL:** Reason codes are static enum. Catalog is compile-time constant.
- **Failure mode:** Unknown deny code → `INTERNAL_SAFE_FAILURE` message (generic, safe). Conflict resolver with empty input → DENY.
- **Audit evidence:** Audit audience message contains full technical detail (e.g., `'Nonce already consumed — replay attack detected.'`). Access-controlled separately from user/verifier messages.

### 6) Evidence checklist

- [x] Spec exists + is coherent (spec 108, spec 21)
- [x] Mechanism is enforceable (4 verifier buckets, deny-wins conflict resolution)
- [x] Negative tests exist (unknown codes, anti-oracle structural proof)
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `deny-reason-codes.ts`, `conflict-resolver.ts`, `denial.test.ts`

---

## G-04 — Anti-Replay Binding (Nonce Store + TTL)

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** Replay attack / context swap

### 1) Spec Anchor (normative)

- **Doc:** `docs/specs/108_Presentation_Binding_AntiReplay_Spec_v1.md`
- **Section:** §5 (Binding Validation Order)
- **Normative rule:**
  - MUST bind presentation request to nonce + audience + expiry + request hash
  - MUST consume nonce atomically (single-use)
  - MUST DENY replay (same nonce consumed twice)
  - MUST DENY expired nonce (beyond TTL + clock skew tolerance)
  - MUST DENY audience mismatch (nonce bound to different verifier)
  - MUST DENY if canonical request hash doesn't match
  - MUST DENY if required fields are missing
  - SHOULD tolerate clock skew within configurable window (default ±30s)

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/shared-crypto/src/nonce-store.ts` — `BindingNonceStore` class (issue, register, consume, pruning, LRU eviction)
  - `src/packages/shared-crypto/src/presentation-binding.ts` — `validateBinding()`, `computeRequestHash()`
- **Decision points:**
  - `BindingNonceStore.consume(audience, nonce, now)` — returns `{ ok: true }` exactly once; all subsequent calls return `{ ok: false, code }`
  - `validateBinding(req, store, verifierAudience, now)` — ordered validation: required fields → expiry → audience → hash → nonce consume
- **Fail-closed behavior:**
  - Unknown nonce → `DENY_BINDING_NONCE_UNKNOWN`
  - Replayed nonce (consumed + deleted) → `DENY_BINDING_NONCE_UNKNOWN` (entry removed after first consume)
  - Expired nonce (beyond TTL + 30s skew) → `DENY_BINDING_EXPIRED`
  - Wrong audience → `DENY_BINDING_AUDIENCE_MISMATCH`
  - Hash mismatch → `DENY_BINDING_HASH_MISMATCH`
  - Missing field → `DENY_SCHEMA_MISSING_FIELD`
- **Nonce lifecycle:**
  - Generated: 32 bytes (256 bits) from `crypto.getRandomValues()`
  - TTL: configurable (default 5 minutes)
  - Clock skew: configurable (default ±30 seconds)
  - Eviction: LRU when exceeding `maxEntries` (default 100,000)
  - After consume: entry immediately deleted from store

### 3) Tests (prove it)

- **Unit/Integration:** `src/packages/shared-crypto/test/presentation-binding.test.ts`
- **Negative tests (fail-closed):**
  - `replay same nonce → DENY` — consume twice → second returns `DENY_BINDING_NONCE_UNKNOWN`
  - `unknown nonce → DENY` — consume nonexistent → `DENY_BINDING_NONCE_UNKNOWN`
  - `expired nonce (beyond skew) → DENY` — advance past TTL+skew → `DENY_BINDING_EXPIRED`
  - `wrong audience → DENY` — consume with different verifier DID → `DENY_BINDING_NONCE_UNKNOWN`
  - `replay same presentation → DENY` — full binding validation, second attempt fails
  - `expired nonce → DENY` (via validateBinding) — past expiry → DENY
  - `wrong audience → DENY` (via validateBinding) — `DENY_BINDING_AUDIENCE_MISMATCH`
  - `tampered hash → DENY` — modified requestHash → `DENY_BINDING_HASH_MISMATCH`
  - `missing required field → DENY` — empty version → `DENY_SCHEMA_MISSING_FIELD`
  - `clock skew beyond tolerance → DENY` — 30,001ms past expiry → DENY
- **Positive tests:**
  - `issue and consume — valid flow` — single use succeeds
  - `nonce within clock skew → ALLOW` — 15s past TTL but within 30s skew → succeeds
  - `valid presentation → ALLOW` — full binding validation passes
  - `same input → same hash` (canonicalization determinism)
  - `different nonce → different hash`, `different audience → different hash` (hash sensitivity)

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Replay presentation (reuse nonce) | Nonce consumed atomically + deleted; second use → DENY | In-memory store; server restart clears store (all outstanding nonces invalidated — safe direction) |
| Context swap (present to different verifier) | Audience binding: nonce is keyed by `audience\0nonce`; wrong audience → unknown | None — composite key enforces binding |
| Clock manipulation to extend nonce life | Clock skew tolerance ±30s; beyond that → DENY | ±30s window is the maximum exploitation window |
| Brute-force nonce prediction | 256-bit random nonce (2^256 keyspace); infeasible | None |
| Hash tampering to substitute request content | SHA-256 canonical hash verified before nonce consume | Hash collision (2^128 for SHA-256); infeasible for pilot |
| Nonce store memory exhaustion | LRU eviction at 100k entries; `pruneExpired()` on every operation | Under extreme load, legitimate nonces could be evicted — fails closed (DENY) |

### 5) Operational semantics

- **Versioning / compatibility:** Nonce store is in-memory, ephemeral. No persistence across restarts (safe: all nonces invalidated).
- **Rotation / TTL:** Default 5min TTL + 30s clock skew. Configurable via `NonceStoreConfig`.
- **Failure mode:** Store full → LRU eviction → evicted nonces fail-closed. Server restart → all nonces lost → clients must re-request (safe direction).
- **Audit evidence:** `ConsumeResult` contains deny code on failure. `BindingValidationResult` contains specific code for each failure mode.

### 6) Evidence checklist

- [x] Spec exists + is coherent (spec 108)
- [x] Mechanism is enforceable (atomic consume, composite audience key, SHA-256 hash)
- [x] Negative tests exist — 10 distinct replay/expiry/tamper/mismatch tests
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `nonce-store.ts`, `presentation-binding.ts`, `presentation-binding.test.ts`

---

## G-05 — eID Issuer Simulator (SD-JWT VC, ES256, DID Doc)

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** Credential forgery / issuer impersonation

### 1) Spec Anchor (normative)

- **Doc:** `docs/specs/110_eID_Issuer_Simulator_Fidelity.md`
- **Section:** "What the Simulator Does Faithfully" / "What the Simulator Skips"
- **Normative rule:**
  - MUST issue SD-JWT VC credentials with ES256 signatures (production-identical algorithm)
  - MUST publish valid `did:web` DID Document with `JsonWebKey2020` verification method
  - MUST compute `age_over_18` predicate correctly from birthdate
  - MUST support selective disclosure (individual claim disclosures with SHA-256 hashing)
  - MUST NOT be used in production (clearly non-production DID: `did:web:eid-simulator.mitch.local`)
  - SHOULD model eID-Client protocol state machine (idle → tc_token → pin → card_read → issue → complete)

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/eid-issuer-connector/src/index.ts` — `EIDIssuerConnector` class
  - `src/packages/eid-issuer-connector/src/types.ts` — type definitions
  - `docs/specs/110_eID_Issuer_Simulator_Fidelity.md` — fidelity constraints doc
- **Decision points:**
  - `initialize()` — generates ephemeral ES256 keypair per session
  - `requestIssuance(request, profile)` — validates required fields, runs protocol state machine, issues SD-JWT VC
  - `verifyCredential(sdJwt)` / `verifyWithPublicKey(sdJwt, jwk, issuer)` — verifies JWT signature, parses disclosures, checks `_sd` hashes
- **Fidelity guarantees:**
  - ES256 (ECDSA P-256) — same algorithm as production eID issuers
  - SD-JWT VC format per `draft-ietf-oauth-sd-jwt-vc`: `vct`, `_sd`, `_sd_alg`, disclosures
  - DID Document with `assertionMethod` and `authentication` relationships
  - Protocol state machine tracks all states (observable via `getSession()`)
- **Known limitations (documented in spec 110):**
  - PIN verification is state-transition only (no actual check)
  - No smartcard/NFC interaction
  - Self-signed keypair (no BSI CA certificate chain)
  - No AusweisApp2 SDK integration
  - No eIDAS SAML

### 3) Tests (prove it)

- **Unit/Integration:** `src/packages/eid-issuer-connector/src/__tests__/connector.test.ts`
- **Negative tests:**
  - `should fail verification with wrong key` — credential signed by connector A, verified by connector B → throws
  - `should reject request with missing userDID` — empty userDID → `'Invalid issuance request'`
  - `should reject request with empty attributes` — empty array → `'Invalid issuance request'`
  - `should reject request with missing purpose` — empty purpose → `'Invalid issuance request'`
  - `should reject unknown citizen profile` — `'nonexistent'` → `'Unknown citizen profile'`
  - `should throw for unimplemented modes` — `ausweisapp2` → `'not yet implemented'`
- **Positive tests:**
  - `should issue SD-JWT VC credential via simulated eID flow` — full protocol, valid SD-JWT structure
  - `should verify credential against issuer public key` — round-trip issue → verify
  - `should verify credential using static method with JWK` — external verifier flow
  - `should include correct selective disclosures` — 4 attributes → 4 disclosures with correct values
  - `should include age_over_18 predicate for adult citizen` — adult profile → `true`
  - `should include age_over_18 = false for minor citizen` — minor profile → `false`
  - `should publish a valid DID Document with verification key` — EC P-256 key, correct structure
  - `should verify credential using key from DID Document` — DID Doc → key → verify (simulated verifier flow)
  - `should track protocol session through all states` — session ends in `'complete'`

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Forge credential with wrong issuer key | `jwtVerify()` against DID-resolved key; wrong key → verification fails | None for ES256 |
| Use simulator credentials in production | DID is clearly non-production: `did:web:eid-simulator.mitch.local`. Production verifiers won't resolve it. | Social engineering to trust simulator DID — mitigated by verifier trust registry |
| Tamper with SD-JWT disclosures | Disclosure hashes verified against `_sd` array; mismatch → error | None — SHA-256 integrity |
| Age predicate forgery | `age_over_18` computed server-side from birthdate; not selectively disclosable | Simulator uses in-memory profiles — no real eID chip binding |
| Enumerate citizen profiles | Only `default` and `minor` profiles; unknown profile → error | Limited profile set is by design for testing |

### 5) Operational semantics

- **Versioning / compatibility:** SD-JWT VC per `draft-ietf-oauth-sd-jwt-vc`. VCT: `urn:eu:europa:ec:eudi:pid:1` (EU PID).
- **Rotation / TTL:** Keys are ephemeral per `initialize()` call. Credential validity: configurable (default 1 year).
- **Failure mode:** Uninitialized connector → `'Connector not initialized'` error. Invalid request → validation error.
- **Audit evidence:** Protocol sessions tracked with timestamps, states, and citizen data. All sessions inspectable via `getAllSessions()`.
- **Upgrade path:** Documented in spec 110: Phase 6 (AusweisApp2), Phase 7+ (eIDAS), Phase 8 (HSM + OCSP).

### 6) Evidence checklist

- [x] Spec exists + is coherent (spec 110 with fidelity matrix)
- [x] Mechanism is enforceable (real ES256, real SD-JWT VC, real DID Document)
- [x] Negative tests exist (wrong key, invalid requests, unknown profile)
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `eid-issuer-connector/src/index.ts`, `connector.test.ts`, `docs/specs/110_eID_Issuer_Simulator_Fidelity.md`

---

## G-06 — Credential Persistence (Encrypted at Rest)

**Status:** 🟩 Closed (Evidence-backed)  
**Owner:** miTch  
**Scope:** Pilot P0  
**Primary Threat Class:** Data breach / plaintext exposure / erasure failure

### 1) Spec Anchor (normative)

- **Doc:** Internal architecture (SecureStorage module), GDPR Art. 17 (right to erasure via crypto-shredding)
- **Section:** Storage model, encryption at rest
- **Normative rule:**
  - MUST encrypt all credential payloads at rest using AES-256-GCM
  - MUST NOT store plaintext PII in IndexedDB
  - MUST support credential deletion (crypto-shredding: key destruction = data erasure)
  - MUST fail-closed on wrong key (decryption failure → error, not partial data)
  - MUST persist credentials across page reloads (IndexedDB)
  - SHOULD support selective claim decryption (T-36a data minimization)

### 2) Mechanism (enforceable)

- **Components:**
  - `src/packages/secure-storage/src/index.ts` — `SecureStorage` class
- **Decision points:**
  - `SecureStorage.init(masterKey)` — initializes with AES-256-GCM CryptoKey
  - `save(id, data, metadata)` — serializes → encrypts → stores ciphertext + plaintext index tags
  - `load(id)` — retrieves → decrypts → parses. Wrong key → `'Decryption Failed'` error
  - `delete(id)` — removes both ciphertext and metadata from IndexedDB
  - `loadSelectiveClaims(id, effectiveClaims)` — T-36a: decrypt then filter to authorized claims only
- **Storage model:**
  - `EncryptedDocument`: `{ id, ciphertext (Base64 AES-256-GCM), indexTags (plaintext metadata) }`
  - Index tags contain structural info only (issuer DID, credential type, claims list, issuedAt) — never PII
  - IndexedDB with indexes on `type` and `issuer` for query optimization
- **Erasure semantics:**
  - `delete(id)` removes document from IndexedDB
  - `SecureStorage.reset()` deletes entire database
  - Master key destruction = crypto-shredding (ciphertext becomes unrecoverable)

### 3) Tests (prove it)

- **Unit/Integration:** `src/packages/secure-storage/test/persistence.test.ts`
- **Negative tests (fail-closed):**
  - `encrypted at rest — raw storage contains no plaintext PII` — raw ciphertext does NOT contain `'Alice Testperson'`, `'1990-05-15'`, `'123-45-6789'`; no plaintext `payload` field
  - `wrong key → decryption fails (fail-closed)` — different AES key → `'Decryption Failed'` error (not partial/plaintext data)
  - `delete credential → actually removed from storage` — after delete: `has()` returns false, `load()` returns null, metadata gone, double-delete returns false
  - `delete non-existent credential returns false (no crash)` — graceful handling
- **Positive tests:**
  - `credentials survive simulated reload (store → new instance → load)` — save in instance 1, load in instance 2 with same key → all fields intact
  - `multiple credentials persist independently` — delete one, other survives

### 4) Threat mapping (attack → mitigation)

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Disk/storage dump reveals PII | AES-256-GCM encryption; raw storage contains only ciphertext | IndexedDB metadata (index tags) is plaintext — contains issuer/type but NOT PII |
| Wrong key returns partial data | Decryption failure throws error; never returns partial/truncated plaintext | None — AES-GCM authentication tag prevents partial decryption |
| Credential survives deletion | `delete()` removes from IndexedDB; verified by `has()` + `load()` + metadata check | IndexedDB compaction is browser-controlled; deleted data may persist on disk briefly |
| Memory dump during decryption | Decrypted payload exists in JS heap temporarily | Mitigated by: JS GC, no persistent plaintext storage. Full mitigation requires TEE (G-20) |
| GDPR erasure request | Crypto-shredding: destroy master key → all ciphertext unrecoverable. `delete()` for individual credentials. `reset()` for full wipe. | Legal opinion on crypto-shredding as Art. 17 compliance pending (G-14) |

### 5) Operational semantics

- **Versioning / compatibility:** IndexedDB database `mitch_wallet_v1`, object store `credentials`. Schema version 1 with `onupgradeneeded`.
- **Rotation / TTL:** Master key rotation requires re-encryption of all stored credentials (not yet automated).
- **Failure mode:** IndexedDB unavailable → `init()` rejects. Wrong key → `load()` throws `'Decryption Failed'`. Corrupt data → same error.
- **Audit evidence:** `EncryptedDocument` structure with `indexTags` for metadata queries without decryption. `getRawDocument()` for test/audit verification of encryption.

### 6) Evidence checklist

- [x] Spec exists + is coherent (SecureStorage architecture + GDPR crypto-shredding)
- [x] Mechanism is enforceable (AES-256-GCM, fail-closed on wrong key, verified no plaintext on disk)
- [x] Negative tests exist (no plaintext PII, wrong key fails, deletion verified)
- [x] Threat mapping written
- [x] Ops semantics written
- [x] Code paths: `secure-storage/src/index.ts`, `persistence.test.ts`

---

## Cross-Cutting: Golden Fail-Closed Invariants

The following invariants hold across all 6 gaps and MUST be regression-tested:

| # | Invariant | Enforced By | Test Coverage |
|---|-----------|-------------|---------------|
| 1 | Unknown verifier / DID resolution fails → DENY | G-01 `DIDSignatureVerifier` | `did.test.ts`: 6 DENY-on-failure tests |
| 2 | Revocation status unknown/unreachable → DENY (high-risk) | G-02 `StatusListRevocationChecker` | `checker.test.ts`: 3 DENY-on-unreachable tests |
| 3 | Policy ambiguity / purpose mismatch → DENY or PROMPT, never ALLOW | G-03 `resolveConflict()` | `denial.test.ts` + structural: empty verdicts → DENY, deny-wins |
| 4 | Nonce replay → DENY | G-04 `BindingNonceStore.consume()` | `presentation-binding.test.ts`: replay tests |
| 5 | Wrong key / tampered credential → DENY | G-05 `verifyCredential()` / G-01 `DIDSignatureVerifier` | `connector.test.ts` + `did.test.ts`: wrong-key tests |
| 6 | Wrong encryption key → error (not partial data) | G-06 `SecureStorage.load()` | `persistence.test.ts`: wrong key test |

---

## File Index

| Gap | Source Files | Test Files | Spec Docs |
|-----|-------------|------------|-----------|
| G-01 | `src/packages/shared-crypto/src/did.ts`, `did-verification.ts` | `test/did.test.ts` | W3C DID Core |
| G-02 | `src/packages/revocation-statuslist/src/index.ts`, `types.ts` | `src/__tests__/checker.test.ts` | W3C StatusList2021 |
| G-03 | `src/packages/policy-engine/src/deny-reason-codes.ts`, `conflict-resolver.ts` | `test/denial.test.ts` | Spec 108, Spec 21 |
| G-04 | `src/packages/shared-crypto/src/presentation-binding.ts`, `nonce-store.ts` | `test/presentation-binding.test.ts` | Spec 108 |
| G-05 | `src/packages/eid-issuer-connector/src/index.ts`, `types.ts` | `src/__tests__/connector.test.ts` | `docs/specs/110_eID_Issuer_Simulator_Fidelity.md` |
| G-06 | `src/packages/secure-storage/src/index.ts` | `test/persistence.test.ts` | GDPR Art. 17 |
