# Phase-0 Security: Method Assessment & Cleanup-Drift Record (2026-10-29)

**Scope:** `src/packages/phase0-security/` — method-by-method assessment of
`ADVANCED_SECURITY_HARDENING.ts` and the consolidated `index.ts`, plus the
findings from the 2026-03-12 cleanup commit `01b94b1`.
**Type:** Dated QA/review record. No code change — this document deliberately
avoids re-adding or re-implementing anything, to prevent a second drift.
**Evidence:** local test run 2026-10-29: 149/149 tests pass (5 files) after
building `@askmi/shared-types` (the initial failure was a missing `dist/`, not
a code defect).

## 1. Cleanup-drift from commit `01b94b1` (confirmed, recorded, not restored)

`chore(phase0-security): delete duplicate root-level .ts files — code lives in
src/` deleted the 790-line root `ADVANCED_SECURITY_HARDENING.ts`. That file was
**not** a byte-duplicate of the 171-line `src/` version. The loss history is
more tangled than a single delete (all on 2026-03-12, within ~1 hour):

- `01b94b1` (21:31) deleted the root files (-2082 lines), including
  `HARDENING_CHECKLIST` and the recommendation matrix.
- `897b226` (22:27:30, "fix IndexedDB timeout") **re-introduced the root
  files with identical blob hashes** (+1960 lines) — the content was still
  fully present at that commit, and also changed test wiring (deleted
  `test/setup.ts`, `pool: forks`).
- `81d1672` (22:27:47) reverted `897b226`, deleting the root files again —
  this is the commit where the loss became final. The revert also carried
  ~513 lines of unrelated in-flight changes (OID4VP tests in verifier-demo,
  wallet-pwa `App.tsx`) and permanently restored `test/setup.ts` and
  `pool: forks`, both of which survive in some form to HEAD.

Recovered into `src/index.ts`: `MemoryHardeningProtection`,
  `NetworkHardeningProtection`, `SupplyChainHardeningProtection`,
  `PhysicalSeizureProtection`, `AIResistanceProtection`.
- **Lost with no surviving copy:** the exported `HARDENING_CHECKLIST` const
  (✅/⚠️ threat-mapping lists: againstGoogle, againstMemoryDumps,
  againstNetworkSurveillance, againstSupplyChain, againstPhysicalSeizure,
  againstAI) and the `RECOMMENDATION MATRIX` (Consumer→Government phase
  table). Zero occurrences remain in `src/` or `docs/`.
- **Follow-up drift created by the cleanup:** `src/index.ts` (1104 lines) is
  still a self-described "Consolidated Entry" that duplicates
  `UserDerivedKeyProtection` and `SplitKeyProtection` with **different APIs**
  from `ADVANCED_SECURITY_HARDENING.ts` (see §2.3). Tests and
  `integration-example.ts` import the modular files; nothing outside the
  package imports either.

Decision for this record: do **not** restore the lost checklist/matrix as code.
If the content is still wanted, it belongs in a dated doc (e.g. under
`docs/context/`) as historical reference, clearly marked as superseded concept
work — see issue linked at the end.

## 2. Method assessment

Context: this package is Phase-0 **demo/concept code**. The production
presentation path (signed HTTP, numeric-age profile, issuer/holder binding)
lives elsewhere and is regression-tested per `STATE.md`. Several placeholders
below are **fail-open**, which contradicts the project's fail-closed principle
if the code were ever treated as production.

### 2.1 `ADVANCED_SECURITY_HARDENING.ts` (modular file, tested)

- **`PanicGuard.shredEverything`** — Honest intent, overstated claims:
  `indexedDB.deleteDatabase()` calls are fire-and-forget (not awaited, no
  success check), so "structural non-existence" is asserted without
  verification. "RAM overwrite" is a log line; JS cannot prove zeroization
  (the deleted checklist itself admitted this). Browser-level residues (HTTP
  cache, history, service workers) are out of scope here. Acceptable as demo;
  must never be surfaced to users as a verified wipe.
- **`UserDerivedKeyProtection` (PBKDF2-SHA256, 600k iterations)** — Sound per
  OWASP 2023 for PBKDF2; correct choice inside WebCrypto constraints (no
  Argon2id available there; Argon2id would be preferable where runtime allows).
  Non-extractable derived key is correct. Salt is caller-supplied — contract OK
  but caller must guarantee per-user random salt.
- **`SplitKeyProtection` (2-of-3 Shamir over GF(2^8), poly 0x11B)** — The math
  is **correct**: per-byte degree-1 polynomials y = s ⊕ a₁·x, Lagrange
  reconstruction over any two shares; `gf256Inv` via a^254 is correct and
  rejects zero. Two real limitations: (a) shares carry no authenticity — a
  modified share silently corrupts reconstruction; share-level MACs are needed
  if shares are stored in hostile locations (OS keychain); (b) `gf256Mul`
  branches on secret-dependent bits (`hi`), so it is not constant-time — in JS
  this is hard to avoid and low-risk here, but it should not be claimed
  side-channel-safe.
- **`GoogleAppleBypass.isPlatformTrusted`** — hardcoded `return true`, pure
  placeholder; name promises an attestation check (WebAuthn L3) that does not
  exist.

### 2.2 `index.ts`-only classes (consolidated entry, partially tested)

- **`VerifierDirectClient`** — ES256 request JWT signing itself is fine, but
  `verifyResponse()` **always returns `true`** and
  `WalletDirectProtocol.parseRequest()` never checks the JWT signature
  (header explicitly discarded: `void encodedHeader`). This is the textbook
  fail-open anti-pattern; OK only as an undeleted demo artifact, dangerous if
  copied. The 5-minute expiry check in `validateRequest` is good.
- **`MemoryHardeningProtection`** — HKDF context-derived operation keys: sound
  pattern; note WebCrypto requires the master key importable as HKDF key.
  `createShortLivedKey` only deletes a map entry after TTL — the `CryptoKey`
  object is not provably destroyed; "expired and destroyed" overstates it.
  `encryptKeyInMemory` requires an **extractable** key, contradicting the
  non-extractability posture of the modular file.
- **`NetworkHardeningProtection`** — three fail-open/misleading placeholders:
  `fetchWithCertPinning` ignores `_expectedCertHash` entirely; the "Onion
  routing" via `https://onion.to/` routes plaintext through a third-party
  clearnet proxy (worse than direct, privacy-wise); DoH pinned to Cloudflare
  shifts metadata to a single resolver. All must stay labeled demo-only.
- **`SupplyChainHardeningProtection`** — `TRUSTED_HASHES` is an empty record;
  the dependency check logic exists but has nothing to check against.
- **`PhysicalSeizureProtection`** — all wipe methods are empty stubs;
  `checkDuressPIN` compares a duress-derived hash against the stored (real)
  hash, which is inverted logic; `hashPIN` returns the PIN in plaintext (stub).
  `setupDeadMansSwitch`'s `setInterval` is never cleared and check-ins leak a
  fixed URL every 24h.
- **`AIResistanceProtection`** — timing-variance heuristic is weak (trivially
  defeated by adding jitter); `detectLinearPath` is a `return false` placeholder;
  `checkRateLimit` sleeps the caller thread as "limiting" (blocks nothing else,
  unbounded `Math.pow(2, …)` wait).

### 2.3 API drift between the two `SplitKeyProtection`/`UserDerivedKeyProtection`

| | `ADVANCED_SECURITY_HARDENING.ts` | `index.ts` |
|---|---|---|
| `deriveKeyFromUser` | static, `(pinOrPassword, salt)` | instance, `(biometricSample, userPIN)`, fixed literal salt `'AskMI-v1-salt'` |
| `splitKey` | takes `Uint8Array` secret | takes `CryptoKey`, requires `exportKey('raw')` → extractable key |

The literal salt in the `index.ts` version is a genuine weakness (rainbow-table
friendly); the modular version's caller-supplied salt is correct. Consumers
importing from `index.ts` get the weaker variants. Consolidation (single
source, `index.ts` re-exports modules) is the correct fix, tracked in the issue.

## 3. Overall verdict

- Keep: GF(2^8) SSS core, PBKDF2-600k (modular variant), HKDF operation keys,
  ES256 request signing, 5-min request expiry.
- Label as demo/fail-open and never reuse in production: `verifyResponse`,
  `parseRequest` (no signature check), cert pinning, onion.to proxy,
  `GoogleAppleBypass`, seizure/AI-resistance stubs, `TRUSTED_HASHES`.
- Fix in a consolidation pass: `index.ts` split into module re-exports, one
  canonical `UserDerivedKeyProtection`/`SplitKeyProtection` API, remove
  hardcoded salt, add share authentication to SSS if shares are ever stored in
  hostile locations.
- Lost-but-wanted content from `01b94b1` (checklist, matrix): restore as dated
  historical doc only if still needed; do not re-enter it as code.

## 4. Follow-up

Tracked in the linked issue (consolidation + demo labeling + historical doc
decision). This record itself changes no code.
