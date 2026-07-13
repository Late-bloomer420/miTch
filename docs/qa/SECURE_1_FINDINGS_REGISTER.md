# SECURE-1 Findings Register

**Started:** 2026-07-13
**Baseline:** `pnpm test` 46/46 green, lint 0/0, guard green (Task 0).

Each finding:

| ID | File:line | Class | Description (1 line) | Severity | Confidence | Disposition |
|----|-----------|-------|----------------------|----------|------------|-------------|

- **Class:** `false-success` | `fail-closed-violation` | `swallowed-error` | `contract-mismatch`
- **Severity:** `high` (auth/crypto/disclosure bypass) | `med` (audit/integrity) | `low` (defense-in-depth)
- **Confidence:** `high` (PoC-able) | `med` (needs runtime confirmation) | `low` (suspicious, unverified)
- **Disposition:** `fix` (Phase 3 task) | `documented-residual` (can't fix in scope, note why) | `not-a-bug` (rationale)

## Findings

| ID | File:line | Class | Description (1 line) | Severity | Confidence | Disposition |
|----|-----------|-------|----------------------|----------|------------|-------------|
| F-01 | `src/apps/wallet-pwa/src/services/WalletService.ts:1640` | `contract-mismatch` | `getIdentityPublicKey()` casts `AuditLog` to `{ publicKey?: CryptoKey }` but the field is `auditPublicKey`; always returns `null`. | med | high | fixed (commit 14ab393) |
| F-02 | `src/apps/wallet-pwa/src/services/WalletService.ts:618-624` | `swallowed-error` | `savePolicy()` fires `persistPolicy()` with `void …catch(console.error)` (bug at line 621) — policy write failures are logged but the caller receives no signal and the in-memory state diverges silently from persistent storage. | med | high | fixed (commit 6fb7e08) |
| F-03 | `src/packages/shared-crypto/src/webauthn.ts:602-604` | `false-success` | `WebAuthnService.verifyPresence()` returns `true` for any non-empty attestation string without doing any cryptographic verification. **Zero call sites** — the real WebAuthn boundary is the separate `webauthn-verifier` package (per ADR-009); this is a dead, self-documented "Legacy-Kompatibilität" stub with a misleading name. Latent risk (a future caller would gain a false presence proof), not a live bypass. Fix = tombstone / make it throw fail-closed. | med | med | fixed (commit dc0bdca) |
| F-04 | `src/packages/policy-engine/src/geo-scope.ts:17,22` | `fail-closed-violation` | `isAllowedByGeoScope()` fails OPEN twice: line 17 returns `true` when the country cannot be determined ("fail-open for geo only"), and line 22 returns `true` as the default for an unrecognized `geoScope` value. Both violate the AskMI invariant that ambiguity → DENY. Fix closes both. | med | high | fix |
| F-05 | `src/packages/audit-log/src/storage/l2-anchor-client.ts:311-328` | `false-success` | `verifyAnchor()` returns `true` unconditionally for all non-mock, non-pending receipts whose contract address is the zero-address sentinel (i.e. every production network before deployment); callers believe the anchor is verified on-chain when the check was never performed. | med | high | documented-residual |
| F-06 | `src/packages/audit-log/src/storage/l2-anchor-client.ts:119-128` | `false-success` | `submitToL2()` always falls through to `mockAnchor()` even in production mode, returning a synthetic confirmed receipt without sending any real transaction; the caller `processBatch()` and `anchorRoot()` treat it as a successful blockchain write. | med | high | documented-residual |
| F-07 | `src/apps/wallet-pwa/src/services/WalletService.ts:1950-1987` | `false-success` | `handleAction()` returns `{ success: true }` for `LOAD_CREDENTIAL`, `CONTACT_VERIFIER`, `LEARN_MORE`, and `REPORT_ISSUE` without performing any actual effect; callers that check the flag will believe the action completed. | low | high | not-a-bug |
| F-08 | `src/apps/wallet-pwa/src/services/WalletService.ts:770-773` | `contract-mismatch` | `corruptEntry()` accessed via `as unknown as { corruptEntry: … }` cast on SecureStorage — only used in stress-test path, not a security path. | low | high | not-a-bug |
| F-09 | `src/apps/wallet-pwa/src/services/WalletService.ts:899` | `contract-mismatch` | `metadata as unknown as Record<string, unknown>` in `logDisclosureDecision` — type widening for audit append; the type is structurally compatible and no property reads silently undefined. | low | high | not-a-bug |
| F-10 | `src/apps/wallet-pwa/src/services/WalletService.ts:1390` | `contract-mismatch` | `(proofKeys as unknown as { privateKey: CryptoKey \| null }).privateKey = null` — intentional null-write for crypto-shredding; the cast is the only way to null a non-extractable WebCrypto key reference. | low | high | not-a-bug |
| F-11 | `src/apps/wallet-pwa/src/services/WalletService.ts:1598` | `contract-mismatch` | `metadata as unknown as Record<string, unknown>` in `recordIdentityFirewallEvents` — same pattern as F-09; structurally safe. | low | high | not-a-bug |
| F-12 | `src/apps/wallet-pwa/src/services/WalletService.ts:299` | `contract-mismatch` | `{ … } as unknown as Storage` — in-memory shim for localStorage; correct, all Storage interface methods are implemented. | low | high | not-a-bug |
| F-13 | `src/apps/wallet-pwa/src/services/WalletService.ts:2109-2114` | `contract-mismatch` | `this.auditLog as unknown as { auditPrivateKey?: CryptoKey; auditPublicKey?: CryptoKey }` in `signData()` — this cast correctly names `auditPrivateKey` (the real field name), so the key look-up succeeds. Note: F-01 is the _paired_ read of `publicKey` (wrong name) in `getIdentityPublicKey()`. | low | high | not-a-bug |
| F-14 | `src/packages/oid4vp-verifier/src/response-verifier.ts:47-85` | `false-success` | `verifyAuthorizationResponse()` parses the VP token and checks structural submission constraints but does NOT verify any cryptographic signature on credentials; `valid: true` means structural compliance only, not cryptographic authenticity. | high | high | documented-residual |
| F-15 | `src/packages/policy-engine/src/engine.ts:378-383` | `fail-closed-violation` | Break-glass path (`allowBreakGlass`) issues an ALLOW without presence/consent when `userAvailable === false`; this is a documented EHDS Art. 8(5) exception, not a bug, but it is an intentional fail-open branch with audit trail. | med | high | documented-residual |
| F-16 | `src/packages/shared-crypto/src/webauthn.ts:77-79` | `swallowed-error` | `savePasskeyMeta()` swallows all IndexedDB errors in an empty catch with a comment "will be ignored"; a failed save means the passkey metadata is lost on the next load, causing `isIdentityRegistered()` to return false and potentially downgrading security level silently. | med | med | fix |
| F-17 | `src/packages/shared-crypto/src/webauthn.ts:94-97` | `swallowed-error` | `loadPasskeyMeta()` catches all errors and returns `null` silently; when the DB is corrupt `isIdentityRegistered()` returns false, which (in environments where WebAuthn is available) would cause `signWithIdentityKey()` to throw — correct behaviour — but without any diagnostic. | low | med | not-a-bug |
| F-18 | `src/packages/shared-crypto/src/webauthn.ts:110-113` | `swallowed-error` | `saveIdentityKeyMeta()` swallows all IndexedDB errors in an empty catch; same class of issue as F-16 — if saving the identity key registration fails, subsequent calls to `isIdentityRegistered()` return false, which will cause `signWithIdentityKey()` to throw in WebAuthn-available environments. | med | med | fix |
| F-19 | `src/packages/audit-log/src/index.ts:130-136` | `swallowed-error` | `append()` catches IndexedDB persistence failures and continues — the comment says "in-memory log is still valid"; acceptable by design (best-effort persistence), but the failure is only `console.error`'d with no structured error surface. | low | high | documented-residual |
| F-20 | `src/packages/policy-engine/src/engine.ts:800-803` | `swallowed-error` | Pairwise DID generation failure inside `result()` is caught and logged with `console.error`, then silently continues without a pairwise DID; this is privacy-weakening (unlinkability goal not met) but does not affect the ALLOW/DENY verdict. | low | high | documented-residual |
| F-21 | `src/apps/wallet-pwa/src/services/WalletService.ts:433-434` | `swallowed-error` | Audit-key storage load error in `initialize()` is caught in an empty catch (the error variable `_` is unused); first-run is indistinguishable from a storage failure — no diagnostic path. | low | med | not-a-bug |
| F-22 | `src/packages/audit-log/src/storage/l2-anchor-client.ts:238-243` | `swallowed-error` | `startBatchTimer()` calls `processBatch().catch(console.error)` via `setInterval`; batch failures are logged but never retried beyond the in-function retry counter — fire-and-forget on an integrity path. | low | med | documented-residual |

## Rationale Notes

**F-05 (documented-residual):** `verifyAnchor()` returns `true` for undeployed contracts by design — the JSDoc explicitly says "treat as unverifiable but non-blocking". Fixing it requires deploying the anchor contract (out of current scope). Tracked as F-12 in the L2-anchoring roadmap.

**F-06 (documented-residual):** `submitToL2()` is a documented stub — the JSDoc header lists it explicitly as "mocked: does NOT send a real on-chain transaction". Fixing requires adding an ethers.js/viem integration (out of current scope).

**F-07 (not-a-bug):** `handleAction()` is a UI routing helper that simulates UI side-effects in the PoC. The `success: true` signals that the _routing_ action (logging, navigation intent) was dispatched, not that an external side-effect completed. No security invariant is affected.

**F-08 (not-a-bug):** `corruptEntry()` cast is only called from `corruptCredential()`, which is a stress-test method with no production call site. No security path is affected.

**F-09 / F-11 (not-a-bug):** `DisclosureDecisionMetadata` and `IdentityFirewallMetadata` are structurally compatible with `Record<string, unknown>` — no property reads on undefined occur from the cast.

**F-10 (not-a-bug):** This cast is the idiomatic way to null-out a WebCrypto key reference for crypto-shredding, as `CryptoKeyPair.privateKey` is typed as `CryptoKey` (non-nullable). The intent is correct.

**F-12 (not-a-bug):** The in-memory shim fully implements the `Storage` interface. All five required methods are present and correct.

**F-13 (not-a-bug):** `signData()` correctly reads `auditPrivateKey` (the real field), so this cast is safe. F-01 is the separate, distinct bug in `getIdentityPublicKey()` that reads `publicKey` (wrong name).

**F-14 (documented-residual):** Cryptographic signature verification of SD-JWT or VP credentials is intentionally out of scope for this verifier package in the PoC phase. The JSDoc says "real impl would decode SD-JWT and verify field paths". A full crypto verification layer requires @sd-jwt/core or jose integration that is not yet wired.

**F-15 (documented-residual):** Break-glass is a required EHDS Art. 8(5) feature — emergency access without consent is the specification. The audit trail (`BREAK_GLASS_ACTIVATED`) is the designed safeguard. This cannot be "fixed" without removing the feature.

**F-17 (not-a-bug):** `loadPasskeyMeta()` returning `null` on DB error is a safe fallback — `signWithIdentityKey()` will throw (fail-closed) when WebAuthn is available but no meta exists. The fail-closed path is correct.

**F-19 (documented-residual):** Best-effort persistence is the design intent for the in-memory audit log. Production deployments should use `useProductionStorage: true` with the IndexedDB store. The current `console.error` is adequate for the PoC.

**F-20 (documented-residual):** Pairwise DID failure is intentionally non-blocking ("continuing without it"). Fixing requires ensuring pairwise DID generation never throws (requires a separate task in the pairwise-DID subsystem, not in the policy-engine scope).

**F-21 (not-a-bug):** The empty catch on `load(AUDIT_KEY_STORAGE_ID)` at line 433 handles the first-run / storage-empty case. The subsequent path always generates fresh audit keys, so no security invariant is broken by the swallowed error.

**F-22 (documented-residual):** The batch timer is a non-critical integrity layer (L2 anchoring is not yet wired to a real chain). When the real L2 integration lands, the retry/alerting path should be hardened.
