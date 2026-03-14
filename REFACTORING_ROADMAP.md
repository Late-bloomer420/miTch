# miTch Refactoring Roadmap

Tracks planned architectural improvements across the codebase. Items here are *planned* work, not blocking the current PoC phase. Each item links to a sprint finding or ADR for context.

---

## Phase 6 Gate — WalletService Decomposition

**File:** `src/apps/wallet-pwa/src/services/WalletService.ts` (1081 LOC)
**Finding:** F-16 (audit 2026-03)
**Status:** Planned — not blocking PoC

WalletService is a God Object accumulating every wallet concern. Planned split:

| Extracted Service | Responsibility |
|---|---|
| `KeyService` | Master-key derivation, HKDF, AES-GCM wrap/unwrap |
| `CredentialService` | Credential storage, retrieval, metadata index |
| `AuditService` | Audit-log writing, chain verification |
| `ConsentService` | Consent prompts, consent-log persistence |
| `RecoveryService` | SSS key splitting, fragment distribution |

**Migration strategy:** Extract one service at a time, keeping `WalletService` as a thin coordinator delegating to extracted services. No breaking API changes to callers.

**Gate criterion:** All `WalletService` tests remain green after each extraction step.

---

## EphemeralKey Unification

**Files:**
- `src/packages/shared-crypto/src/ephemeral.ts` (WebCrypto, browser)
- `src/packages/shared-crypto/src/ephemeral-key.ts` (Uint8Array, minimal)
- `src/packages/secure-memory/src/ephemeral_key.ts` (Node, hash-proof + timeout)

**Finding:** F-04 (audit 2026-03)
**Status:** Phase 1 complete (interface + shared-crypto conformance)

Common `IEphemeralKey` interface defined in `shared-crypto/src/interfaces/IEphemeralKey.ts`:
```typescript
interface IEphemeralKey {
    isShredded(): boolean;
    shred(): void;
}
```

**Phase 1 (done):**
- `ephemeral-key.ts` (Uint8Array variant) → `implements IEphemeralKey` (already conformed)
- `ephemeral.ts` (CryptoKey variant) → `implements IEphemeralKey` + added `isShredded()` alias
- Interface exported from `@mitch/shared-crypto`

**Phase 2 (planned):**
- `secure-memory/ephemeral_key.ts` — different lifecycle model (`use()` + auto-shred, private `shred()`). Conformance requires design decision on whether to expose public `shred()` alongside `use()`.
- Adapt `WalletService.ts` callers to use `IEphemeralKey` where applicable.

---

## Claim-Level Encryption

**File:** `src/packages/secure-storage/src/index.ts` (`loadSelectiveClaims`)
**Finding:** F-07 (audit 2026-03)
**Status:** Planned — post-PoC

Current implementation decrypts full blob, then filters. True data minimization requires each claim stored as a separate AES-GCM ciphertext blob. Blocked on credential schema stabilization.

---

## Key Rotation

**File:** `src/packages/secure-storage/src/index.ts`
**Finding:** F-14 (audit 2026-03)
**Status:** Planned

Add `rotateKey(oldKey: CryptoKey, newKey: CryptoKey): Promise<void>` — iterates all stored entries, decrypts with `oldKey`, re-encrypts with `newKey`, writes back atomically.

---

## Verifier Binding (Phase 2 — DNS-DID)

**File:** `src/packages/policy-engine/src/engine.ts` (around line 465)
**Finding:** F-09 (audit 2026-03)
**Status:** Phase 1 in sprint; Phase 2 planned

- **Phase 1 (sprint):** Origin header vs. VerifierID prefix check
- **Phase 2 (planned):** DNS `TXT` record + `.well-known/did-configuration` binding per DIF spec

---

## TEE Migration (Key Non-Extractability)

**File:** `src/packages/shared-crypto/src/ephemeral.ts:44`
**Finding:** F-05 (audit 2026-03)
**Status:** T-31 in backlog

`extractable: true` is required for the current key-wrapping approach. Long-term: migrate to non-extractable keys wrapped inside a TEE (Trusted Execution Environment), eliminating the need to export raw key material.

---

*Last updated: 2026-03-14*
