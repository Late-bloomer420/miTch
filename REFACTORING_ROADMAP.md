# miTch Refactoring Roadmap

Tracks planned architectural improvements across the codebase. Items here are _planned_ work, not blocking the current PoC phase. Each item links to a sprint finding or ADR for context.

---

## Phase 6 Gate — WalletService Decomposition

**File:** `src/apps/wallet-pwa/src/services/WalletService.ts` (1395 LOC)
**Finding:** F-16 (audit 2026-03)
**Status:** Planned — Blueprint Resolved & Approved

We will decompose the monolithic `WalletService` into highly decoupled, single-responsibility packages.

### Target Dependency Graph

```mermaid
graph TD
    shared-crypto  shared-types
         │               │
         ├── wallet-auth (keys, PBKDF2, signer factories)
         │       │ injects CryptoKey handles / CapsuleSigner
         │       ▼
         ├── wallet-storage   (SecureStorage, IndexedDB)
         ├── audit-log        (consumer, no key ownership)
         ├── policy-engine    (consumer, no key ownership)
         └── wallet-sync      (CRDT + transport adapters, no crypto)
                      ▲
                 wallet-core  (orchestrator — bootstraps all of the above)
```

### Extracted Core Packages & Orchestration Plane

| Package / Module        | Responsibility                                                                                     | Invariants & Cryptographic Boundaries                                                                                                                                                                                                                                                                      |
| ----------------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@mitch/wallet-auth`    | Master-key derivation, PIN stretching (PBKDF2), signer callbacks, Identity & Audit Key lifecycles. | **Strict Key Encapsulation**: Owns auth credentials. Delivers only opaque `CryptoKey` handles to storage and `CapsuleSigner` closures to policy engine. Captures identity keys without leakage to serializable states (avoiding binding to transferable objects).                                          |
| `@mitch/wallet-storage` | Credential indexing, metadata database, encrypted load/save.                                       | **Opaque Cryptography**: Constitutionally forbidden from knowing key origins. Accepts only injected `CryptoKey` master handles from `wallet-auth`.                                                                                                                                                         |
| `@mitch/audit-log`      | Append-only tamper-evident verification trails.                                                    | **Consumer Only**: Holds no key ownership. Receives `kid` and Audit Key handles externally. The hardcoded `'audit-key-2026-v1'` default at `audit-log/src/index.ts:27` is a smell that **must** be removed, making `kid` a required parameter in `setAuditKeys` to force boundary compliance from day one. |
| `@mitch/policy-engine`  | Evaluation of verifier disclosure requirements.                                                    | **Consumer Only**: Operates strictly on injected `CapsuleSigner` callbacks. Holds no local credentials or key material.                                                                                                                                                                                    |
| `@mitch/wallet-sync`    | Budget sync, multi-device replication.                                                             | **No Cryptography**: Holds transport adapters (iCloud/Drive stubs) and state-merge counters (CRDTs). Meets storage plane only at the orchestrator level.                                                                                                                                                   |
| `@mitch/wallet-core`    | Monolithic `WalletService` successor.                                                              | **Thin Orchestrator**: Bootstraps services, coordinates authentication events, injects keys/callbacks, and triggers replication pipelines.                                                                                                                                                                 |

### CI Architectural Constraints & ESLint Boundary Rules

To prevent boundary erosion, the following constraints must be enforced in CI (`eslint-plugin-import` or custom dependency validations):

1. **No Shared Plane Imports**: `@mitch/wallet-sync` is prohibited from importing `@mitch/secure-storage`.
2. **Pure Consumers**: Neither `@mitch/audit-log` nor `@mitch/policy-engine` may import `@mitch/wallet-auth` directly; they are strictly downstream receivers of injected dependencies.
3. **API Integrity**: All `WalletService` unit tests (`WalletService.test.ts`) must compile and remain green after each progressive decomposition step.

---

## EphemeralKey Unification

**Files:**

- `src/packages/shared-crypto/src/ephemeral.ts` (WebCrypto, browser)
- `src/packages/shared-crypto/src/ephemeral-key.ts` (Uint8Array, minimal)
- `src/packages/secure-memory/src/ephemeral_key.ts` (Node, hash-proof + timeout)

**Finding:** F-04 (audit 2026-03)
**Status:** Complete (interface + all implementations conform)

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

**Phase 2 (done):**

- `secure-memory/ephemeral_key.ts` → `implements IEphemeralKey` + public `shred()` (delegates to internal shred with `success=false`). Existing `use()` auto-shred pattern preserved.
- `WalletService.ts` already calls `.shred()` on concrete `EphemeralKey` — no adapter needed.

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

_Last updated: 2026-03-14_
