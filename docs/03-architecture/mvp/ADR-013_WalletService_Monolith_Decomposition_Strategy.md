# ADR-013 — WalletService Monolith Decomposition Strategy

**Status:** PROPOSED
**Date:** 2026-05-25
**Owner:** Architecture Lead
**Decision:** Modularize and decompose the monolithic `WalletService.ts` into single-responsibility services under `@askmi/wallet-core` and dedicated monorepo packages.

## Context

The monolithic `WalletService.ts` in `src/apps/wallet-pwa/src/services/WalletService.ts` stands at over 1,300 lines of code. It aggregates key-derivation, local database seeding, deep link parsing, credential presentation token generation, storage persistence, and audit logging into a single class.

This monolith creates several architectural concerns:

1. **Security Coupling**: RAM-scoped identity key material and database encryption handles coexist in the same space as network-facing presentation builders and telemetry reporters.
2. **Testing Overhead**: Tests for presentation building require stubbing IndexedDB, WebAuthn, and audit logging, inflating runtime execution limits.
3. **Circular Dependencies**: Downstream applications must import `WalletService` as a whole, preventing modular integration or alternate wallet implementations.

## Decision

We will progressively decompose the monolithic `WalletService` into isolated, single-responsibility, highly decoupled sub-services. This extraction will be managed across incremental sprints to ensure continuous build greenness.

### 1. Separation Plan

The monolith will be broken down into:

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

We will extract the following lightweight, highly independent sub-services first:

1. **`SeedService`**: Manages GovID, Employment, EHDS, and ISO 18013-5 mdoc demo credential seeding into the local storage layer.
2. **`ConsentReceiptService` / `PrivacyAuditService`**: Handles caching, paginating, and exporting signed consent receipts.
3. **`PresentationBuilder`**: Assembles SD-JWT VP, KB-JWT, and ISO 18013-5 mdoc presentations for verifiers, removing transport logic.
4. **`CredentialRepository`**: Governs indexing, loading, saving, and deletion operations for credential metadata and base64 documents.

### 2. Guardrails & Invariants

To maintain strict architectural boundaries, we will enforce:

- **Constitutional Key Separation**: The database storage engine and presentation builders must never derive or hold master credential credentials. They receive only opaque `CryptoKey` handles or specific signer closures injected by the orchestrator plane.
- **Fail-Closed Defaulting**: Any failed parameter injection or verification checks during state extraction must immediately result in a hard `DENY` or compilation error rather than defaulting to soft-allowances.
- **Linting Restrictions**: Boundary compliance is statically monitored via ESLint `no-restricted-imports`.

## Consequences

- ✅ **Clear Security Enclaves**: Credentials and keys are locked inside specific logical submodules, mitigating memory leakage vectors.
- ✅ **Mechanical Testing**: Tests are isolated to separate packages (e.g. testing `PresentationBuilder` without setting up full IndexedDB contexts).
- ✅ **Reusability**: Sub-services can be consumed by other apps or packages in the typescript workspace.

## Acceptance Evidence

- [ ] Static analysis checks exit with status 0 (`pnpm lint`).
- [ ] All typescript builds across packages and apps compile cleanly (`pnpm build`).
- [ ] The entire vitest workspace test suite remains fully green (`pnpm test`).
- [ ] E2E browser scenarios execute flawlessly without degradation.

## Change Log

- 2026-05-25: Initial strategy proposed (PROPOSED)
