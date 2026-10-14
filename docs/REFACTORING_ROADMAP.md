# AskMI Refactoring Roadmap

> **Role:** Deferred architecture work from PoC to production hardening.
> This is the canonical roadmap referenced by `docs/DOCS_CANON.md`.

**Status:** Reference closeout for F-16/F-18
**Last updated:** 2026-06-25

This file tracks larger architecture work that should not be mixed into small
security, UX, or pilot-readiness fixes. Items here are planned or partially
delivered work, not blockers unless `docs/BACKLOG.md` promotes them into an
active sprint.

## Authority

- Operational state: [`../STATE.md`](../STATE.md)
- Task tracking: [`BACKLOG.md`](BACKLOG.md)
- Architecture authority map: [`DOCS_CANON.md`](DOCS_CANON.md)
- WalletService decomposition ADR: [`03-architecture/mvp/ADR-013_WalletService_Monolith_Decomposition_Strategy.md`](03-architecture/mvp/ADR-013_WalletService_Monolith_Decomposition_Strategy.md)
- Original audit finding source: [`AUDIT_2026_03.md`](AUDIT_2026_03.md)

## Closed Reference Gap

| Finding | Status | Roadmap placement |
|---|---|---|
| F-16 WalletService god object | Documented | Phase 6 wallet facade and service extraction |
| F-18 missing refactoring roadmap | Closed | This canonical file, plus root compatibility pointer |

F-16 is not a one-line fix. Treat it as an architecture extraction sequence with
API stability gates. Do not refactor `WalletService` opportunistically while
working on unrelated policy, UX, or demo-flow tasks.

## Phase 6 Gate: WalletService Decomposition

**Current concern:** `src/apps/wallet-pwa/src/services/WalletService.ts`

`WalletService` has historically carried credential storage, policy mediation,
presentation generation, consent/audit bookkeeping, and recovery helpers in one
orchestration surface. The target shape is a facade that delegates to narrower
services while preserving the public wallet API.

### Target Services

| Extracted service | Responsibility |
|---|---|
| `CredentialService` / repository | Credential storage, retrieval, metadata index, selective load |
| `PolicyService` / evaluator adapter | Request evaluation, policy state, risk score access |
| `PresentationService` | VP generation, encryption target handling, proof output |
| `AuditService` | Audit event writes, chain verification, export/sync helpers |
| `RecoveryService` | Recovery fragment split/recover workflows |
| `KeyService` | Master-key derivation, wrap/unwrap, key lifecycle boundaries |

### Migration Rules

- Extract one seam at a time.
- Keep `WalletService` public method signatures stable unless a dedicated
  migration task says otherwise.
- Add tests at the seam before moving behavior.
- Do not change disclosure, policy verdict, or audit semantics as a side effect
  of moving code.
- Prefer adapter interfaces already present in the repo over new abstractions.

### Acceptance Gates

| Gate | Measurement |
|---|---|
| API stability | Existing wallet-pwa tests pass with no caller rewrites |
| Behavior stability | Scenario disclosure outputs and audit event sequences unchanged |
| Extraction proof | Each extracted service has focused tests |
| Facade reduction | `WalletService` becomes mostly orchestration, not domain logic |

## SecureStorage Boundary

**Current concern:** `src/packages/secure-storage/src/index.ts`

The production target is a clear split between persistence and envelope crypto.
This supports browser, Node test, and future native/mobile adapters without
rewriting data minimization logic.

| Planned seam | Responsibility |
|---|---|
| `IStorageAdapter` | Store/list/delete ciphertext blobs and metadata tags |
| `IEnvelopeCrypto` | Seal/unseal, key wrapping, key lifecycle state |
| `ICredentialRepository` | Domain-facing credential operations |

Related deferred findings:

- F-07 claim-level encryption: current selective load is post-decryption
  minimization; true claim-level encryption requires schema work.
- F-14 key rotation: add an atomic decrypt/re-encrypt path once storage seams are
  stable.
- F-08 `getRawDocument()`: small hardening item, separate from the larger
  adapter extraction.

## PolicyEngine Extension Point

**Current concern:** credential selection and verifier matching should stay
simple until a product requirement forces a strategy boundary.

Candidate future seam:

```ts
interface ICredentialSelectionStrategy {
  select(
    candidates: StoredCredentialMetadata[],
    requirement: Requirement,
    context: EvaluationContext
  ): StoredCredentialMetadata | null;
}
```

Rules:

- Current first-compatible credential behavior is acceptable for the pilot.
- Add a strategy only when multi-issuer or privacy-rotation requirements are
  explicit.
- Do not introduce reputation scoring into verifier-facing enforcement without a
  separate design decision; AskMI remains deny-biased and scope-bound.

## Deferred Crypto / Platform Items

| Item | Status |
|---|---|
| F-04 EphemeralKey unification | Mostly delivered via shared interface and conforming implementations |
| F-05 TEE migration | Deferred; WebAuthn identity binding is delivered, session-key TEE wrapping remains platform-dependent |
| F-07 claim-level encryption | Deferred until credential schema is stable |
| F-14 key rotation | Deferred until storage adapter boundary is stable |
| F-17 crypto capability check | Small hardening item, safe as its own task |

## Scope Guard

This roadmap is a parking lot for deliberate architecture work. It must not be
used as permission for drive-by refactors. If a task is about security behavior,
policy verdicts, disclosure semantics, UX, or demo runtime, keep that task
small and leave Phase 6 refactoring for a separate branch.
