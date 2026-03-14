# Architecture Decision Records

Decisions made on 2026-02-20 for miTch Phase 0+ credential and proof infrastructure.

| # | Decision | Status | Key Choice |
|---|---|---|---|
| [001](DECISION_001_Credential_Proof_Stack.md) | Credential Format & Proof System | Accepted | SD-JWT now, BBS+ Phase 1 |
| [002](DECISION_002_Issuer_Integration.md) | Issuer Integration Boundary | Accepted | Adapter layer, on-device derivation |
| [003](DECISION_003_Revocation_Status.md) | Revocation & Status Checking | Accepted | Pre-issued + StatusList2021 bitstring |
| [004](DECISION_004_Consent_UX.md) | User Consent UX | Accepted | Three-tier, no dark patterns, receipts |
| [005](DECISION_005_Metadata_Minimization.md) | Metadata Minimization | Accepted | Padding, jitter, stripped fields (~80 LOC) |
| [006](DECISION_006_Recovery.md) | Recovery | Accepted | Re-issuance Phase 0, cloud backup Phase 1, no social recovery |
| [007](DECISION_007_AI_Orchestrator.md) | AI Orchestrator Integration | Accepted | Scoped delegation, 4-layer enforcement |

## Phase 0 Summary

**Ship first:** SD-JWT credentials, issuer adapter + mock, StatusList2021 bitstring, three-tier consent UI, consent receipts, metadata minimization (~80 lines), credential re-issuance recovery.

**Design now, build later:** AI delegation token spec (data model), BBS+ credential format slot.

**Not Phase 0:** Cloud backup, social recovery, dark pattern detection, AI SDK, relay proxy, OHTTP.

## Verwandte Sammlungen

Diese DECISION-Dateien sind frühe, lightweight Decision Notes aus Phase 0. Für weiterführende ADRs siehe:

- [`docs/03-architecture/mvp/`](../mvp/) — formale Architektur-Strategie-ADRs (ADR-001–012)
- [`docs/compliance/ADR/`](../../compliance/ADR/) — compliance- und implementierungsnahe ADRs (ADR-001–009)
