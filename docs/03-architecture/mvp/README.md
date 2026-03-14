# docs/03-architecture/mvp/ — Architecture Strategy ADRs

Formale Architecture Decision Records für miTch-MVP-Architektur und Manifest-Prinzipien.

## Scope

Diese Sammlung enthält Architekturentscheidungen auf Strategie-Ebene — von Credential-Stack über Recovery bis Threat Model. Jede ADR dokumentiert Context, Decision, Consequences und Acceptance Evidence.

## Status-Legende

| Status | Bedeutung |
|--------|-----------|
| ACCEPTED | Entscheidung angenommen, im Repo umgesetzt |
| PROPOSED | Strategie dokumentiert, noch nicht angenommen oder umgesetzt |

## Nummernkollision

Die Nummern ADR-001 bis ADR-009 existieren auch in `docs/compliance/ADR/` — dort handelt es sich um **andere Dokumente** mit anderem Fokus (compliance- und implementierungsnah). Die Nummerierung ist unabhängig voneinander.

## Index

| ADR | Titel | Status |
|-----|-------|--------|
| [ADR-001](ADR-001_Credential_Stack_Decision.md) | Credential Stack Decision (SD-JWT VC) | ACCEPTED |
| [ADR-002](ADR-002_WebAuthn_Native_Strategy.md) | WebAuthn Native Verification Strategy | ACCEPTED |
| [ADR-003](ADR-003_Revocation_Strategy.md) | Revocation Strategy (StatusList2021) | ACCEPTED |
| [ADR-004](ADR-004_Consent_UX_Strategy.md) | Consent UX Strategy (Human-in-the-Loop First) | PROPOSED |
| [ADR-005](ADR-005_Metadata_Minimization_Strategy.md) | Metadata Minimization Strategy (Unlinkability First) | PROPOSED |
| [ADR-006](ADR-006_Recovery_Strategy.md) | Recovery Strategy (Device Loss) | PROPOSED |
| [ADR-007](ADR-007_AI_Orchestrator_Integration.md) | AI Orchestrator Integration (Scoped Delegation) | PROPOSED |
| [ADR-008](ADR-008_Batch_Credentials_Strategy.md) | Batch Credentials Strategy (Unlinkable Multi-Credential) | PROPOSED |
| [ADR-009](ADR-009_Threat_Model.md) | Threat Model (STRIDE) | PROPOSED |
| [ADR-010](ADR-010_TEE_Integration_Strategy.md) | TEE Integration Strategy | PROPOSED |
| [ADR-011](ADR-011_Claim_Level_Encryption_Strategy.md) | Claim-Level Encryption (Per-Claim SD-JWT) | PROPOSED |
| [ADR-012](ADR-012_ISO_18013-5_mdoc_Offline_Verification_Strategy.md) | ISO 18013-5 mdoc & Offline Verification | PROPOSED |

## Verwandte Sammlungen

- [`docs/03-architecture/decisions/`](../decisions/) — frühe, lightweight Decision Notes (Phase 0)
- [`docs/compliance/ADR/`](../../compliance/ADR/) — compliance- und implementierungsnahe ADRs
