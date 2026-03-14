# ADR-008 — Batch Credentials Strategy (Unlinkable Multi-Credential Issuance)

**Status:** PROPOSED  
**Date:** 2026-03-14  
**Owner:** Architecture Lead  
**Decision:** Batch-Issuance von bis zu 8 Credentials in einer Session mit per-Credential Shredding und Nullifier-Rotation

## Context
Nach ADR-007 (AI Orchestrator) fehlt eine formale Strategie für Batch-Credentials.  
Im Backlog (Task B-08) und in der REFACTORING_ROADMAP wird „batch_credential“ nur als Stub erwähnt.  
EUDI-CIR und DSGVO Art. 25 verlangen, dass auch Massenfreigaben (z. B. Führerschein + Alter + Student-Status gleichzeitig) keine Linkability oder Metadata-Leaks erzeugen dürfen.

## Decision
**Batch-Issuance wird strukturell erzwungen durch:**
- **Single Session mit Multi-SD-JWT**: Ein WebAuthn-Confirm → bis zu 8 unabhängige SD-JWTs mit je eigenem pairwise-ephemeren Key
- **Per-Credential Nullifier + Shredding**: Jeder Credential erhält eigenen HKDF-derived Key; nach Auslieferung sofort $0x00-Überschreiben des jeweiligen Keys
- **Policy-Engine Batch-Check**: `allowBatch(n)` prüft lokal Datensparsamkeit + Unlinkability-Score; bei > 0 → Fail-Closed
- **Blind Provider Enforcement**: miTch-Proxy sieht nur den finalen Batch-Proof, niemals die einzelnen Credentials oder deren Zusammenhang

**Technische Umsetzung:**
- `@mitch/wallet-core` erweitert um `issueBatchCredentials(claims[])` 
- `@mitch/shared-crypto` rotiert automatisch Nullifier pro Credential
- Fail-Closed: Bei jeder Batch-Session wird die Session-ID sofort nach Abschluss shredded

## Alternatives Considered
- Separate Sessions pro Credential → schlechte UX + mehr Human-in-the-Loop-Interaktionen  
- Ein großer zusammenhängender JWT → verstößt massiv gegen Unlinkability + Blind Provider

## Consequences
✅ **Human-in-the-Loop** bleibt erhalten (ein WebAuthn-Confirm für den gesamten Batch)  
✅ **Crypto-Shredding** wird auf Batch-Ebene erweitert (pro-Credential $0x00)  
✅ **Smart Policy Engine** entscheidet lokal über Batch-Größe und Zulässigkeit  
✅ **Blind Provider** bleibt blind (kein Zusammenhang zwischen Credentials sichtbar)

## Acceptance Evidence
- Test-Suite: 8-Credential-Batch + Linkability-Attack-Vektoren
- Demo in `verifier-demo` (Batch vs. Single)
- EVIDENCE_PACK-Erweiterung mit Performance-Messung

## Implementation Notes
- Task B-08 in BACKLOG Phase 3 (Batch Credential Support)
- Verknüpfung mit ADR-001 (Credential Stack), ADR-005 (Metadata) und ADR-006 (Recovery)

## References
- miTch-Manifest (Crypto-Shredding + Blind Provider)
- EUDI-CIR Art. 9 (Unlinkability) + Art. 12 (Batch Support)
- SD-JWT RFC (Multi-Claim Batching)
- BSI TR-02102 (Schlüsselrotation)

## Change Log
+ 2026-03-14: Initial Proposal (PROPOSED)