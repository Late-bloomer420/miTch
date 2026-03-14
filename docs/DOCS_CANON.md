# Docs Canon

This file defines the authoritative document per topic area and serves as navigation entry point.

---

## Document Hierarchy

| Dokument | Zweck | Rolle |
|----------|-------|-------|
| `STATE.md` | Operativer Health-Snapshot (Tests, Lint, Audit, Demo) | Was läuft? |
| `docs/BACKLOG.md` | Autoritatives Task-Tracking (erledigt / offen / geplant) | Was ist erledigt, was fehlt? |
| `docs/specs/SPECS_STATUS_INDEX.md` | Statusübersicht aller 112 Specs | Spec-Navigation |
| `docs/DOCS_CANON.md` | Dokumenten-Autorität und Navigation (diese Datei) | Einstiegspunkt |
| `docs/REFACTORING_ROADMAP.md` | Deferred Architekturarbeit (PoC → Production) | Größere Umbauten |

## Authoritative Sources

- **P0 closure evidence (security + fail-closed test proof):** `docs/ops/EVIDENCE_PACK_P0.md`
- **Pilot execution record:** `docs/pilot/PILOT_DRY_RUN_01.md`
- **Pilot findings source:** `docs/pilot/PILOT_DRY_RUN_01_FINDINGS.md`
- **Pilot findings tracking/backlog:** `docs/pilot/FINDINGS_BACKLOG.md`
- **Capability handshake + downgrade handling:** `docs/protocol/CAP_NEGOTIATION_V1.md`
- **Metadata budget + anti-correlation controls:** `docs/ops/METADATA_BUDGET_V1.md`
- **Failure-mode operations playbooks:** `docs/ops/RUNBOOKS_V1.md`

## Navigation

- **Spec status index (all 112 specs classified):** `docs/specs/SPECS_STATUS_INDEX.md`
- **Master Backlog (offene Arbeit + ADR-Sektion):** `docs/BACKLOG.md`
- **Session History (abgeschlossene Sessions):** `docs/SESSION_HISTORY.md`

## Architecture Decision Records (3 Sammlungen)

| Ort | Scope | Index |
|-----|-------|-------|
| `docs/03-architecture/decisions/` | Frühe Phase-0 Decision Notes (DECISION_001–007) | [README](03-architecture/decisions/README.md) |
| `docs/03-architecture/mvp/` | Formale Architektur-Strategie-ADRs (ADR-001–012) | [README](03-architecture/mvp/README.md) |
| `docs/compliance/ADR/` | Compliance- und implementierungsnahe ADRs (ADR-001–009) | [README](compliance/ADR/README.md) |

**Hinweis:** ADR-001–009 existieren in `mvp/` und `compliance/ADR/` mit unterschiedlichen Themen. Die READMEs in den jeweiligen Ordnern erklären die Abgrenzung.

## Conflict Resolution Rules

- If README conflicts with the Evidence Pack, the Evidence Pack is authoritative.
- If STATE.md conflicts with a protocol spec, the spec is authoritative.
- If BACKLOG.md conflicts with STATE.md regarding completion status, BACKLOG.md is authoritative for task tracking, STATE.md for operational status.
