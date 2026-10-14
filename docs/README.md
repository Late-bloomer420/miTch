# miTch Documentation Structure

## Einstiegspunkte

| Dokument | Zweck |
|----------|-------|
| [`DOCS_CANON.md`](DOCS_CANON.md) | Dokumenten-Autorität, Navigation, Conflict Resolution |
| [`BACKLOG.md`](BACKLOG.md) | Offene Arbeit, erledigte Meilensteine, ADR-Übersicht |
| [`specs/SPECS_STATUS_INDEX.md`](specs/SPECS_STATUS_INDEX.md) | Statusübersicht aller 112 Specs |
| [`../STATE.md`](../STATE.md) | Aktueller Betriebszustand |
| [`REFACTORING_ROADMAP.md`](REFACTORING_ROADMAP.md) | Deferred Architekturarbeit (PoC → Production) |

## Canonical Locations

| Folder | Content | Notes |
|--------|---------|-------|
| `specs/` | **All numbered spec docs (00–112)** | Single source of truth; Status in `SPECS_STATUS_INDEX.md` |
| `00-welt/` | Project vision & manifesto files | MASTER_BRIEF, digital_rights_charter, mitch_policy_manifest |
| `01-grundversorgung/` | Phase-specific overrides (if any differ from specs) | Mostly emptied after dedup |
| `03-architecture/decisions/` | Frühe Phase-0 Decision Notes | DECISION_001–007; [README](03-architecture/decisions/README.md) |
| `03-architecture/mvp/` | Formale Architektur-Strategie-ADRs | ADR-001–012; [README](03-architecture/mvp/README.md) |
| `compliance/ADR/` | Compliance- und implementierungsnahe ADRs | ADR-001–009; [README](compliance/ADR/README.md) |
| `04-legal/` | Legal documents | Unique content |
| `05-business/` | Business documents | Unique content |
| `context/` | Context documents | Unique content |
| `ops/` | Operational docs | EVIDENCE_PACK_P0, METADATA_BUDGET, RUNBOOKS |
| `pilot/` | Pilot execution records | PILOT_DRY_RUN_01, FINDINGS_BACKLOG |
| `protocol/` | Protocol specs | CAP_NEGOTIATION_V1 |

## Rule

**Do not duplicate spec docs.** If a numbered spec (e.g. `42_Pilot_Critical_Config.md`) exists in `specs/`, do not copy it elsewhere. Link or reference it instead.
