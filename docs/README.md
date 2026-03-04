# miTch Documentation Structure

## Canonical Locations

| Folder | Content | Notes |
|--------|---------|-------|
| `specs/` | **All numbered spec docs (00–102+)** | Single source of truth |
| `00-welt/` | Project vision & manifesto files | MASTER_BRIEF, digital_rights_charter, mitch_policy_manifest |
| `01-grundversorgung/` | Phase-specific overrides (if any differ from specs) | Mostly emptied after dedup |
| `03-architecture/decisions/` | Architecture Decision Records (ADRs) | DECISION_001–007 |
| `03-architecture/mvp/` | MVP-specific ADRs | ADR-001–003 |
| `04-legal/` | Legal documents | Unique content |
| `05-business/` | Business documents | Unique content |
| `context/` | Context documents | Unique content |

## Rule

**Do not duplicate spec docs.** If a numbered spec (e.g. `42_Pilot_Critical_Config.md`) exists in `specs/`, do not copy it elsewhere. Link or reference it instead.
