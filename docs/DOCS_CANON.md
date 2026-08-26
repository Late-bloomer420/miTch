# Docs Canon

This file defines the authoritative document per topic area and serves as navigation entry point.

---

## Document Hierarchy

| Dokument | Zweck | Rolle |
|----------|-------|-------|
| `STATE.md` | Operativer Health-Snapshot (Tests, Lint, Audit, Demo) | Was läuft? |
| `docs/BACKLOG.md` | Autoritatives Task-Tracking (erledigt / offen / geplant) | Was ist erledigt, was fehlt? |
| `docs/RELEASE_READINESS_ROADMAP.md` | Release-Sequenz, EUDI-Interop-Gates und Zielkorridore | Was muss in welcher Reihenfolge belegt werden? |\n| `docs/eudi/EUDI_SOURCE_BASELINE.md` | Offizielle EC/EUDI-Quellen und Versions-Lock | Gegen welche externe Wahrheit wird geprüft? |
| `docs/specs/SPECS_STATUS_INDEX.md` | Statusübersicht aller 112 Specs | Spec-Navigation |
| `docs/DOCS_CANON.md` | Dokumenten-Autorität und Navigation (diese Datei) | Einstiegspunkt |
| `docs/REFACTORING_ROADMAP.md` | Deferred Architekturarbeit (PoC → Production) | Größere Umbauten |
| `docs/qa/` | Datierte QA-/Evidence-Artefakte | Was wurde konkret geprüft? |

## Authoritative Sources

- **P0 closure evidence (security + fail-closed test proof):** `docs/ops/EVIDENCE_PACK_P0.md`
- **Pilot execution record:** `docs/pilot/PILOT_DRY_RUN_01.md`
- **Pilot findings source:** `docs/pilot/PILOT_DRY_RUN_01_FINDINGS.md`
- **Pilot findings tracking/backlog:** `docs/pilot/FINDINGS_BACKLOG.md`
- **Capability handshake + downgrade handling:** `docs/protocol/CAP_NEGOTIATION_V1.md`
- **Metadata budget + anti-correlation controls:** `docs/ops/METADATA_BUDGET_V1.md`
- **Failure-mode operations playbooks:** `docs/ops/RUNBOOKS_V1.md`
- **Accountable audit export schema:** `docs/ops/AUDIT_EXPORT_SCHEMA_V1.md`
- **MCP server architecture (Epic 5):** `docs/mcp-server-architecture.md`
- **EUDI official-source and version lock:** `docs/eudi/EUDI_SOURCE_BASELINE.md`\n- **QA evidence archive:** `docs/qa/`

## Navigation

- **Spec status index (all 112 specs classified):** `docs/specs/SPECS_STATUS_INDEX.md`
- **Master Backlog (offene Arbeit + ADR-Sektion):** `docs/BACKLOG.md`
- **Release-readiness roadmap (Sequenz + Gates):** `docs/RELEASE_READINESS_ROADMAP.md`
- **Session History (abgeschlossene Sessions):** `docs/SESSION_HISTORY.md`
- **QA evidence (date-specific validation records):** `docs/qa/`
- **Branch hygiene manifests (dated cleanup records):** `docs/ops/BRANCH_CLEANUP_2026-06-06.md`
- **Epic 4–5 execution plan (Scout & Advisor record):** `docs/EXECUTION_PLAN_epic4-5.md`
- **Verifier-facing Commercial Trust Kit (narrative, technical appendix, evidence index, security sign-off):** `docs/05-business/trust-kit/README.md`

## Agent and Memory Surfaces

| Ort | Rolle |
|-----|-------|
| `AGENTS.md` | Aktuelle repo-lokale Regeln fuer Codex/OpenClaw/Coding Agents |
| `CLAUDE.md` | Aktuelle repo-lokale Regeln fuer Claude Code |
| `docs/archive/CLAUDE_TASKS_session10.md` | Historisches Session-10-Artefakt (archiviert), nicht aktueller Arbeitsauftrag |
| `.agent/skills/**` | Versionierte repo-lokale Skills |
| `.codex/agents/**` | Versionierte repo-lokale Codex-Agent-Konfiguration |
| `.agents/`, `.claude/`, `.qodo/` | Lokale/ignored Agent-Runtime oder Tool-Konfiguration |
| workspace `memory/*` | Private lokale OpenClaw-Memory, nicht portable Repo-Wahrheit |

Wenn diese Flaechen widersprechen, gelten fuer den Repo-Stand zuerst
`docs/DOCS_CANON.md`, `STATE.md`, `docs/BACKLOG.md`, `AGENTS.md` und die
jeweilige aktuelle Tool-Datei. Historische Session-Aufgaben duerfen nicht als
neuer Auftrag behandelt werden.

## Architecture Decision Records (3 Sammlungen)

| Ort | Scope | Index |
|-----|-------|-------|
| `docs/03-architecture/decisions/` | Frühe Phase-0 Decision Notes (DECISION_001–007) | [README](03-architecture/decisions/README.md) |
| `docs/03-architecture/mvp/` | Formale Architektur-Strategie-ADRs (ADR-001–012) | [README](03-architecture/mvp/README.md) |
| `docs/compliance/ADR/` | Compliance- und implementierungsnahe ADRs (ADR-001–009) | [README](compliance/ADR/README.md) |

**Hinweis:** ADR-001–009 existieren in `mvp/` und `compliance/ADR/` mit unterschiedlichen Themen. Die READMEs in den jeweiligen Ordnern erklären die Abgrenzung. Konkretes Beispiel ADR-009: `mvp/ADR-009_Threat_Model.md` ist das STRIDE Threat Model (Sprint 4: Accepted — pending external review); `compliance/ADR/ADR-009.md` ist die WebAuthn-Native-vs-HMAC-Proxy-Entscheidung. Beide Dateien tragen oben einen wechselseitigen "siehe auch"-Hinweis.

## Conflict Resolution Rules

- If README conflicts with the Evidence Pack, the Evidence Pack is authoritative.
- If STATE.md conflicts with a protocol spec, the spec is authoritative.
- If BACKLOG.md conflicts with STATE.md regarding completion status, BACKLOG.md is authoritative for task tracking, STATE.md for operational status.
- If QA evidence conflicts with STATE.md, prefer the newer dated evidence for
  the specific validation it records, then update STATE.md in the next docs
  alignment pass.
- If repo docs reference workspace `memory/*`, treat that as local/private
  context, not as portable public evidence.
