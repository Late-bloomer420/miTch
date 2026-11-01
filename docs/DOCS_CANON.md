# Docs Canon

## Evidence navigation and maintenance — 2026-10-14

GitHub is the authoritative home of code, dated evidence, open findings and live trackers.
External reports/chats are inputs, not a second task-tracking authority.

| Topic | Canonical source |
|---|---|
| Additional scoped findings and links to their evidence | [security/REPO_EVIDENCE_STATUS_2026-10-14.md](security/REPO_EVIDENCE_STATUS_2026-10-14.md); this index does not replace topic/component evidence below |
| Exact dated observations and reproducible probes | [qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md](qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) |
| Task state | [BACKLOG.md](BACKLOG.md), linked implementation issues #170–#173 and planning owners #175–#177 |
| Operating snapshot | [../STATE.md](../STATE.md) |
| Technical sequence / live gate | [RELEASE_READINESS_ROADMAP.md](RELEASE_READINESS_ROADMAP.md), #142 |
| Market hypotheses / live gate | [GTM_SPRINT_ROADMAP.md](GTM_SPRINT_ROADMAP.md), #143 |
| Dated upstream version registry | [eudi/EUDI_SOURCE_BASELINE.md](eudi/EUDI_SOURCE_BASELINE.md); not implementation/interoperability evidence |

**Preserve goals when correcting status.** Missing implementation or evidence does not retire or weaken an agreed product goal. Present the goal, the scoped current evidence, and the remaining work/acceptance criteria separately. Fingerprinting prevention, control of every disclosure and complete user-inspectable transaction history remain goals until explicitly changed by a product decision. A threat model defines how progress is tested; it must not silently narrow the goal. Preserve dated evidence and link unresolved work.

A spec is normative/planned behavior, not proof of implementation. An accepted design is not completed code.
Existing component evidence remains authoritative for its stated scope. A newer counterexample qualifies only an overlapping claim/path/profile; it does not invalidate unrelated passed tests or completed work.
Keep original QA run dates/SHAs and outcomes immutable. Attach later findings in a separate record or navigation entry.
Close a technical issue only with fix commit and profile-specific negatives/integration evidence; close market gates only with auditable counts/artifacts.

For each reviewed claim, link the component/path, profile/configuration, source revision, verification date, test/observation and known limits. A source SHA records where the observation was made; it does not require a fresh whole-repository audit whenever prose changes. Recheck affected claims when their implementation, relevant dependencies/configuration or profile changes. Unchanged evidence retains its original date and scope. Broad release/deployment claims require broader integration/release checks.

Distinguish reproduced defects, integration gaps, externally unvalidated assurances, deliberate system boundaries and planned functions. Missing evidence is not proof of a malfunction. A component implementation is not automatically an integrated application guarantee.

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
- **QA evidence archive:** `docs/qa/`

## Navigation

- **Spec status index (all 112 specs classified):** `docs/specs/SPECS_STATUS_INDEX.md`
- **Master Backlog (offene Arbeit + ADR-Sektion):** `docs/BACKLOG.md`
- **Session History (abgeschlossene Sessions):** `docs/SESSION_HISTORY.md`
- **QA evidence (date-specific validation records):** `docs/qa/`
- **Branch hygiene manifests (dated cleanup records):** `docs/ops/BRANCH_CLEANUP_2026-06-06.md`
- **Epic 4–5 execution plan (Scout & Advisor record):** `docs/EXECUTION_PLAN_epic4-5.md`
- **Verifier-facing Commercial Trust Kit (narrative, technical appendix, evidence index, security sign-off):** `docs/05-business/trust-kit/README.md`
- **September 2026 external-style EUDI desk assessment (research, not certification/legal advice):** `docs/compliance/EXTERNAL_DESK_AUDIT_EUDI_2026-09-11.md`
- **September 2026 use-case and GTM research (proposal, not approved backlog):** `docs/05-business/USE_CASE_LANDSCAPE_AND_SEQUENCED_ROADMAP_2026-09-11.md` and `docs/05-business/USE_CASES_AND_GTM_BRAINSTORM_2026-09-11.md`
- **ADOPT-1 planning gate ("Sign in with AskMI" / `@askmi/connect`):** `docs/tasks/ADOPT_1_CONNECT_PLAN.md`
- **ADOPT-1.0 product boundary decision:** `docs/tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md`
- **ADOPT-1.1 minimal session contract:** `docs/tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md`
- **Repository ecosystem (canonical repo, related repositories, consolidation rule):** `docs/REPOSITORY_ECOSYSTEM.md`
- **ADOPT-1.2 SDK/API shape:** `docs/tasks/ADOPT_1_SDK_API_SHAPE.md`
- **Security audit remediation roadmap:** `docs/security/SECURITY_AUDIT_ROADMAP_2026-10-01.md`

- **Observable trust milestones and assurance/role boundaries:** `docs/security/TRUST_ASSURANCES_AND_ROLE_BOUNDARIES.md` (planning; #175–#177, complements existing component evidence and #170–#173).

## Research And Strategy Inputs

These documents are useful inputs, but they do not override `STATE.md`,
`docs/BACKLOG.md`, specs, ADRs or dated QA evidence:

- `docs/compliance/EXTERNAL_DESK_AUDIT_EUDI_2026-09-11.md` — external-style desk assessment of EUDI trust boundaries, product routes and certification limits. It is not an accredited audit, certification, legal opinion or production approval.
- `docs/05-business/USE_CASE_LANDSCAPE_AND_SEQUENCED_ROADMAP_2026-09-11.md` — broad use-case landscape and sequenced roadmap proposal. It is not customer validation or delivery commitment.
- `docs/05-business/USE_CASES_AND_GTM_BRAINSTORM_2026-09-11.md` — earlier GTM brainstorm; superseded for breadth by the landscape document, still useful for the verifier-vs-issuer framing.

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

- If a public claim conflicts with a reproduced finding, qualify the overlapping claim with its specific dated evidence. Preserve other component Evidence Pack results; the finding index is navigation, not a global override.
- A protocol spec defines intended behavior; dated active-path evidence defines observed implementation. STATE must expose any gap rather than present a normative spec as implementation.
- If BACKLOG.md conflicts with STATE.md regarding completion status, BACKLOG.md is authoritative for task tracking, STATE.md for operational status.
- If QA evidence conflicts with STATE.md, prefer the newer dated evidence for
  the specific validation it records, then update STATE.md in the next docs
  alignment pass.
- If repo docs reference workspace `memory/*`, treat that as local/private
  context, not as portable public evidence.
