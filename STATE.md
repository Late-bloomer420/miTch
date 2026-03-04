# STATE.md — Current Operating State

**Date:** 2026-03-04  
**Branch:** `master` (default)  
**Release tag:** `pilot-ready-p0`  
**Repo:** `https://github.com/Late-bloomer420/miTch.git`

---

## Canonical references (single source of truth)

- Documentation authority map: [`docs/DOCS_CANON.md`](docs/DOCS_CANON.md)
- P0 evidence and closure status: [`docs/ops/EVIDENCE_PACK_P0.md`](docs/ops/EVIDENCE_PACK_P0.md)
- Latest pilot dry run record: [`docs/pilot/PILOT_DRY_RUN_01.md`](docs/pilot/PILOT_DRY_RUN_01.md)
- Findings backlog: [`docs/pilot/FINDINGS_BACKLOG.md`](docs/pilot/FINDINGS_BACKLOG.md)
- Capability negotiation spec: [`docs/protocol/CAP_NEGOTIATION_V1.md`](docs/protocol/CAP_NEGOTIATION_V1.md)
- Metadata budget: [`docs/ops/METADATA_BUDGET_V1.md`](docs/ops/METADATA_BUDGET_V1.md)
- Failure-mode runbooks: [`docs/ops/RUNBOOKS_V1.md`](docs/ops/RUNBOOKS_V1.md)

## Pilot path (frozen for execution)

- **Minimal scenario:** Altersverifikation (18+) only.
- Purpose: keep pilot scope narrow and avoid parallel drift across multiple use-cases.

## Current status

- **Tests:** 33/34 pass (only `secure-ui-test` needs Playwright browsers)
- **Audit:** 0 npm vulnerabilities
- **All P0 gaps (G-01 through G-06) closed** with evidence
- **P1 open:** AI-02 (WebAuthn timeout codes), AI-04 (audit export schema)
- **Lint:** 290 pre-existing issues (no regressions)

## Recent changes (2026-03-04)

- Merged Codex Pilot Bundle v1 (DOCS_CANON, CAP_NEGOTIATION, METADATA_BUDGET, RUNBOOKS)
- Added `DENY_DOWNGRADE_ATTACK` ReasonCode
- ESLint 8→9 migration (12→0 audit vulns)
- @simplewebauthn v9→v13
- Removed unconfigured APIsec CI workflow
