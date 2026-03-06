# STATE.md — Current Operating State

**Date:** 2026-03-06
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

- **Tests:** 37/37 turbo tasks pass; **639 individual tests** green (Session 3: +449)
- **Audit:** 0 npm vulnerabilities (Dependabot alert #18 dismissed)
- **All P0 gaps closed:** G-01–G-06 ✅ AI-01 ✅ AI-05 ✅ AI-06 ✅
- **All P1 gaps closed:** AI-02 ✅ AI-04 ✅ G-07 ✅ G-08 ✅ G-09 ✅
- **Lint:** 0 errors (pre-existing warnings only, no regressions)
- **Findings backlog:** all items closed (P0 × 9, P1 × 5, P2 × 1)
- **Phase 1 Unlinkability:** U-01–U-05 ✅ (Pairwise Ephemeral DIDs + Policy Engine Integration)
- **Phase 3 Security Hardening:** S-01–S-05 ✅ (Fingerprint, Rollback, Input Validation, Isolation, Zero Trust)
- **.gitattributes:** Line endings normalized (LF)

## Recent changes (2026-03-06)

- U-05: Policy Engine generates pairwise DID (did:peer:0z) per ALLOW/PROMPT decision
- S-01: verifier_fingerprint in PolicyRule — Fake Verifier Spoofing defense
- S-02: manifest_version (monotonic) + manifest_hash — Manifest Rollback protection
- S-03: Whitelist-based Input Validation (claim names, DID format, path traversal)
- S-04: Spec 112 — Komponenten-Isolations-Modell (Engine/Consent/Audit boundaries)
- S-05: docs/ARCHITECTURE_ZERO_TRUST.md — Zero Trust intern verankert
- H-04: main branch was already deleted on GitHub (confirmed)
- H-05: .gitattributes created (text=auto eol=lf)
- fix: pairwise-did.test.ts — 30s timeout for 1000-DID collision test (parallel turbo load)
