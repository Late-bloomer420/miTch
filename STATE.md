# STATE.md — Current Operating State

> **Rolle:** Operativer Health-Snapshot — was läuft, was ist deployed, was ist der aktuelle technische Zustand.
> Für Task-Tracking (was ist erledigt, was ist offen) siehe [`docs/BACKLOG.md`](docs/BACKLOG.md).

**Date:** 2026-03-17
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

### Operational Health
- **Tests:** 41/41 turbo tasks pass; 1442 individual tests (27 packages); 66/66 wallet-pwa tests
- **Lint:** 0 errors, 0 warnings
- **Audit:** 7 npm vulnerabilities (4 high, 3 moderate — `undici` ≥7.0.0 <7.24.0, `flatted` <3.4.0; alle in devDependency-Ketten)
- **Live Demo Flow:** `pnpm dev` → Verifier (3004) + Wallet (5173) → `/authorize` → consent → `/wallet-present` → SD-JWT VC + KB-JWT validated → disclosedClaims in UI
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)
- **Demo Scenarios:** 5 clickable scenarios incl. Revoked Credential flow

### Recent additions (since Session 10+)
- **`@mitch/data-flow`** package: Transaction view — Audit-Entries nach decision_id gruppiert, claims/lifecycle/shredding (Phase 1). VP_GENERATED Audit-Event in WalletService. DataFlowPanel in wallet-pwa.
- **`@mitch/mdoc`** package: CBOR codec, COSE Sign1 ES256, ISO 18013-5 types — 40 tests green
- **PQC Readiness:** `shared-crypto/src/pqc.ts` (ML-DSA, ML-KEM via @noble/post-quantum) + `crypto-agility.ts` (algorithm registry, negotiation)
- **SPRINT_PLAN.md F-01–F-18:** recovery SSS, verifier binding, safe glob, CSP, ci-security — details in [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)

### Completion Summary
Alle P0 + P1 Gaps geschlossen. Phase 0–1 complete, Phase 2–3 teilweise.
Detailliertes Task-Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
