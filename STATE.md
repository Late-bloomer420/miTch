# STATE.md — Current Operating State

**Date:** 2026-03-14
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

- **Tests:** 39/39 turbo tasks pass; 60/60 wallet-pwa tests (oid4vp alias fix: `92161b8`)
- **Live Demo Flow:** `pnpm dev` → Verifier (3004) + Wallet (5173) → `/authorize` → consent → `/wallet-present` → SD-JWT VC + KB-JWT validated → disclosedClaims in UI
- **Audit:** 0 npm vulnerabilities (Dependabot alert #18 dismissed)
- **All P0 gaps closed:** G-01–G-06 ✅ AI-01 ✅ AI-05 ✅ AI-06 ✅
- **All P1 gaps closed:** AI-02 ✅ AI-04 ✅ G-07 ✅ G-08 ✅ G-09 ✅
- **Lint:** 0 errors, **0 warnings** (ESLint 26 → 0: unused imports/vars entfernt, stale eslint-disable-Direktiven entfernt, test-local any-casts durch präzise Typen ersetzt)
- **Findings backlog:** all items closed (P0 × 9, P1 × 5, P2 × 1)
- **Phase 1+2 Unlinkability:** U-01–U-05 ✅ (HKDF pairwise DIDs + did:peer:0 inline resolution + cross-verifier isolation)
- **Phase 3 Security Hardening:** S-01–S-05 ✅
- **OID4VP:** E-01a–E-01d ✅ complete (Parser, VP Token Builder, Verifier, Policy Bridge)
- **Session 9 E2E Wiring:** W-01–W-05 ✅ (OID4VP request generation, wallet consent UI, SD-JWT VC issuance, KB-JWT, verifier validation, session cleanup, consent receipt)
- **Demo Scenarios:** 5 clickable scenarios incl. Revoked Credential flow
- **OID4VCI:** E-02 ✅ 32 comprehensive tests (createOffer, issueCredential, policy, audit)
- **Wallet PWA Tests:** G-01–G-03 ✅ (DocumentService, PrivacyAuditService, App, WalletService, ConsentModal, PolicyEditor)
- **Demo:** D-01 ✅ (17 E2E scenario tests), D-02 ✅ (docs/DEMO_SCRIPT.md)
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
