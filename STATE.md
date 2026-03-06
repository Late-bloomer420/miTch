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

- **Tests:** 38/38 turbo tasks pass; **760+ individual tests** green (Session 6: +26)
- **Audit:** 0 npm vulnerabilities (Dependabot alert #18 dismissed)
- **All P0 gaps closed:** G-01–G-06 ✅ AI-01 ✅ AI-05 ✅ AI-06 ✅
- **All P1 gaps closed:** AI-02 ✅ AI-04 ✅ G-07 ✅ G-08 ✅ G-09 ✅
- **Lint:** 0 errors, **0 warnings** (H-01b complete — was 170 warnings / 2 errors)
- **Findings backlog:** all items closed (P0 × 9, P1 × 5, P2 × 1)
- **Phase 1+2 Unlinkability:** U-01–U-05 ✅ (HKDF pairwise DIDs + did:peer:0 inline resolution + cross-verifier isolation)
- **Phase 3 Security Hardening:** S-01–S-05 ✅
- **OID4VP:** E-01a–E-01d ✅ complete (Parser, VP Token Builder, Verifier, Policy Bridge)
- **OID4VCI:** E-02 ✅ 32 comprehensive tests (createOffer, issueCredential, policy, audit)
- **Wallet PWA Tests:** G-01–G-03 ✅ (DocumentService, PrivacyAuditService, App, WalletService, ConsentModal, PolicyEditor)
- **Demo:** D-01 ✅ (17 E2E scenario tests), D-02 ✅ (docs/DEMO_SCRIPT.md)
- **Working directory:** `D:/Mensch/miTch` (master branch)

## Recent changes (2026-03-06 Session 6)

- D-01: 4 E2E demo scenario tests — Liquor Store, Hospital, EHDS Emergency, Pharmacy (17 tests)
- D-02: docs/DEMO_SCRIPT.md — full demo walkthrough, troubleshooting, Q&A talking points
- H-01b: ESLint `no-explicit-any` eliminated across ALL packages (0 warnings, was 170)
  - Source packages: shared-crypto, policy-engine, predicates, verifier-sdk, oid4vci,
    eid-issuer-connector, verifier-browser, mock-issuer, anchor-service, audit-log, catalog
  - Apps: wallet-pwa (WalletService, ConsentModal, App, AuditReportPanel), verifier-demo
  - Tests: file-level eslint-disable for legitimate browser-API mock patterns
  - 2 errors fixed: unused imports/params in revocation-statuslist
- Presentation: docs/presentation/OUTLINE.md + ARCHITECTURE.md (Mermaid diagrams)

## Recent changes (2026-03-06 Session 5)

- G-02: WalletService unit tests — 12 tests (init, credential eval, AES-256-GCM, policy, audit chain, key split/recovery)
- G-03: ConsentModal (12 tests) + PolicyEditor (10 tests) component tests
- E-02: OID4VCI expanded tests — 29 new tests (32 total): offer, issuance, validation, policy, audit log
- H-01: Fixed all ESLint errors in policy-engine, oid4vp, wallet-pwa (0 errors remaining)
- fix: IndexedDB mock — added getAll/getAllKeys/clear methods (SecureStorage.getAllMetadata)
- fix: document.elementFromPoint stub for jsdom (SecureZone component)
- fix: config-profiles.test.ts manifestId→trustedIssuers (TS type error)
- fix: jurisdiction.ts unused purpose param, proof-fatigue.ts let→const
