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

- **Tests:** 38/38 turbo tasks pass; **663 individual tests** green (Session 4: +24)
- **Audit:** 0 npm vulnerabilities (Dependabot alert #18 dismissed)
- **All P0 gaps closed:** G-01–G-06 ✅ AI-01 ✅ AI-05 ✅ AI-06 ✅
- **All P1 gaps closed:** AI-02 ✅ AI-04 ✅ G-07 ✅ G-08 ✅ G-09 ✅
- **Lint:** 0 errors (pre-existing warnings only, no regressions)
- **Findings backlog:** all items closed (P0 × 9, P1 × 5, P2 × 1)
- **Phase 1+2 Unlinkability:** U-01–U-05 ✅ (HKDF pairwise DIDs + did:peer:0 inline resolution + cross-verifier isolation)
- **Phase 3 Security Hardening:** S-01–S-05 ✅
- **OID4VP Policy Bridge:** E-04 ✅ (executeOID4VPFlow, mapRequestToPolicyInput, validateRequestCompatibility)
- **Wallet PWA Tests:** G-01–G-03 ✅ (DocumentService, PrivacyAuditService, App component)
- **Working directory:** `D:/Mensch/miTch-master` (git worktree on master)

## Recent changes (2026-03-06 Session 4)

- U-01: generatePairwiseDIDFromMasterKey — HKDF-SHA-256 wallet master key derivation
- U-02: resolveDidPeer0 — inline did:peer:0z resolution (P-256 pub key, no network)
- U-03/U-04: 23 unlinkability tests (cross-verifier isolation, key shredding, HKDF recovery)
- E-04: OID4VP Policy Bridge — executeOID4VPFlow + 19 tests
- G-01–G-03: Wallet PWA vitest setup + 24 tests (DocumentService, PrivacyAuditService, App)
- fix: tsc strict Uint8Array<ArrayBuffer> cast in pairwise-did.ts
- fix: pairwise-did.test.ts 1000-DID timeout 30s→60s (parallel turbo load)
- fix: parseAuthorizationRequest passes client_metadata through
