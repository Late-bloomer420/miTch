# STATE.md — Current Operating State

**Date:** 2026-03-05
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

- **Tests:** 34/34 turbo tasks pass; 155+ individual tests green
- **Audit:** 0 npm vulnerabilities
- **All P0 gaps (G-01 through G-06) closed** with evidence
- **All P1 gaps closed:** AI-02 ✅ AI-04 ✅ G-07 ✅ G-08 ✅ G-09 ✅
- **Lint:** 0 errors (pre-existing warnings only, no regressions)

## Recent changes (2026-03-05)

- WebAuthn cross-device + ConsentModal EHDS + i18n: all committed
- fix(policy-engine): missing workspace deps `@mitch/layer-resolver` + `@mitch/mock-issuer`
- G-07: Key separation — ECDH-P256 encryption keys separated from ECDSA signing keys in KeyGuardian
- G-08: JWE encrypted credentials at rest (jose CompactEncrypt, alg=dir enc=A256GCM)
- G-09: L2/blockchain anchoring stubs — EthereumL2AnchorProvider + TransparencyLogAnchorProvider
- AI-02/AI-04: marked closed in FINDINGS_BACKLOG (tests were already passing)
- fix(lint): removed unused `receivedProof` state in VerifierPanel
