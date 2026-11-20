# STATE.md — Current Operating State

**Scoped update 2026-11-20 — merge session (master `8dd7f3e`, 0 open PRs):** all 10 mergeable PRs squash-merged (#165, #178, #249, #265, #266, #301, #302, #304, #308, #309); only the `Entire Gates` check fails (Entire out of credits) and does not block. #301 verified against #296/L2A-04: audit-log suite 34/34 green at `8dd7f3e` (Node 24.16.0, ASKMI_TEST_MODE=1). Local branch `chore/session-22-history` cleaned and synced to master. Session plan: [`docs/tasks/SESSION_PLAN_2026-11-20.md`](docs/tasks/SESSION_PLAN_2026-11-20.md). No release or pilot gate moves.

**Scoped update 2026-11-03 — API & protocol reality audit + v2 architecture plan (branch `chore/enable-entire`, executable baseline `002ce5e`):**
a first-principles audit against 2026 upstream EUDI/OpenID4VP 1.0/OpenID4VCI 1.0/RFC 9901/ISO 18013-5/W3C DC API standards and active `src/` code recorded 7 scoped findings (`API-01`..`API-07`) in [`docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md) and established the 4-stage remediation & architecture roadmap in [`docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`](docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md):
- **Reproduced active-code gaps (Stage 0 `API-V2-S0`):** (1) `API-01` 4-way live browser E2E mismatch across `@askmi/connect`, `verifier-demo`, `wallet-pwa`, and `issuer-mock` (HTTPS vs. HTTP `walletBaseUrl`/CORS, missing `demo=wallet` query param in `handoff.ts`, bypass of `claim-contract.ts` requesting `$.age` which `DemoPolicy.ts` denies with `CLAIM_NOT_ALLOWED` — masked in `App.test.tsx:972` by `bootstrapFetchMocks('ALLOW')` — and `issuer-mock` `iss` mismatch); (2) `API-02` `wallet-pwa/src/App.tsx:959-961` (`presentOID4VP`) bypasses `decisionCapsule.authorized_requirements`; (3) `API-03` `sd-jwt-vc.ts` RFC 9901 §7.1 validation gaps + `oid4vp-verifier` optional/skippable KB-JWT check (`response-verifier.ts:197`); (4) `API-04` `mdoc/src/device-auth.ts` inverted COSE detached-payload structure vs. ISO/IEC 18013-5 §9.1.3.6; (5) `API-05` unverified default trust list (`anchorPublicKey: null`), status list, and server-side WebAuthn signature check.
- **Architectural direction (Stages 1–3 `API-V2-S1`..`S3`, `API-V2-ONBOARD`, `API-V2-QR`, `API-V2-ZKP`):** commercial role stays open pending G0/G1 (`#143`); dual wallet strategy extracts `@askmi/wallet-guard` as an embeddable SDK while evolving `wallet-pwa` / native apps (including via EU DMA NFC/distribution rules, `#176`) as a standalone product; `@askmi/connect` unifies 3 northbound RP surfaces (Connect Sessions, Headless REST `/v2/verifications`, OIDC-Provider-Bridge) over a two-tier southbound wire protocol (mandatory 100% standard OpenID4VP 1.0 + W3C DC API baseline, plus optional `askmi_ext` AskMI-to-AskMI negotiation). Captures the full design for: (a) **Zero-Account ID/ePassport & Photo-ID Bootstrap** (PIN-free ICAO 9303 ePassport MRZ + NFC `EF.SOD`/`DG1`/`DG2` with Chip/Active Auth + local selfie check, classic eID with PIN for German nPA where `DG2` is EAC-restricted, and optical Photo-ID fallback into a local Passkey vault with zero cleartext issuer retention); (b) **Hybrid Online Universal-QR & Offline POS QR with Honest Anti-Relay UX** (addressing Fett/Küsters cross-device QR phishing `#196` and Apple PCC Observable Trust `#174`–`#177` via dynamic rotating QRs, background BLE/optical proximity where available, and honest 🟢/🟡 UI indicators with Layer 1/2 Number Matching step-up); and (c) **Two-Track Cryptographic Unlinkability** pairing EUDI standard single-use credentials (`#171`) with HPI's published age-verification architecture (`av-demo.hpi.de` / Prof. Lehmann: BBS+ bridged to ECDSA P-256 hardware device binding) alongside Boneh–Boyen $q$-SDH short signatures (`10.1007/978-3-540-24676-3_4`) and Constant-Size Dynamic $k$-TAA (`10.1007/11832072_8`, Au/Susilo/Mu 2006) for multi-show unlinkability and scope-bound rate limiting / zero-registration pseudonyms. Earlier component test results remain valid for their stated scopes; no release or pilot gate moves.

**Scoped update 2026-10-25 — Connect integration for #170:** the fix branch now
mounts the Connect adapter in verifier-demo and hands its stored request to the
wallet. Real signed HTTP regressions enforce the exact numeric-age profile,
issuer/holder binding, one-shot lifecycle and minimized results. The latest
wallet/passkey changes are retained. [Revision, validation and limits](docs/qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md).
Local full test graph: 49/49 tasks; affected builds: 18/18; lint: 13/13 (seven
existing warnings). Implementation/merge record: #224; no release or pilot gate moves.

**Scoped update 2026-10-25 — SLH-DSA test-timeout flake fixed (branch
`fix/pqc-slh-dsa-test-timeout`):** the recurring `pqc.test.ts` SLH-DSA-SHA2-128s
CI timeout (documented 2026-07-12 and twice on 2026-10-25 Actions runs) is fixed
by sharing one keygen+sign `beforeAll` fixture and giving the fixture and tests
explicit 120s budgets — no crypto change. Local: 25/25 direct file run (previously
always 2 fails at the 5s CLI default), full shared-crypto suite 32/32 files,
312/312 tests. [Dated evidence](docs/qa/PQC_SLH_DSA_TEST_TIMEOUT_2026-10-25.md).
Remaining SEC-AUDIT-2 dependency work (49 high advisories, of which 12 are the
`pnpm` CLI devDep in `@askmi/evidence`) stays open under
[`docs/security/SECURITY_AUDIT_ROADMAP_2026-10-01.md`](docs/security/SECURITY_AUDIT_ROADMAP_2026-10-01.md).

**Scoped update 2026-10-25 — #170 fix branch:** the active numeric-age presentation
route now reserves attempts once, checks eligibility and exact profile/scope,
and returns a minimized result. Backend 87 source tests passed; affected apps
built; wallet 203 tests passed. [Revision, commands and limits](docs/qa/ACTIVE_AGE_PROFILE_2026-10-25.md).
This supersedes the older active-route observations below only for that tested
profile. Connect integration and #170 remain open; no release gate changes.

**Scoped update 2026-10-25 — audit gate branch:** PR #206's dependency remediation
allows the minimum critical gate in #194 to pass a fresh audit (141 total,
49 high, 0 critical). Gate regressions: 17/17 passed. [Exact revision and limits](docs/qa/SECURITY_AUDIT_GATE_2026-10-25.md).
High findings and #185 remain open; this does not establish release readiness.

**Scoped update 2026-11-13 — audit gate (PR #257):** the 2026-10-25 entry above is kept as
dated. With PR #257 the shared gate (`scripts/check-security-audit.mjs`) denies on any high
or critical advisory, not only critical. The PR description reports 0 critical / 0 high after
the pnpm 10 switch; that count is dated registry output and has no QA record under `docs/qa/`
yet. #185 stays open for its remaining scope (evidence provenance, SBOM/signed provenance,
conformance, independent validation). No release gate changes.

**2026-11-18 — time-boxed exception (PR #257):** GHSA-fc5q-39xc-vjpf (picomatch ≤ 4.0.7,
high, ReDoS) has no patched release and reaches only dev tooling. It is excepted in
`scripts/security-audit-exceptions.json` until 2026-12-18, and only while the
production-only audit (`pnpm audit --prod`) stays clean. Critical findings are never
excepted; entries expire after at most 90 days. Dated registry output, no `docs/qa/` record.

> **Rolle:** Operativer Health-Snapshot — was läuft, was ist deployed, was ist der aktuelle technische Zustand.
> Für Task-Tracking (was ist erledigt, was ist offen) siehe [`docs/BACKLOG.md`](docs/BACKLOG.md).

**Date:** 2026-10-14 (scoped evidence reconciliation; earlier run dates retained)
**Branch:** `master` (full AskMI rebrand merged via PR #70)
**Historical milestone label:** `v1.0-RC`; this label is not a current release approval
**Repo:** `https://github.com/Late-bloomer420/miTch.git`
**Executable source checked:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`. #138/#158/#159/#160 designs/docs and #152 runner work are merged; #141 security reconciliation remains open.

---

## Canonical references (single source of truth)

- Documentation authority map: [`docs/DOCS_CANON.md`](docs/DOCS_CANON.md)
- P0 evidence and closure status: [`docs/ops/EVIDENCE_PACK_P0.md`](docs/ops/EVIDENCE_PACK_P0.md)
- Latest pilot dry run record: [`docs/pilot/PILOT_DRY_RUN_01.md`](docs/pilot/PILOT_DRY_RUN_01.md)
- Findings backlog: [`docs/pilot/FINDINGS_BACKLOG.md`](docs/pilot/FINDINGS_BACKLOG.md)
- Capability negotiation spec: [`docs/protocol/CAP_NEGOTIATION_V1.md`](docs/protocol/CAP_NEGOTIATION_V1.md)
- Metadata budget: [`docs/ops/METADATA_BUDGET_V1.md`](docs/ops/METADATA_BUDGET_V1.md)
- Failure-mode runbooks: [`docs/ops/RUNBOOKS_V1.md`](docs/ops/RUNBOOKS_V1.md)
- Security Target (CC): [`docs/compliance/SECURITY_TARGET_CC_READY.md`](docs/compliance/SECURITY_TARGET_CC_READY.md)
- QA evidence records: [`docs/qa/`](docs/qa/)
- Deployment Orchestration: [`docker-compose.yml`](docker-compose.yml)

## Reference/pilot-target path

- **Minimal scenario:** Altersverifikation (18+) via OID4VP.
- **Status:** historical RC milestone; current integrated release gates remain open in #142. Component completion below does not imply an accepted full deployment.

## Scoped verification update — 2026-10-14

Executable baseline: `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`. Build 29/29, rebrand/archived-import guards, and a focused 63-test schema/metadata/engine run passed. The existing harness returned 10 PASS / 2 RESIDUAL / 0 FAIL within its manifest. A new full-suite, lint, browser E2E or official-wallet matrix was not run in this audit.

| Scope | Observation / task | Existing work retained |
|---|---|---|
| `/oid4vp-present` | Server request not retained; replay and caller-selected nonce/state accepted (#170) | Issuer-signature, digest and KB-JWT checks (#132/#135/#137) |
| Age demo/application result | Signed age 12 is cryptographically accepted; eligible success must be a separate application decision (#170) | Cryptographic validity is not an age-policy verdict |
| Stored SD-JWT lifecycle | Repeated `singleUse:true` presentation and premature SHREDDED UI (#171) | Legacy pool consumption/holder-binding (#86–#94) |
| External audit/telemetry | Tier-2 helpers not found wired at inspected app/audit call sites (#172); inventory actual outputs first | #81 schema and local Tier-1 history |
| Evidence report / CI audit | Final-LF hash mismatch (#173); synthetic critical/high check exits 0 (EV-05/#141) | #134 harness and #152 shell-free runner |

[Detailed dated observations](docs/qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) and [finding index](docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md) add to the earlier evidence below; they do not reclassify unrelated completed work. G0/G1 remain open in #142/#143; no published 20/8/3 tally was found, which does not imply zero private interviews.

## Recorded operating status

### Operational Health
- **GitHub Actions:** see the run for the exact head being assessed. Older checks are dated evidence; the audit-threshold false-success reproduced in EV-05 is distinct from build/test success. Current branch-protection configuration was not revalidated in this pass.
- **Tests:** `pnpm test` → **46/46 turbo tasks green** (verified 2026-07-13; 1820+ individual tests). Earlier records (2026-06-04 RC) showed 45/45; the 46th task was added when `integration-tests` joined the turbo graph. PR #66 additionally re-ran targeted package tests for the npm scope alignment (`revocation-statuslist`, `shared-crypto`, `audit-log`, `policy-engine`) before merge.
- **Lint:** `pnpm lint` → **0 errors, 7 warnings** (verified 2026-07-13). All 7 warnings are pre-existing `@typescript-eslint/no-explicit-any` in `wallet-pwa`, present since the SECURE-1 baseline (Task 0). SECURE-1 introduced zero new warnings (count unchanged 7→7).
- **Compliance mapping:** retain the detailed [CIR component matrix](docs/compliance/EUDI_CIR_MATRIX.md). Its internal row counts do not establish regulatory compliance, LoA High or independent certification.
- **Live Demo Flow (real credential path — verified live 2026-07-17):** issuer-mock (3005) issues a real `vc+sd-jwt` (holder-bound `cnf`) → wallet stores it → wallet presents from the stored VC with selective disclosure (`age` only) + KB-JWT → verifier `/oid4vp-present` (3004) resolves the issuer key **authoritatively via the trust list / JWKS** (ignores any wallet-supplied `issuer_jwk`), verifies the signature, decodes disclosures → `200 {ok, disclosedClaims:{age:24}}` + consent receipt. Negative paths proven live: attacker-forged trusted `iss` → `403 Signature verification failed`; untrusted `iss` → `403 untrusted_or_unresolvable_issuer`. Evidence: [`docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md`](docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md). **Start note (fixed 2026-10-24, branch `feat/adopt-1-connect-slice`, Node v24.16.0):** the former `@askmi/poc-hardened` `pnpm dev` failure (`ERR_MODULE_NOT_FOUND`) is fixed — extensionless relative imports in `@askmi/shared-crypto` and `@askmi/revocation-statuslist` sources are now `.js`-suffixed so their ESM `dist` loads under plain Node; verified: `poc-hardened` `tsc && node dist/server.js` boots (port 8080), package tests green (shared-crypto 285, revocation-statuslist 26, poc-hardened 132). **Known gaps:** only the `age`/liquor-store scenario runs end-to-end with a real credential (others fail-closed as "no matching credential"); the browser UI click-through of wallet-pwa (`:5174`, HTTPS self-signed) was not automated this pass; the verifier-demo **frontend** (`:5175`) `/wallet-present` is still the *simulated* wallet, not the real ADOPT path.
- **Legacy simulated demo (`/wallet-present`):** the verifier-demo frontend still drives a self-contained simulation (ephemeral issuer keys + scenario claims) for visualization across all scenarios; this is demo-only and distinct from the real ADOPT-0a/0b path above.
- **Containerization:** All services (Wallet, Issuer, Verifier) fully Dockerized with multi-stage builds. Verified via `scripts/verify-deployment.ps1`.
- **Reverse Proxy:** Caddy-based routing with TLS termination configured for `*.askmi.demo` domains.
- **Visual Branding:** W3C VC-Render support enabled; dynamic credential cards with SVG templates.
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)

### Change history

This file holds the current operating snapshot only. What merged on `master` since 2026-10-14 is in [`CHANGELOG.md`](CHANGELOG.md) (one line per pull request, linked QA records). Earlier history, including the "Recent additions" sections moved out of this file, is in [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md) under "Moved from STATE.md".

### Completion Summary
The entries moved to [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md) retain their original dates, component scopes and recorded validation. They document substantial delivered work. Current profile integration and independent assurance are separate gates; internal mapping counts are not compliance scores.
Detailliertes Task-Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
