# AskMI — Session History

Ausgelagert aus `STATE.md` am 2026-03-14. Enthält den Verlauf abgeschlossener Sessions.

---

### Session 24 — Massen-Merge: alle 10 mergebaren PRs nach master (2026-11-20)
- **Goal:** „Pick and merge what's possible" — Entire ist ohne Credits, der `Entire Gates`-Check schlägt auf jedem PR fehl, blockiert aber nicht.
- **Merges (squash, in Reihenfolge):** #308 `c2fc6f4`, #249 `246fbbe`, #302 `ac67854`, #266 `26717bf`, #178 `536f18a`, #165 `9f89522`, #301 `21fc573`, #304 `ab1832a`, #265 `cd50806`, #309 `8dd7f3e`. Danach 0 offene PRs. Vor jedem Merge waren alle übrigen Checks (Build & Test, CodeQL, security, Evidence, Layer Protection, Dependency Audit) grün.
- **Konfliktlösungen:** #304 (`docs/BACKLOG.md`: beide Sektionen behalten), #265 (`dev-demo.sh`/`.ps1`: master-Shim `pnpm demo` behalten; `DEMO_SCRIPT.md`: beide Absätze + HTTPS-CORS; `App.tsx`: `isDemoRuntime || route === 'wallet' || isWalletDeepLink(...)`), #301 (Base-Branch-Arbeit war via #297 schon auf master; auf master retargeted und sauber gemerged).
- **Verifikation:** #296 (L2A-04) gegen #301 geprüft — `anchor.ts` setzt `network: 'mock'`/`status: 'mocked'`, `mock-anchor-export.test.ts` 1/1 und volle audit-log-Suite 34/34 grün (Node 24.16.0, ASKMI_TEST_MODE=1, master `8dd7f3e`); Evidence-Kommentar auf #296 (ID 7032389824).
- **Lokaler Branch `chore/session-22-history` aufgeräumt:** alle uncommitted/untracked Änderungen waren veraltete Snapshots (master hat jeweils mehr) — verworfen; Branch auf `origin/master` synchronisiert (0 eigene Commits, `git cherry` bestätigte Duplikate). Keine Repo-Settings/Rulesets angefasst (AGENTS.md-Guard).
- **Offen:** `Entire Gates` rot bis Credits wieder da sind; #294/#295 (echtes L2-Anchoring + ADR), #293 (fail-closed ohne Status-Claim), #185 (High-Severity-Remediation).

### Session 20 — API & Protocol Reality Audit + v2 Architecture Plan (2026-11-03)
- **Goal:** Conduct a first-principles audit of AskMI's APIs, protocols, and documentation against 2026 upstream specifications (OpenID4VP 1.0 Final, OpenID4VCI 1.0 Final, HAIP 1.0, RFC 9901, `draft-ietf-oauth-sd-jwt-vc`, ISO/IEC 18013-5 §9.1.3.6, W3C Digital Credentials API, ETSI TS 119 475/602, EU Age Verification Profile `eu.europa.ec.av.1`, EUDI TS07/TS08) and active `src/` code at `002ce5e`.
- **Findings (`API-01`..`API-07`):** Documented in [`docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md): (1) 4-way live browser E2E break in `@askmi/connect` + `verifier-demo` + `wallet-pwa` + `issuer-mock` (`API-01`); (2) `presentOID4VP` disclosure clipping bypass ignoring `decisionCapsule.authorized_requirements` (`API-02`); (3) RFC 9901 §7.1 SD-JWT VC validation gaps and skippable KB-JWT check (`API-03`); (4) inverted COSE detached-payload structure in `mdoc/src/device-auth.ts` vs. ISO/IEC 18013-5 §9.1.3.6 (`API-04`); (5) unverified default trust list, status list, and server-side WebAuthn signature (`API-05`); (6) false `@sd-jwt/*` library claim in `03_ARCHITECTURE.md` (`API-06`, fixed); (7) pre-final OID4VP/OID4VCI vs. 2026 final specs (`API-07`).
- **Architectural Plan (`API-V2-S0`..`S3`, `API-V2-ONBOARD`, `API-V2-QR`, `API-V2-ZKP`):** Documented in [`docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`](tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md): commercial role open pending G0/G1 (`#143`); dual wallet strategy (`@askmi/wallet-guard` SDK extraction + standalone `wallet-pwa`/native product evolution under EU DMA `#176`); unified 3-surface northbound RP API (Connect Sessions, Headless REST `/v2/verifications`, OIDC-Provider-Bridge) over a two-tier southbound wire protocol (mandatory 100% standard OpenID4VP 1.0 + W3C DC API baseline + optional `askmi_ext` AskMI-to-AskMI extension negotiation); Zero-Account ID/ePassport & Photo-ID Bootstrap (PIN-free ICAO 9303 ePassport MRZ + NFC `EF.SOD`/`DG1`/`DG2` with Chip/Active Auth + local selfie check, nPA eID with PIN, and Photo-ID fallback into a Passkey vault with zero cleartext issuer retention); Hybrid Online Universal-QR + Offline POS QR with honest Anti-Relay UX (Fett/Küsters `#196` + Apple PCC Observable Trust `#174`–`#177`); and Two-Track Cryptographic Unlinkability pairing EUDI standard single-use credentials (`#171`) with HPI's published age-verification ZKP architecture (`av-demo.hpi.de` / Prof. Lehmann: BBS+ bridged to ECDSA P-256 hardware device binding) alongside Boneh–Boyen $q$-SDH short signatures (`10.1007/978-3-540-24676-3_4`) and Constant-Size Dynamic $k$-TAA (`10.1007/11832072_8`, Au/Susilo/Mu 2006).
- **Tracker Alignment:** Updated `docs/DOCS_CANON.md`, `docs/_core/03_ARCHITECTURE.md`, `docs/compliance/EUDI_CIR_MATRIX.md`, `docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md`, `STATE.md`, and `docs/BACKLOG.md` on branch `chore/enable-entire`.

### Session 21 — Entire Trail #16 Review-Fixes (2026-11-12)
- **Goal:** Work the open agent findings on Entire trail #16 / change `miTch/15` (branch `chore/enable-entire`) against the local code.
- **Fixes:** (1) `.entire/settings.json` `push_sessions` back to `false` — high finding: `8bbebba` flipped it to `true` inside a docs commit, contradicting the trail's "keep checkpoints local" (`f15cf8d` had it `false`); (2) `docs/_core/03_ARCHITECTURE.md` ML-DSA claim qualified: implemented in `pqc.ts` but `pqc-candidate` in `crypto-agility.ts`, so the roadmap warning and risk table stay true; (3) `API-07` section added to `docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md` and `API-07` row added to `docs/BACKLOG.md`, so trackers again match the 7 recorded findings (`API-01`..`API-07`); (4) audit evidence re-pinned from branch SHA `f15cf8d` to executable baseline `002ce5e` in all trackers (branch SHAs do not survive squash-merge); (5) API-04 observation corrected to the real `device-auth.ts` functions (`verifyDeviceSignature` / `verifyDeviceMac` / `verifyDeviceAuth`; no `signDeviceAuth`; no `throw` — `'COSE_Sign1 payload is null'` is in `mso.ts:173`), incl. the Stage-0 plan row; (6) API-02 code quote replaced with the actual `App.tsx:959-962` lines.
- **Not code-actionable:** the finding that this PR mixes the Entire chore with the protocol-audit docs — requires splitting the PR by the maintainer, not a code edit.

### Session 22 — Trail #16 merge, ruleset repair, Dependabot cleanup (2026-11-13)
- **Goal:** Merge PR #247 (change `miTch/15`), unblock the broken `master` ruleset, and clear the 153 Dependabot alerts on master.
- **Trail #16:** 8 of 9 findings fixed in `2ae0ae0` and resolved via `entire trail finding reply`/`resolve`; the 9th (low, PR scope mixing) is deliberately left open with an explanatory reply. Change `miTch/15` merged via PR #247 (`4397b2b`).
- **AGENTS.md guard:** new rule committed (PR #267, `102e436`): agents must never change GitHub repo settings / branch protection / rulesets via API/CLI without explicit owner approval; on an unexpected rule block, stop, list the rule, wait.
- **Ruleset repair (owner-approved):** ruleset `master` (26415448) had unsatisfiable rules that froze master — removed `required_deployments:["wallet"]` (no wallet deploy workflow exists), `code_quality`, `code_coverage`, and re-added `update` **with** `bypass_actors: [RepositoryRole admin, always]`. `code_quality`+`code_coverage` staged in new ruleset `master-evaluate` (27168875, enforcement `disabled` — `evaluate` requires Enterprise). Note: `gh pr merge` without `--admin` is not treated as bypass; use `--admin` or the UI.
- **Dependabot cleanup:** 153 → 0 open alerts. Wave 1 (PR #269, `2bdd8ac`): removed stray `src/apps/verifier-demo/frontend/package-lock.json`, zod ^3→^4.6.6 in oid4vci/mcp-server (mcp-server tool schema moved `zod/v3`→zod v4, tsconfig paths repointed), pnpm pin 9.15.9→10.34.5 in `@askmi/evidence` (+ runner `PNPM_VERSION`; one security test now accepts fail-closed FAIL verdicts, payload-execution assertion unchanged). Wave 2 (PR #272, `f9ca6fe`): root `pnpm.overrides` extended for all remaining vulnerable ranges (undici `>=7.30.1 <8` — 7.x kept for jsdom; hono 4.13.16; ip-address; brace-expansion; js-yaml; qs; body-parser 2.4.0; form-data; glob; minimatch `>=11.0.1` with 3.x pinned `<4`; source-map-js; vitest/@vitest/mocker 4.1.12; esbuild 0.28.1; @simplewebauthn/server; @humanfs/node; @hono/node-server `>=2.1.3`; `@modelcontextprotocol/sdk` ^1.32.0). Verified: `pnpm audit` 0, build 31 pkgs, tests 49/49, lint green; Dependabot check on master now success → Entire `base_checks` gate green again.
- **Open points / notes for the next session:** (1) Trail #16 itself stays open as discussion trail — only the deliberate low PR-scope finding remains open. (2) Entire hooks auto-added `.entire/agent-guide.md` + agent markers in `AGENTS.md`/`CLAUDE.md` (landed in #272 because #247 merged without them). (3) Once a real `wallet` deployment pipeline exists, `required_deployments` can be re-enabled; `master-evaluate` can switch to `evaluate` on Enterprise. (4) CI did not auto-trigger once when a merged PR's branch was re-pushed — fixed with an empty commit + merging master into the branch (real conflict in `pnpm-lock.yaml` resolved in favour of the branch). (5) Other agents' PRs still open (#248 deps, #268 CLAUDE.md mirror, #273 Dependabot vitest-mocker, docs PRs) — not touched here.

### Session 23 — #247 scope split assessed and not carried out (2026-11-16 … 2026-11-18)
- **Goal:** Resolve the remaining low finding of Entire trail 16 ("PR scope mixing"): #247 (`4397b2b`) had merged the Entire enablement together with the 2026-11-03 API/protocol audit.
- **Attempt:** #280 reverted the audit and tracker changes on master; #281 was to re-land them standalone for a separate review.
- **Outcome:** Both closed unmerged by owner decision on 2026-11-18. The Entire findings on #280 (Entire trail 37, 5 medium / 2 low, confirmed against `d7f0e77`) showed the revert would remove master's tracking of open defects `API-01`..`API-07` (incl. API-02, P0), set CIR rows 2977-6, 2977-9, 2982-7, 2982-11, 2982-14 and 2982-15 back to ✅ against the code, restore the incorrect `@sd-jwt/*` library claim (API-06) and delete Sessions 20–21 from this append-only log. #281's net diff contained none of the audit because the audit was still on master.
- **Decision:** The audit stays on master unchanged. The separate review the split was meant to produce is tracked in #299. No finding, gate or code changed in this session.

### Session 19 — G-100.4 Correlation IDs (2026-07-04)
- **Goal:** Close the remaining G-100.4 traceability gap without adding semantic identifiers or widening the privacy surface.
- **Change:** Added canonical `txn_*` correlation IDs in `@askmi/shared-types` (`newCorrelationId`, `resolveCorrelationId`, validation tests). OID4VP verifier request builders and `VerifierSDK` mint them; OID4VP parser/encoder preserves them; `policy-engine` carries them into `DecisionCapsule`.
- **Wallet/Issuer trace path:** Wallet policy/audit events now share the same correlation ID across `POLICY_EVALUATED`, `VP_GENERATED`, and Proximity `VP_SENT`; issuer-mock mirrors `x-correlation-id` on `/credential` and `/credential/mdoc`.
- **Validation:** Targeted tests/builds for changed packages passed; repo gates passed locally: `pnpm run guard:rebrand`, `pnpm lint`, `pnpm test` (46/46 Turbo tasks).
- **Status:** Merged via PR #126 to master `da8afce` after required GitHub checks passed.
- **Follow-on:** Started G-110.1 closeout on `docs/g110-qr-link-closeout`: existing VerifierPanel QR + "Open in wallet" behavior is being locked with all-scenario coverage and backlog truth-alignment.

### Session 18 — G-100 closure, Proof-Randomization, Passkey onboarding, Capsule-Sig root-cause (2026-06-08 … 2026-06-20)
- **EPIC G-100 P0-block closed (#98–#102):** EUDI-shaped versioned claim/predicate contract (G-100.2, #98), injectable `asOf` determinism fix (G-100.1, #99), `verifier-browser` PoC archived + CI archived-import guard (G-100.6, #100), anti-oracle timing-test de-flaked (G-100.7, #102).
- **Phase-1 Unlinkability / Proof-Randomization (#83–#96):** single-use credential boundary at issuance (#91), batch issuance + ephemeral holder binding (C2, #92), KB-JWT PoP gate on verifier `/present` (C1, #94), `brainpoolP512r1` (#90), honest single-use DataFlow display (#88/#96), IndexedDB teardown-deadlock fix (#93). BBS+ (U-10–U-13 remainder) deferred.
- **G-130.1 Passkey-first onboarding (#103, #104):** device-bound passkey = account (Model A), durable vault, enforced unlock default, first-run welcome, explicit Reset escape hatch, user-facing Get/Refresh credential UI.
- **"Capsule signature verification failures" root-caused & resolved (2026-06-18):** the 5-scenario failures were an incomplete AskMI↔miTch rebrand (DID-namespace + package-scope drift), not a crypto defect. `did:mitch`/`@mitch/*` = 0 in `src/`, `guard:rebrand` green. Verified live across all 4 demo servers (`POST /wallet-present`: real disclosed claims for liquor-store/doctor-login/ehds-er/pharmacy; correct `REVOKED` 403). Evidence: [`qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md`](qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md). Added `start-4-servers.ps1` (4-window dev launcher).
- **H-10 Truth-Alignment (2026-06-20, branch `docs/h10-truth-alignment`):** corrected `STATE.md`/`BACKLOG.md` master pointer #81→#104, flipped G-130.1 to ✅, clarified the Phase-3-rollup vs. Video-Gap-granular status convention, recorded the capsule-sig resolution as QA evidence, added this entry. Full suite: 46/46 turbo test tasks green.
- **Net master move:** `fb879cc` (PR #81) → `20478f0` (PR #104).

### Session 17 — Epic 2–5 Scout & Advisor Pass (2026-06-05 / 2026-06-06)
- **Mode:** Scout & Advisor — every change landed via a reviewed `proposal/*` PR; no direct commits to `master`. Corrected plan of record: [`EXECUTION_PLAN_epic4-5.md`](EXECUTION_PLAN_epic4-5.md).
- **Epic 2 — Sovereignty Center (PR #75):** Restored `SovereigntyCenter.tsx` and wired it back into `wallet-pwa` `App.tsx`; added a wallet-side verifier reputation watchdog.
- **Epic 4 — Consent Manager UX (PR #77, UX-09):** Found the panel used a `consent-manager-panel__*` BEM contract with **no matching stylesheet** — authored it in `wallet.css` against shared `--accent-*` / `--text-*` tokens, removed all inline styles, and wrote `ConsentManagerPanel.test.tsx` (10 tests). `wallet-pwa` build ✓, tests ✓ 105/105 (baseline 95).
- **Epic 5 — MCP Integration (PRs #78–#80, CI-01):** Wired `@askmi/mcp-server` `askmi_evaluate_disclosure` to the real `policy-engine` instead of inventing a new tool; added stdio smoke validation (#79) and a local evaluation scope loader (#80). Architecture: [`mcp-server-architecture.md`](mcp-server-architecture.md).
- **Accountable audit export (PR #81):** Added a `policy-engine` audit export model for accountable disclosure records — [`docs/ops/AUDIT_EXPORT_SCHEMA_V1.md`](ops/AUDIT_EXPORT_SCHEMA_V1.md).
- **Housekeeping:** ADR-013 WalletService decomposition strategy (PR #73); 2026-06-06 branch cleanup manifest (PR #74); test-fixture centralization + drift guard and shared StatusList helpers (PRs #71/#72, S2-04/S2-05).
- **Net master move:** `8d8735b` (PR #69) → `fb879cc` (PR #81).

### Session 16 — Full AskMI Rebrand (2026-06-04)
- **Goal:** Complete the partial npm-scope rename into a full active workspace rebrand.
- **Change:** Renamed all active workspace package names, imports, aliases, scripts, lockfile entries, demo trust fixtures, local `*.askmi.demo` identifiers, and app-facing product strings to AskMI / `@askmi/*`.
- **Compatibility:** Added targeted `MITCH_*` fallback support for existing environment variables and popup bridge messages while making `ASKMI_*` the primary runtime naming.
- **Fix:** Renamed `MitchPolicyEvaluator` to `AskmiPolicyEvaluator` and aligned the wallet audience binding to `askmi-wallet-pwa`.
- **Validation:** `@askmi/oid4vp` tests/build, verifier backend tests/build, wallet-pwa tests/build, issuer-mock test/build, policy-engine tests, shared-crypto tests, verifier-sdk build, and mcp-server build passed locally.
- **Deliverable:** [`docs/NPM_SCOPE_RENAME_ASKMI.md`](NPM_SCOPE_RENAME_ASKMI.md)

### Session 15 — Sprint 1A Pilot Flow Rerun (2026-06-04)
- **Goal:** Re-ran the local issuer/verifier/wallet pilot flow as runtime truth after Sprint 0 documentation alignment.
- **Finding:** Local EUDI LOTL fixture did not trust the runtime issuer URI `https://issuer.askmi.demo`, causing all `/wallet-present` scenarios to fail with `ENTITY_NOT_IN_TSL`.
- **Finding:** Revoked demo credentials used the external placeholder `https://example.com/status-list/1`, causing fail-closed `STATUS_SOURCE_UNAVAILABLE` instead of a real local revocation decision.
- **Fix:** Added the runtime issuer URI to the local LOTL fixture and added a local issuer mock StatusList2021 endpoint at `/status-list/1`.
- **Fix:** Made the demo SD-JWT presentation builder accept a local `statusListUri`, wired by verifier backend and wallet PWA.
- **Validation:** Five-scenario matrix now returns four positive HTTP 200 results and one revoked HTTP 403 `REVOKED`; targeted package tests and builds passed.
- **Deliverables:** [`docs/tasks/SPRINT_01A_PILOT_FLOW_RERUN.md`](tasks/SPRINT_01A_PILOT_FLOW_RERUN.md), [`docs/qa/PILOT_FLOW_RERUN_2026-06-04.md`](qa/PILOT_FLOW_RERUN_2026-06-04.md)

### Session 14 — Repo Truth Alignment & npm Scope Reality (2026-06-04)
- **Repo hygiene:** Reconfirmed `master` as the clean integration ground. Old/local/agent-generated work should be reviewed, secret-scanned, and integrated via small targeted commits or cherry-picks, not blind merges.
- **Second-PC rescue review:** Inspected `rescue/second-pc-2026-06-04`; kept it as rescue evidence and re-derived the useful npm scope changes fresh on current `master`.
- **npm scope alignment:** PR #66 aligned the three published packages to npm reality: `@askmi/shared-types`, `@askmi/shared-crypto`, and `@askmi/revocation-statuslist`. All other internal `@askmi/*` packages keep their names.
- **README update:** Documented that miTch remains the project name while public npm packages use `@askmi/*`.
- **Validation:** Targeted package tests passed before PR merge; post-merge `master` checks passed: ci-security, Deploy GitHub Pages, miTch CI/CD Pipeline, and CodeQL.
- **Sprint 0 discovery:** Started docs/current-state alignment work to resolve drift between `STATE.md`, `docs/BACKLOG.md`, `docs/SESSION_HISTORY.md`, `docs/qa/`, and agent-facing files.
- **Deliverables:** [`docs/NPM_SCOPE_RENAME_ASKMI.md`](NPM_SCOPE_RENAME_ASKMI.md), [`docs/tasks/SPRINT_00_REPO_TRUTH_ALIGNMENT.md`](tasks/SPRINT_00_REPO_TRUTH_ALIGNMENT.md)

### Session 13 — Production Path Finalization (2026-06-02)
- **v1.0-RC Achievement:** Completed all 5 strategic phases for pilot readiness.
- **Stabilization:** Normalized `dateOfBirth` monorepo-wide and fixed `AGE_NOT_VERIFIED` blockers.
- **Architecture:** Decoupled storage (Adapters) and decomposed `WalletService` into Repositories.
- **Security:** Implemented Passkey-first unlock, Sandboxed Iframe rendering (V-02), and Anti-Fingerprinting padding (U-22).
- **Compliance:** Live TSL integration with signature verification; achieved **100% technical functional coverage**.
- **Deliverables:** [Detailed Report: Session 13](./session-reports/Session-13-Production-Path.md)
- **Validation:** 1820+ tests green; full consolidation into `master`.

### Session 11 — Compliance Gap Sprint (2026-05-25)
- **EUDI Compliance Matrix:** Updated to 94% coverage (50/53 requirements ✅).
- **StatusList PoC:** Implemented `SDJWTStatusResolver` in `@askmi/shared-crypto` to wire `@askmi/revocation-statuslist`.
- **LoA High Readiness:** Finalized certification analysis documenting WebAuthn hardware binding (ADR-013).
- **Deliverables:** Generated `COMPLIANCE_GAP_REPORT_MAY_2026.md` and updated `BACKLOG.md` with Pilot-Readiness gaps (Trust List, Batch Issuance).
- **Validation:** `pnpm turbo test` green (44 tasks).

### Session 10+ (2026-03-11 – 2026-03-13)
- **SPRINT_PLAN.md Block A Security Fixes:** F-01–F-03, F-06, F-08, F-10–F-11, F-13, F-17 (closed)
- **F-01** Recovery: GF(2^8) Shamir 2-of-3 SSS (real secret sharing, ersetzt XOR 3-of-3)
- **F-09** Verifier Binding Phase 1 (origin hostname vs. verifierId/did:web)
- **F-18** `REFACTORING_ROADMAP.md` erstellt
- phase0-security: IndexedDB test fixes, EIDASComplianceChecker tests (28 tests)
- ESLint: 26 → 0 problems (unused imports, stale directives, test any-casts → precise types)
- response-verifier tests + verifier-browser vitest config
- fix(wallet-pwa): `@askmi/oid4vp` alias in vite.config.ts + vitest.config.ts → 39/39 turbo, 60/60 wallet-pwa tests
- **Deferred to REFACTORING_ROADMAP.md:** F-04 (EphemeralKey), F-07 (claim-level crypto), F-14 (key rotation), F-16 (WalletService split)

#### Bekannte Altlasten
- ~~shared-crypto `pairwise-did.test.ts`: 60s timeout bei 1000 DID generation~~ → **behoben:** Iterationen 1000→100, Timeout 60s→30s (Testaussage erhalten: P-256 256-bit Zufallsraum, Kollisionswahrscheinlichkeit ~2^-200 bei 100 DIDs)

### Session 7 (2026-03-06)
- GitHub Pages deployment workflow (`.github/workflows/pages.yml`)
- OpenGraph / Twitter Card meta tags for link previews
- README rewrite (badges, quick start, live demo link)
- Stale file cleanup (task files → `docs/archive/`)

### Session 8 — EUDI/eIDAS 2.0 Compliance Sprint (2026-03-06)
- **E-10** SD-JWT VC Compliance (draft-ietf-oauth-sd-jwt-vc-11) — 17 tests
- **E-05** DPoP (RFC 9449) — 13 tests
- **E-03** SIOPv2 (Self-Issued OpenID Provider v2) — 15 tests
- **E-04** OAuth 2.0 Attestation-Based Client Auth — attestation+pop chain
- **E-13** HAIP (High Assurance Interoperability Profile) — direct_post.jwt, verifier attestation
- **C-01** Brainpool P256r1 (noble-curves, RFC 5639 §3.4) — 10 tests
- **C-02** ECDH + HMAC-SHA-256 MAC Verification — 10 tests
- **L-01** CIR Compliance Matrix (82% coverage: 2977/2979/2982)
- **L-02** Architecture Decision Records (ADR-001 to ADR-004)

- **CIR Compliance:** 82% ✅ → remaining 🟡: status endpoint deploy, brainpoolP384r1, batch_credential
- **Working directory:** `D:/Mensch/miTch` (master branch)

### Session 6 (2026-03-06)

- D-01: 4 E2E demo scenario tests — Liquor Store, Hospital, EHDS Emergency, Pharmacy (17 tests)
- D-02: docs/DEMO_SCRIPT.md — full demo walkthrough, troubleshooting, Q&A talking points
- H-01b: ESLint `no-explicit-any` eliminated across ALL packages (0 warnings, was 170)
  - Source packages: shared-crypto, policy-engine, predicates, verifier-sdk, oid4vci,
    eid-issuer-connector, verifier-browser, mock-issuer, anchor-service, audit-log, catalog
  - Apps: wallet-pwa (WalletService, ConsentModal, App, AuditReportPanel), verifier-demo
  - Tests: file-level eslint-disable for legitimate browser-API mock patterns
  - 2 errors fixed: unused imports/params in revocation-statuslist
- Presentation: docs/presentation/OUTLINE.md + ARCHITECTURE.md (Mermaid diagrams)

### Session 5 (2026-03-06)

- G-02: WalletService unit tests — 12 tests (init, credential eval, AES-256-GCM, policy, audit chain, key split/recovery)
- G-03: ConsentModal (12 tests) + PolicyEditor (10 tests) component tests
- E-02: OID4VCI expanded tests — 29 new tests (32 total): offer, issuance, validation, policy, audit log
- H-01: Fixed all ESLint errors in policy-engine, oid4vp, wallet-pwa (0 errors remaining)
- fix: IndexedDB mock — added getAll/getAllKeys/clear methods (SecureStorage.getAllMetadata)
- fix: document.elementFromPoint stub for jsdom (SecureZone component)
- fix: config-profiles.test.ts manifestId→trustedIssuers (TS type error)
- fix: jurisdiction.ts unused purpose param, proof-fatigue.ts let→const
# 2026-10-25 — #170 bounded active-route correction

Implemented and tested one-shot request attempts, numeric-age eligibility, exact
disclosure/VCT/submission checks, minimal application/status results and isolation
from simulated routes. [Dated revision-bound evidence](qa/ACTIVE_AGE_PROFILE_2026-10-25.md).
The separate Connect API and integration remain outstanding under #170.


### Connect profile integration — 2026-10-25 (branch, merge pending)

- Confirmed #208 post-merge checks and removed its completed branch/worktree.
- Completed the remaining #170 Connect profile and verifier/wallet integration;
  preserved current master wallet/passkey changes and integrated #211's timeout fix.
- Added real signed HTTP rejection cases and configured issuer/JWKS binding.
- [Exact code revision, commands, results and boundaries](qa/CONNECT_PROFILE_INTEGRATION_2026-10-25.md).
  This is numeric-age middleware with minimized application results, not ZKP or
  official-wallet interoperability evidence. No pilot/release gate changes.

# 2026-11-19 — Build/test runtime baseline measurement

- Question: why does `pnpm build`/`pnpm test` feel long? No documented runtime
  baseline existed (no runtime entries in BACKLOG/STATE/SESSION_HISTORY).
- Method: timed warm/cold runs plus per-suite vitest breakdown at clean committed
  revision `70c7aef` on the local Windows machine (Node 24, 12 cores), verified
  empty `git status` before each run. Exact commands, numbers and limits:
  [dated QA report](qa/BUILD_TEST_PERFORMANCE_BASELINE_2026-11-19.md).
- Measured results: warm test run 1.7 s turbo ("FULL TURBO") / 3.3 s wall; full cold
  test graph (`turbo run test --force`, 50 tasks incl. `@askmi/poc-hardened`, which `pnpm test`
  excludes; not like-for-like with the warm run) 3 m 7.5 s turbo / 3 m 11.1 s wall.
  Top suites under full load: evidence 83.3 s wall vs 13.6 s isolated (~6x CPU
  contention; its real `spawnSync` subprocess tests are the package's purpose),
  wallet-pwa 78.2 s with worker-aggregated import time dominating and environment
  startup measured at 6 ms. shared-crypto is real PQC test work but 19.4 s wall
  (the 61.2 s figure is worker-aggregated, not wall clock). `turbo.json` defines
  no `inputs`; CI runs with a cold Turbo cache per run plus a duplicate
  `pnpm build` in the layer-validation job.
- Retraction: a preliminary timing taken on an unversioned dirty local tree
  (including a locally modified `package.json`) did not reproduce at the committed
  revision and was retracted; the committed-revision numbers above supersede it.
- Outcome: docs-only evidence on branch `docs/qa-perf-baseline-2026-11-19`;
  follow-up proposals recorded in the BACKLOG entry (turbo `inputs`, CI cache,
  wallet-pwa module-import-cost investigation, demo environment hosting
  decision). No code changed, no pilot/release gate moves.

---

### Moved from STATE.md — 2026-11-20 (DOC-04, #255)

These sections were moved unchanged (only the heading level was lowered) out of `STATE.md`, newest first. They are history, not current state. Merged work since 2026-10-14 is also listed one line per pull request in [`CHANGELOG.md`](../CHANGELOG.md).

#### Recent additions (2026-10-25 — discrete-core merged)
- **`@askmi/discrete-core` (merged to master via PR #189, `f4c0073`, 2026-10-25):** additive zero-runtime-dependency package turning the MCI lecture *Mengen & Abbildungen* (Relation, Mapping, compose, inverse, bijectionWitness) plus miTch guards (`findDuplicateKeys`, `analyzeComposition` with `reducedAt`, `verifyBijectionPair`, `verifyTrustEquivalence`) into fail-closed TypeScript. Branch verification 2026-10-23 at `95f1fe3` (Node 22.22.0, pnpm 9.15.9, Linux, cloud container): package 38/38 tests, `tsc` clean, Prettier clean; full `pnpm build` ok, `pnpm test` 47/47 turbo tasks, `pnpm lint` 12/12 tasks (0 errors; the 7 pre-existing `wallet-pwa` `no-explicit-any` warnings). CI on the PR head is the authoritative re-run for later commits. The PR-audit review points are addressed on the branch (set-compatibility guard in `verifyBijectionPair`, unused generic removed, README wording). Codex review points addressed in `95f1fe3` (presence checks instead of `undefined` sentinels, `surjectivityViolation()` returns `{ element } | null`, SameValueZero element equality). Later branch commits resolved the QA findings F-1–F-5 ([`docs/qa/DISCRETE_CORE_REVIEW_2026-10-23.md`](docs/qa/DISCRETE_CORE_REVIEW_2026-10-23.md)) and snapshot validated inputs (`4e72166`). Master verification 2026-11-02 at `002ce5e` (Node 22.22.0, pnpm 9.15.9, Linux, cloud container): package `build`, `lint` (`tsc --noEmit`) and 45/45 tests green; the full repository suite was not re-run for this docs update. Pure logic library — not wired into wallet/verifier; no release gate is closed by this.
#### Corrective lifecycle slice (2026-10-24 — PR #193, branch only)

- Resolver failures use `ISSUER_RESOLUTION_FAILED` (503) and persist terminal failure; retry requires a fresh session/nonce. The in-memory store atomically checks state and TTL for reads/consume/updates using one clock; no late success/failure can overwrite terminal expiry. Express catches rejected handlers and attempts guarded terminal failure; unavailable storage is explicitly reported as unconfirmed state. Custom stores must adopt the revised guarded update contract. [Scoped evidence](docs/qa/CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md). Human review and head CI remain merge gates; #170 and verifier-demo integration remain open. Audit-gate work is separate under #185.

#### Recent additions (2026-10-23 — ADOPT-1.2-code first `@askmi/connect` slice, branch only)
- **`@askmi/connect` (branch `feat/adopt-1-connect-slice`, PR pending, NOT on master):** first code slice of the accepted ADOPT-1.1/1.2 gates — framework-agnostic core (`createAskMIConnect`, policy registry with exactly `age-liquor-store-v1`, session state machine, crypto-random `askmi_sess_` ids/nonces), `InMemoryAskMIConnectSessionStore` with one-shot consume and TTL cleanup, thin Express adapter (`POST /askmi/connect/sessions`, `.../opened`, `.../presentation`, `GET .../:id`) with the stable ADOPT-1.1 error codes mapped onto the HTTP failure table, and a browser handoff helper — each as subpath exports. Verification wraps the real ADOPT-0 path (`@askmi/oid4vp` `validateSDJWTPresentation` + injected trust-gated issuer key resolver; fail-closed UNTRUSTED_ISSUER when no resolver is configured). `eligible` is a separate policy decision (`age >= 18`), addressing the #170 finding that a validly signed age 12 must not become an eligibility success. The legacy `/wallet-present` `scenarioId` body fails closed as `SIMULATED_ROUTE_REJECTED`. Branch verification 2026-10-23: package build/lint clean, 37/37 tests, full `pnpm test` 47/47 turbo tasks, `pnpm lint` 12/12, `guard:rebrand` green. Not yet integrated into verifier-demo; no release gate closed by this.

#### Recent additions (2026-10-01 — ADOPT-1 planning gates)
- **ADOPT-1.0 accepted:** `docs/tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md` defines the first `@askmi/connect` boundary as relying-party deployed verifier/policy integration. The first implementation slice is intentionally limited to the age/liquor-store profile on the real ADOPT-0a/0b path; AskMI does not issue a new credential, operate as an attestation provider, replace the wallet, or claim EUDI certification.
- **ADOPT-1.1 accepted:** `docs/tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md` defines the minimal verifier-side session contract before code: registered `age-liquor-store-v1` policy, `/askmi/connect/sessions` routes, one-shot session state machine, pluggable session store, stable error codes and negative tests proving the legacy simulated `/wallet-present` route cannot satisfy the real Connect flow.
- **ADOPT-1.2 accepted:** `docs/tasks/ADOPT_1_SDK_API_SHAPE.md` defines the first SDK/API boundary: a new `@askmi/connect` package with framework-agnostic core, `InMemoryAskMIConnectSessionStore`, a thin Express adapter and a browser handoff helper. First code must prove crypto-random session/nonce generation, one-shot consume semantics, negative tests and PII-minimal status responses.
- **Security audit remediation started:** `docs/security/SECURITY_AUDIT_ROADMAP_2026-10-01.md` sequences the audit cleanup into small PRs: first stale code-security PR review (#151/#152), then dependency-alert batches, then evidence-pack freshness and residual hardening.
- **Next gate:** first `@askmi/connect` code slice plus SEC-AUDIT-1 remediation PRs.

#### Recent additions (2026-09-20 — public demo honesty fixes)
- **Demo claims aligned (#154/#155):** the public demo no longer presents a completed DPIA where none is approved; scenario copy is qualified, real organisation names were replaced with fictional names, the nullifier demo uses real SHA-256 with a session seed, and the cost model is a single sourced/assumption-labelled model rather than an unsupported savings headline.
- **Backlog follow-up:** `docs/BACKLOG.md` now tracks DP-01..DP-05 and CL-01..CL-05. DP-01, CL-01 and CL-02 are done; DP-02..DP-05 and CL-03..CL-05 remain open where legal review, DPIA completion, evidence-map updates or doc alignment are still required.
- **Strategy/research intake:** the September EUDI desk audit and use-case landscape are preserved as research inputs, not as certification evidence or an approved delivery backlog. See `docs/DOCS_CANON.md` for their authority status.

#### Recent additions (2026-07-17 — SECURE-2 + ADOPT-0a/0b real credential path, live-verified)
- **SECURE-2 (#134):** internal evidence pack (`@askmi/evidence`) + runnable harness that regenerates the P0/fail-closed proof artifacts on demand.
- **`turbo dev dependsOn ^build` (#133):** dev servers now build their workspace deps first (fixes most stale-dist dev breakage). Residual fixed 2026-10-24 (branch `feat/adopt-1-connect-slice`): the `@askmi/poc-hardened` `pnpm dev` failure (`ERR_MODULE_NOT_FOUND`) was caused by extensionless relative imports in the plain-Node-loaded ESM `dist` of `@askmi/shared-crypto` and `@askmi/revocation-statuslist`; sources now use explicit `.js` extensions and the PoC boots.
- **ADOPT-0a (#135) — real issuance + storage:** issuer-mock issues a real holder-bound `vc+sd-jwt` (`cnf` + `_sd` selective-disclosure digests); wallet stores/retrieves it (`addSdJwtVc`/`getSdJwtVc`). The issuer key is resolved via the **trust list**, a real issuer integration still requires an exact protocol, trust and interoperability check. This replaced fabricated issuance.
- **ADOPT-0b (#136) + e2e fix (#137) — real presentation + verification:** the wallet presents from the **stored** credential with real selective disclosure + KB-JWT; the verifier `/oid4vp-present` resolves the issuer key authoritatively (trust list / JWKS) and decodes the disclosures. #137 fixed two bugs that were unit-green but e2e-broken (verifier ignored disclosures; issuer never issued the requested `age`). Fabrication (ephemeral issuer keys, scenario claims) is gone from the wallet present path; the **circular-verification** gap (verifier trusting a wallet-supplied `issuer_jwk`) is closed.
- **Live verification (2026-07-17):** drove the real HTTP path against fresh current-`master` servers — happy path `200 {age:24}` + consent receipt; attacker-forged trusted `iss` → `403 Signature verification failed`; untrusted `iss` → `403 untrusted_or_unresolvable_issuer`. **Real-facts finding:** 3-day-old zombie dev processes on `:3004`/`:5174` were serving pre-merge code and initially masked everything — always confirm the running process is current before trusting a live demo. `pnpm test` → **47/47 turbo tasks green** (integration package increment 46→47). Evidence: [`docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md`](docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md).

#### Recent additions (2026-07-13 — SECURE-1 gap closure)
- **SECURE-1 sprint closed (branch `feat/secure-1-gap-closure`, 2026-07-13):** 6 fail-closed bugs fixed (F-01 wrong audit key field, F-02 fire-and-forget `savePolicy`, F-03 false-success WebAuthn stub tombstoned, F-04 double fail-open geo-scope, F-16/F-18 swallowed IndexedDB errors); F-14 real SD-JWT VC issuer-sig + KB-JWT verification added to `oid4vp-verifier` (opt-in, fail-closed, `signaturesVerified` field); GAP-3 anti-oracle timing-variance regression guard added (bounded mean-timing spread < 2 ms across 500 iterations, no secret-dependent I/O branch found). 22 findings total: 6 fixed + F-14 + 7 documented-residual + 9 not-a-bug. **Verified 2026-07-13: `pnpm test` → 46/46 turbo tasks green; `pnpm lint` → 0 errors, 7 warnings (all pre-existing `@typescript-eslint/no-explicit-any` in `wallet-pwa`, count unchanged 7→7, zero new warnings from SECURE-1); `pnpm guard:rebrand` → passed.** Per-package during sprint: policy-engine 325, shared-crypto 273, wallet-pwa 185, oid4vp-verifier 63. Threat-model gaps: GAP-2 closed with residual (Shamir SSS recovery was already implemented — ADR-009 entry was stale); GAP-3 mitigated (bounded-variance guard + documented residual — true constant-time unattainable in V8); GAP-1 (browser RAM) and GAP-4 (external review) remain open. Evidence: [`docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md`](docs/qa/SECURE_1_GAP_CLOSURE_2026-07-13.md).

#### Recent additions (since PR #81 → master `c118f93`/PR #116, 2026-06-08 … 2026-06-25)
- **WebAuthn fail-closed + real IdentityKeyGuardian wiring (branch `fix/webauthn-fail-closed`, 2026-07-12):** DecisionCapsule signing now routes through `IdentityKeyGuardian`. If WebAuthn is available but no hardware identity key is registered, the wallet refuses to sign (`HARDWARE_IDENTITY_REQUIRED`) instead of creating a RAM software substitute. Node/test software signing remains available only when WebAuthn is absent and is explicitly marked `SOFTWARE_EPHEMERAL`. Evidence: [`docs/qa/WEBAUTHN_FAIL_CLOSED_2026-07-12.md`](docs/qa/WEBAUTHN_FAIL_CLOSED_2026-07-12.md).
- **Unused-code sweep + honest wiring (branch `chore/wallet-deadcode-sweep`, PR #130, not yet on master):** `credential-pool` selection is wired into presentation after `selectablePresentationCredentials`, narrowing each `poolId` group to the oldest unused member and failing closed on exhaustion; GitHub Pages is decoupled from `@askmi/poc-hardened` via top-level [`site/index.html`](site/) while keeping the PoC as a CI-excluded reference package; evidence-grade citations now point to live packages (`shared-crypto`, `audit-log`, `policy-engine`) instead of the PoC; [`docs/_core/10_KEY_PROTECTION_REALITY.md`](docs/_core/10_KEY_PROTECTION_REALITY.md) records the honest crypto state (no TEE, software WebCrypto runtime, WebAuthn/passkeys as the real hardware seam).
- **G-110.1 handoff truth-alignment (branch `docs/g110-qr-link-closeout`, 2026-07-04):** verifier-demo frontend already rendered QR + "Open in wallet" in `VerifierPanel`; the backlog still marked it open. Added focused coverage so all five scenarios render the dual handoff path with a QR SVG and wallet deeplink carrying `scenario`, `endpoint`, and verifier DID.
- **G-100.4 correlation-id closure (merged via #126, master `da8afce`, 2026-07-04):** `shared-types` defines canonical non-semantic `txn_*` correlation IDs and fallback resolution; OID4VP verifier/request flows and `VerifierSDK` mint them; OID4VP parsing/encoding preserves them; `policy-engine` carries them into `DecisionCapsule`; Wallet audit events (`POLICY_EVALUATED`, `VP_GENERATED`, Proximity `VP_SENT`) group under the same ID; `issuer-mock` mirrors `x-correlation-id` on `/credential` and `/credential/mdoc`. Validation: GitHub required checks green (`Build & Test`, `security`, `CodeQL`, `Layer Protection Validation`, `Dependency Security Audit`), plus local `pnpm run guard:rebrand`, `pnpm lint`, `pnpm test` (46/46 Turbo tasks).
- **S-11 enforcement-layer closure (verified 2026-07-01):** Enforcement and visibility are now aligned for the concrete sensitive demo claims. `layer-resolver` classifies `bloodGroup`, `allergies`, `activeProblems`, `emergencyContacts`, `medication`, `dosageInstruction`, `refillsRemaining`, `role`, and `licenseId` as `VULNERABLE` in the enforcement `LAYER_MAP`; `VISIBILITY_LAYER_MAP` remains the superset for display-only vocabulary. Legitimate Doctor/EHDS/Research/Pharmacy rules now declare `minimumLayer: VULNERABLE`, preserving consent, presence, break-glass, HDAB, geo-scope, and pharmacy flows. Negative regression coverage blocks WELT/default access to `bloodGroup` and Layer-1 access to `licenseId`. Validation: `pnpm --filter @askmi/layer-resolver test`, `pnpm --filter @askmi/policy-engine test`, `pnpm --filter @askmi/integration-tests exec vitest run src/demo-scenarios.test.ts`, `pnpm test` (46/46 Turbo tasks), and `pnpm guard:rebrand` all green.
- **G-140 surfacing follow-up landed (#119 Gap E + #120 Gap D, 2026-06-24):** the visibility complement to the Layer-2 sequence. **#119 (substrate):** sensitivity = a read-only projection of `layer-resolver` (`0/1/2 → low/medium/high`, unmapped → `unclassified`); `WalletService.logDisclosureDecision` records `requested_claim_layers` on every `POLICY_EVALUATED`; `DataFlowService` projects them onto `DataFlowTransaction.claimSensitivity`. At the time, demo vocabulary lived only in a separate `VISIBILITY_LAYER_MAP` superset so visibility could not change enforcement verdicts; that surfaced the S-11 under-protection finding. **#120 (display):** neutral per-claim sensitivity badges in `DataFlowPanel` and the panel promoted from a hidden toggle to a permanent first-class section. Validation: `pnpm test` 46/46 turbo green, `guard:rebrand` green. The S-11 follow-up above closes the former open side-finding by promoting the concrete sensitive claims into enforcement and adding explicit Layer-2 rule opt-ins.
- **Doc truth-alignment + drift cleanup (2026-06-20/21):** H-10 pass merged (#110) correcting the master pointer and the G-130.1 ✅-vs-⏳ contradiction; EU-boundaries/Layer-2 foundation merged (#109, docs 08/09 + decisions 1&2); dependabot (#108); the four-window dev launcher consolidated into `dev-demo.ps1` with the `VERIFIER_BACKEND_PORT=3004` proxy fix (#106, duplicate `start-4-servers.ps1` removed).
- **G-140 / Layer-2 Visibility sequence closed (#112, #114, #115, #116):** `WalletService.evaluateRequest()` logs a neutral, PII-minimal `POLICY_EVALUATED` audit event on every verdict (ALLOW/PROMPT/DENY) carrying raw `requested_claims`, `authorized_claims`, `denied_claims`, verdict, and reason codes (#112). `DataFlowService` reads those events so DENY and over-asking transactions are visible and honest against the verifier's raw request (#114). Proximity mdoc `VP_SENT` events carry `decision_id`, `verifier_did`, `claims_requested`, and `claims_shared`, so offline presentations group into Layer-2 transactions (#115). Proximity mdoc now routes through policy before disclosure; the demo reader `did:askmi:proximity-reader` is limited to `given_name` + `family_name`, over-asked elements are clipped, and DENY still creates a visible transaction with empty `claims_shared` (#116). Local validation for #116: wallet-pwa 162/162, data-flow 67/67, `pnpm test` 46/46 turbo tasks, `pnpm build` 29/29, `guard:rebrand` green.
- **EPIC G-100 P0-block closed (#98–#102):** EUDI-shaped versioned claim/predicate contract (G-100.2, #98), `asOf`-determinism root-cause fix (G-100.1, #99), `verifier-browser` PoC archived + CI archived-import guard (G-100.6, #100), anti-oracle timing-test de-flaked (G-100.7, #102). Authoritative tracking in [`docs/BACKLOG.md`](docs/BACKLOG.md).
- **Phase-1 Unlinkability / Proof-Randomization sprint (#83–#96):** single-use credential boundary at issuance (#91), batch issuance with ephemeral holder binding (C2, #92), KB-JWT proof-of-possession gate on verifier `/present` (C1, #94), `brainpoolP512r1` (#90), honest single-use DataFlow display (#88/#96), IndexedDB teardown-deadlock fix (#93). BBS+ (U-10–U-13 remainder) remains deferred.
- **G-130.1 Passkey-first onboarding landed (#103, #104):** device-bound passkey = account, durable vault, enforced unlock as default, first-run welcome + explicit Reset escape hatch, user-facing Get/Refresh credential UI. (Updates the Video-Gap epic row that still read ⏳; see BACKLOG note.)
- **"Capsule signature verification failures" RESOLVED (2026-06-18):** root-caused as an incomplete AskMI↔miTch rebrand (DID-namespace + package-scope drift), **not** a crypto defect. `did:mitch`/`@mitch/*` now 0 in `src/`, `guard:rebrand` passes. Verified live: all 4 demo servers up, `POST /wallet-present` returns real disclosed claims for liquor-store/doctor-login/ehds-er/pharmacy and a correct `REVOKED` 403. Evidence: [`docs/qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md`](docs/qa/CAPSULE_SIG_ROOTCAUSE_2026-06-18.md). Standalone 4-window dev launcher `start-4-servers.ps1` added at repo root.
- **Full suite re-verified 2026-06-20:** `pnpm test` → **46/46 turbo test tasks green**. Directly re-run package counts this pass: shared-crypto 266, verifier-sdk 59, integration-tests 54, verifier-demo backend 96.

#### Recent additions (since Session 16, post full-rebrand — 2026-06-05/06)
Scout & Advisor mode: all work landed via reviewed `proposal/*` PRs, no direct commits to `master`. Plan of record: [`docs/EXECUTION_PLAN_epic4-5.md`](docs/EXECUTION_PLAN_epic4-5.md).
- **Identity Firewall MVP — Abschlussreview passed (2026-06-07):** the Sprint 1 MVP (`IDENTITY_ACCESS_DETECTED` audit events, PII-minimal `IdentityFirewallMetadata`, DataFlow `identity` category + badge) survived the rebrand/consolidation and is on `master`, `@askmi`-namespaced. Final review confirmed PII-minimal metadata (sanitized actor labels, no raw identifiers, no new cross-RP correlators), `blocked: false` literal (visibility, not blocking), and **230 green tests** (shared-types 69, data-flow 56, wallet-pwa 105). Enforcement/blocking deferred to a later sprint. See [`docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md`](docs/tasks/SPRINT_01_IDENTITY_FIREWALL.md).
- **Sovereignty Center restored (Epic 2, PR #75):** `SovereigntyCenter.tsx` re-wired into `wallet-pwa` `App.tsx`.
- **Verifier reputation watchdog (Epic 2):** wallet-side watchdog flagging verifier reputation signals.
- **Consent Manager UX polish (Epic 4, PR #77 — UX-09):** authored the missing `consent-manager-panel__*` stylesheet in `wallet.css` against shared design tokens; removed all inline styles; added `ConsentManagerPanel.test.tsx` (10 tests, wallet-pwa 105/105).
- **MCP integration (Epic 5, PRs #78–#80):** `@askmi/mcp-server` `askmi_evaluate_disclosure` wired to the real `policy-engine` (CI-01), stdio smoke validation (#79), and a local evaluation scope loader (#80). Architecture: [`docs/mcp-server-architecture.md`](docs/mcp-server-architecture.md).
- **Accountable audit export model (PR #81):** `policy-engine` audit export schema for accountable disclosure records — [`docs/ops/AUDIT_EXPORT_SCHEMA_V1.md`](docs/ops/AUDIT_EXPORT_SCHEMA_V1.md).
- **ADR-013 (PR #73):** WalletService monolith decomposition strategy — [`docs/03-architecture/mvp/ADR-013_WalletService_Monolith_Decomposition_Strategy.md`](docs/03-architecture/mvp/ADR-013_WalletService_Monolith_Decomposition_Strategy.md).
- **Branch cleanup manifest (PR #74):** recorded 2026-06-06 branch hygiene pass — [`docs/ops/BRANCH_CLEANUP_2026-06-06.md`](docs/ops/BRANCH_CLEANUP_2026-06-06.md).
- **Test-fixture hygiene (PRs #71/#72 — S2-04/S2-05):** centralized scenario claims + a frontend fixture drift guard, and shared StatusList test helpers (no revocation-behavior change).

#### Recent additions (since Session 11)
- **Full AskMI rebrand (2026-06-04, branch `chore/full-askmi-rebrand`):** All active workspace packages, imports, app aliases, demo trust fixtures, local `*.askmi.demo` runtime IDs, and primary `ASKMI_*` environment variables now align on AskMI / `@askmi/*`. Runtime keeps targeted `MITCH_*` compatibility fallbacks where useful. See [`docs/NPM_SCOPE_RENAME_ASKMI.md`](docs/NPM_SCOPE_RENAME_ASKMI.md).
- **Previous npm scope alignment (2026-06-04, PR #66):** PR #66 aligned the first three published npm packages (`@askmi/shared-types`, `@askmi/shared-crypto`, `@askmi/revocation-statuslist`) before the full workspace rebrand.
- **QA evidence surface:** `docs/qa/` contains dated validation records, including `WALLET_RECOVERY_RC_2026-06-04.md` and `MIT-10-demo-evidence.md`. These are evidence records, not general task tracking.
- **Branch/PR Consolidation (2026-05-27):** all 10 open PRs resolved onto `master` and the branch/worktree sprawl cleared (22 → 3 remote branches; only `master`, the active `feat/mitch-ai-guardian`, and audit-retained `claude/relaxed-pike` remain). Stale-base PRs were never merged directly (they would have re-introduced paperclip / reverted recent work) — only their genuine net-new value was salvaged onto clean master: verifier **fail-closed** + no-PII-logging (#34), **Commercial Trust Kit** docs (#35), **B2B use-case modules** + repo-local **agent skills** + **ADR-010** Regulatory-Positioning Boundary (#37), **MCP-server freeze decisions** (#38), a date-coupled **PII-substring test fix** (#36), and the `_tmp_*` ignore rule (#39). Superseded/no-value PRs closed with rationale (#14/#16/#17/#18/#24/#26/#27/#30). Full suite re-verified green on the consolidated master.
- **Repo Hardening & Hygiene:** `master` branch protection live (PR-only + required CI checks + **verified/signed commits** + no force-push/deletion); SSH commit signing configured and verified end-to-end (`verified: true`); **all 17 Dependabot alerts cleared → 0 open**; paperclip orchestrator runtime (a committed 1,895-file PostgreSQL data dir + phantom submodule) purged from `master` tracking and gitignored — docs `PAPERCLIP.md`/`ASKMI_COMPANY.md` retained; pnpm temp stubs (`_tmp_*`) ignored.
- **Certification Readiness Artefacts (E-42):** Created draft `SECURITY_TARGET_CC_READY.md` mapping AskMI security functions to Common Criteria (ISO/IEC 15408) requirements.
- **OID4VCI Batch Issuance (E-41):** Implemented `/batch_credential` endpoint support in `oid4vci` package. Enables parallel issuance of multiple credentials (e.g., PID + EAA) in a single session.
- **EUDI Trust List (TSL) Integration:** `EUDITrustListResolver` implemented in `shared-crypto`, providing dynamic lookup and validation of trusted issuers/verifiers with fail-closed logic. Operational documentation added in `docs/ops/TRUST_ANCHOR_ARCHITECTURE.md`.
- **Compliance Gap Sprint:** Recorded 52/53 internal mapping rows in the June CIR matrix; this was not an assessed compliance percentage. Completed mapping for LoA High (WebAuthn binding), Proximity (ISO 18013-5), GDPR Data Subject Rights, dynamic Trust List (TSL) integration, and Certification-Readiness artefacts. Remaining: formal CC certification.
- **StatusList PoC:** `SDJWTStatusResolver` implemented in `shared-crypto`, wiring the `@askmi/revocation-statuslist` package for live revocation fetch capability.
- **Turbo v2 & Vite 6:** Completed migration of all apps and packages to Turbo v2 and Vite 6, clearing remaining Dependabot alerts.
- **Hardware Binding:** Finalized implementation and documentation (ADR-013) for hardware-bound identity keys, without independently establishing eIDAS LoA High assurance.
- **`@askmi/data-flow`** package: Transaction view — Audit-Entries nach `decision_id` gruppiert, Claims/Lifecycle/Shredding sichtbar (Phase 1).
- **Data Flow transparency in wallet-pwa:** `VP_GENERATED` Audit-Event in `WalletService`; `claimsWithheld` aus `claims_requested` vs. `claims_shared` abgeleitet und im `DataFlowPanel` angezeigt (Phase 2).
- **Plain-language minimization summary:** `summarizeTransaction()` erzeugt verifizierbare Kurz-Zusammenfassungen aus bestehenden `DataFlowTransaction`-Feldern (z. B. bewiesen statt offengelegt, zurückgehaltene Claims, Shredding-Status) — ohne Risk Scoring oder Spekulation (Phase 3).
- **`@askmi/mdoc`** package: CBOR codec, COSE Sign1 ES256, **COSE_Mac0** (HMAC-SHA-256, RFC 9052 §6), ISO 18013-5 types, MSO digest verification, DeviceAuth (Sign1 + Mac0), **vollständige Offline-Verifikation** (`verifyMdocOffline()` — 5-Step fail-closed Pipeline: Issuer Auth, MSO Digests, Validity, DocType, Device Auth), x5chain Zertifikatsextraktion + SPKI-Parser, `decodeMdoc()` für integer-keyed CBOR Maps, DeviceResponse Parser, **ECDH Session Key Derivation** (`deriveSessionMacKey()` — ECDH P-256 + HKDF-SHA-256, ISO 18013-5 §9.1.1.5) — 169 tests; **Wallet-Integration** (`addMdocCredential`, mdoc-Presentation-Path, Demo-mDL-Seed, 3 Integrationstests); **Verifier-Integration**: `verifyMdocPresentation()` in `@askmi/oid4vp-verifier` (base64url DeviceResponse → offline verification → claim extraction, 9 tests), `mso_mdoc` Format in OID4VP-Typen + `MdocConstraints` für Namespace/Element-Filterung; **Hybrid Issuance**: `buildMdocDocument()` Issuance-Pipeline (claims→MSO→COSE_Sign1→CBOR), `mso_mdoc` in OID4VCI-Typen, issuer-mock `POST /credential/mdoc` (mDL, 7 Elements), 13 Builder-Tests inkl. build→verify Roundtrip.
- **brainpoolP512r1 Support (Sprint Kandidat #5, 2026-06-08):** Echte RFC 5639 §3.7 Parameter + SHA-512 in `shared-crypto/src/brainpool.ts` — keygen, sign, verify, ECDH, key export. Pure-JS via `@noble/curves/abstract/weierstrass` (WebCrypto unterstützt Brainpool nicht nativ). 25 Brainpool-Tests gesamt (7 P256r1, 7 P384r1, 7 P512r1, 4 Cross-Curve Isolation).
- **brainpoolP384r1 Support (E-21):** Echte RFC 5639 §3.6 Parameter + SHA-384 in `shared-crypto/src/brainpool.ts` — keygen, sign, verify, ECDH, key export. 16 Brainpool-Tests (7 P256r1, 7 P384r1, 2 Cross-Curve Isolation).
- **PQC Readiness:** `shared-crypto/src/pqc.ts` (ML-DSA, ML-KEM via @noble/post-quantum) + `crypto-agility.ts` (algorithm registry, negotiation)
- **SPRINT_PLAN.md F-01–F-18:** recovery SSS, verifier binding, safe glob, CSP, ci-security — details in [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
- **EUDI Compliance Hardening (E-30–E-33):** CIR 2024/2981 Certification Analysis (`docs/compliance/`); CIR 2024/2982 **Data Erasure (I9)** & **Reporting Mechanism** (WalletService logic + DataFlow UI buttons); 77% (41/53) CIR compliance score.
- **Proximity Presentation (E-50):** `ProximityView` UI + QR Device Engagement (ISO 18013-5) + `WalletService.generateProximityResponse` implemented (Mock transport).
- **Hardware-bound Identity (T-31):** WebAuthn-backed Identity Key implemented in `WalletService` for hardware-authentication exploration; LoA High is not established by this component alone.
- **EHDS Compliance (T-C2, T-C3):** Global Secondary-Use Opt-Out in `PolicyEditor`; Localized medical terms (`CLAIM_DICTIONARY`) for EU-wide patient mobility.
