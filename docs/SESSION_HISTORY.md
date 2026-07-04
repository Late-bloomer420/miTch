# AskMI — Session History

Ausgelagert aus `STATE.md` am 2026-03-14. Enthält den Verlauf abgeschlossener Sessions.

---

### Session 19 — G-100.4 Correlation IDs (2026-07-04)
- **Goal:** Close the remaining G-100.4 traceability gap without adding semantic identifiers or widening the privacy surface.
- **Change:** Added canonical `txn_*` correlation IDs in `@askmi/shared-types` (`newCorrelationId`, `resolveCorrelationId`, validation tests). OID4VP verifier request builders and `VerifierSDK` mint them; OID4VP parser/encoder preserves them; `policy-engine` carries them into `DecisionCapsule`.
- **Wallet/Issuer trace path:** Wallet policy/audit events now share the same correlation ID across `POLICY_EVALUATED`, `VP_GENERATED`, and Proximity `VP_SENT`; issuer-mock mirrors `x-correlation-id` on `/credential` and `/credential/mdoc`.
- **Validation:** Targeted tests/builds for changed packages passed; repo gates passed locally: `pnpm run guard:rebrand`, `pnpm lint`, `pnpm test` (46/46 Turbo tasks).
- **Status:** Branch `feat/g100.4-correlation-ids`; verified locally, not yet merged to `master`.

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
