# STATE.md — Current Operating State

> **Rolle:** Operativer Health-Snapshot — was läuft, was ist deployed, was ist der aktuelle technische Zustand.
> Für Task-Tracking (was ist erledigt, was ist offen) siehe [`docs/BACKLOG.md`](docs/BACKLOG.md).

**Date:** 2026-06-04
**Branch:** `chore/full-askmi-rebrand`
**Release tag:** `v1.0-RC (Pilot Readiness)`
**Repo:** `https://github.com/Late-bloomer420/miTch.git`
**Current master:** `8d8735b` (PR #69 merged)

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

## Pilot path (v1.0-RC Stable)

- **Minimal scenario:** Altersverifikation (18+) via OID4VP.
- **Status:** Release Candidate achieved. All core stabilization and refactoring phases complete.

## Current status

### Operational Health
- **GitHub Actions:** Post-merge `master` checks for PR #66 passed on 2026-06-04: ci-security, Deploy GitHub Pages, AskMI CI/CD Pipeline, and CodeQL.
- **Tests:** Full suite evidence remains 45/45 turbo tasks and 1820+ individual tests from the 2026-06-04 wallet recovery RC QA record. PR #66 additionally re-ran targeted package tests for the npm scope alignment (`revocation-statuslist`, `shared-crypto`, `audit-log`, `policy-engine`) before merge.
- **Lint:** Last recorded repo-level lint gate passed in the 2026-06-04 QA evidence. Older notes mention a non-blocking verifier frontend `any` warning; treat exact lint-warning count as evidence-specific until next full local sweep.
- **Compliance Score:** 100% Technical (52/53 CIR requirements ✅; 1 partial 🟡 — formal CC certification, see [`EUDI_CIR_MATRIX.md`](docs/compliance/EUDI_CIR_MATRIX.md))
- **Live Demo Flow:** `pnpm dev` → Verifier (3004) + Wallet (5174) → `/authorize` → Passkey Unlock → `/notify-scan` → consent → `/oid4vp-present` → SD-JWT VC + KB-JWT validated → Visual Rendering via SVG/Mustache (verified integrity)
- **Containerization:** All services (Wallet, Issuer, Verifier) fully Dockerized with multi-stage builds. Verified via `scripts/verify-deployment.ps1`.
- **Reverse Proxy:** Caddy-based routing with TLS termination configured for `*.askmi.demo` domains.
- **Visual Branding:** W3C VC-Render support enabled; dynamic credential cards with SVG templates.
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)

### Recent additions (since Session 11)
- **Full AskMI rebrand (2026-06-04, branch `chore/full-askmi-rebrand`):** All active workspace packages, imports, app aliases, demo trust fixtures, local `*.askmi.demo` runtime IDs, and primary `ASKMI_*` environment variables now align on AskMI / `@askmi/*`. Runtime keeps targeted `MITCH_*` compatibility fallbacks where useful. See [`docs/NPM_SCOPE_RENAME_ASKMI.md`](docs/NPM_SCOPE_RENAME_ASKMI.md).
- **Previous npm scope alignment (2026-06-04, PR #66):** PR #66 aligned the first three published npm packages (`@askmi/shared-types`, `@askmi/shared-crypto`, `@askmi/revocation-statuslist`) before the full workspace rebrand.
- **QA evidence surface:** `docs/qa/` contains dated validation records, including `WALLET_RECOVERY_RC_2026-06-04.md` and `MIT-10-demo-evidence.md`. These are evidence records, not general task tracking.
- **Branch/PR Consolidation (2026-05-27):** all 10 open PRs resolved onto `master` and the branch/worktree sprawl cleared (22 → 3 remote branches; only `master`, the active `feat/mitch-ai-guardian`, and audit-retained `claude/relaxed-pike` remain). Stale-base PRs were never merged directly (they would have re-introduced paperclip / reverted recent work) — only their genuine net-new value was salvaged onto clean master: verifier **fail-closed** + no-PII-logging (#34), **Commercial Trust Kit** docs (#35), **B2B use-case modules** + repo-local **agent skills** + **ADR-010** Regulatory-Positioning Boundary (#37), **MCP-server freeze decisions** (#38), a date-coupled **PII-substring test fix** (#36), and the `_tmp_*` ignore rule (#39). Superseded/no-value PRs closed with rationale (#14/#16/#17/#18/#24/#26/#27/#30). Full suite re-verified green on the consolidated master.
- **Repo Hardening & Hygiene:** `master` branch protection live (PR-only + required CI checks + **verified/signed commits** + no force-push/deletion); SSH commit signing configured and verified end-to-end (`verified: true`); **all 17 Dependabot alerts cleared → 0 open**; paperclip orchestrator runtime (a committed 1,895-file PostgreSQL data dir + phantom submodule) purged from `master` tracking and gitignored — docs `PAPERCLIP.md`/`ASKMI_COMPANY.md` retained; pnpm temp stubs (`_tmp_*`) ignored.
- **Certification Readiness Artefacts (E-42):** Created formal `SECURITY_TARGET_CC_READY.md` mapping AskMI security functions to Common Criteria (ISO/IEC 15408) requirements.
- **OID4VCI Batch Issuance (E-41):** Implemented `/batch_credential` endpoint support in `oid4vci` package. Enables parallel issuance of multiple credentials (e.g., PID + EAA) in a single session.
- **EUDI Trust List (TSL) Integration:** `EUDITrustListResolver` implemented in `shared-crypto`, providing dynamic lookup and validation of trusted issuers/verifiers with fail-closed logic. Operational documentation added in `docs/ops/TRUST_ANCHOR_ARCHITECTURE.md`.
- **Compliance Gap Sprint:** Reached 98% EUDI CIR coverage (52/53). Completed mapping for LoA High (WebAuthn binding), Proximity (ISO 18013-5), GDPR Data Subject Rights, dynamic Trust List (TSL) integration, and Certification-Readiness artefacts. Remaining: formal CC certification.
- **StatusList PoC:** `SDJWTStatusResolver` implemented in `shared-crypto`, wiring the `@askmi/revocation-statuslist` package for live revocation fetch capability.
- **Turbo v2 & Vite 6:** Completed migration of all apps and packages to Turbo v2 and Vite 6, clearing remaining Dependabot alerts.
- **Hardware Binding:** Finalized implementation and documentation (ADR-013) for hardware-bound identity keys, satisfying eIDAS LoA High requirements.
- **`@askmi/data-flow`** package: Transaction view — Audit-Entries nach `decision_id` gruppiert, Claims/Lifecycle/Shredding sichtbar (Phase 1).
- **Data Flow transparency in wallet-pwa:** `VP_GENERATED` Audit-Event in `WalletService`; `claimsWithheld` aus `claims_requested` vs. `claims_shared` abgeleitet und im `DataFlowPanel` angezeigt (Phase 2).
- **Plain-language minimization summary:** `summarizeTransaction()` erzeugt verifizierbare Kurz-Zusammenfassungen aus bestehenden `DataFlowTransaction`-Feldern (z. B. bewiesen statt offengelegt, zurückgehaltene Claims, Shredding-Status) — ohne Risk Scoring oder Spekulation (Phase 3).
- **`@askmi/mdoc`** package: CBOR codec, COSE Sign1 ES256, **COSE_Mac0** (HMAC-SHA-256, RFC 9052 §6), ISO 18013-5 types, MSO digest verification, DeviceAuth (Sign1 + Mac0), **vollständige Offline-Verifikation** (`verifyMdocOffline()` — 5-Step fail-closed Pipeline: Issuer Auth, MSO Digests, Validity, DocType, Device Auth), x5chain Zertifikatsextraktion + SPKI-Parser, `decodeMdoc()` für integer-keyed CBOR Maps, DeviceResponse Parser, **ECDH Session Key Derivation** (`deriveSessionMacKey()` — ECDH P-256 + HKDF-SHA-256, ISO 18013-5 §9.1.1.5) — 169 tests; **Wallet-Integration** (`addMdocCredential`, mdoc-Presentation-Path, Demo-mDL-Seed, 3 Integrationstests); **Verifier-Integration**: `verifyMdocPresentation()` in `@askmi/oid4vp-verifier` (base64url DeviceResponse → offline verification → claim extraction, 9 tests), `mso_mdoc` Format in OID4VP-Typen + `MdocConstraints` für Namespace/Element-Filterung; **Hybrid Issuance**: `buildMdocDocument()` Issuance-Pipeline (claims→MSO→COSE_Sign1→CBOR), `mso_mdoc` in OID4VCI-Typen, issuer-mock `POST /credential/mdoc` (mDL, 7 Elements), 13 Builder-Tests inkl. build→verify Roundtrip.
- **brainpoolP384r1 Support (E-21):** Echte RFC 5639 §3.6 Parameter + SHA-384 in `shared-crypto/src/brainpool.ts` — keygen, sign, verify, ECDH, key export. 16 Brainpool-Tests (7 P256r1, 7 P384r1, 2 Cross-Curve Isolation).
- **PQC Readiness:** `shared-crypto/src/pqc.ts` (ML-DSA, ML-KEM via @noble/post-quantum) + `crypto-agility.ts` (algorithm registry, negotiation)
- **SPRINT_PLAN.md F-01–F-18:** recovery SSS, verifier binding, safe glob, CSP, ci-security — details in [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
- **EUDI Compliance Hardening (E-30–E-33):** CIR 2024/2981 Certification Analysis (`docs/compliance/`); CIR 2024/2982 **Data Erasure (I9)** & **Reporting Mechanism** (WalletService logic + DataFlow UI buttons); 77% (41/53) CIR compliance score.
- **Proximity Presentation (E-50):** `ProximityView` UI + QR Device Engagement (ISO 18013-5) + `WalletService.generateProximityResponse` implemented (Mock transport).
- **Hardware-bound Identity (T-31):** WebAuthn-backed Identity Key implemented in `WalletService` for LoA High compliance.
- **EHDS Compliance (T-C2, T-C3):** Global Secondary-Use Opt-Out in `PolicyEditor`; Localized medical terms (`CLAIM_DICTIONARY`) for EU-wide patient mobility.

### Completion Summary
Phase 0–5 complete. AskMI has achieved 98% technical EUDI compliance and is fully containerized for sovereign deployment with a polished visual rendering layer. Technically prepared for formal EUDI evaluation.
Detailliertes Task-Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
