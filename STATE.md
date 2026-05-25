# STATE.md — Current Operating State

> **Rolle:** Operativer Health-Snapshot — was läuft, was ist deployed, was ist der aktuelle technische Zustand.
> Für Task-Tracking (was ist erledigt, was ist offen) siehe [`docs/BACKLOG.md`](docs/BACKLOG.md).

**Date:** 2026-05-25
**Branch:** `master` (default)
**Release tag:** `eudi-pilot-certified-ready`
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
- Security Target (CC): [`docs/compliance/SECURITY_TARGET_CC_READY.md`](docs/compliance/SECURITY_TARGET_CC_READY.md)

## Pilot path (frozen for execution)

- **Minimal scenario:** Altersverifikation (18+) only.
- Purpose: keep pilot scope narrow and avoid parallel drift across multiple use-cases.

## Current status

### Operational Health
- **Tests:** 44/44 turbo tasks pass; 1664 individual tests (28 packages); 169/169 mdoc tests; 226/226 shared-crypto tests; 73/73 wallet-pwa tests; 52/52 oid4vp-verifier tests; 35/35 oid4vci tests
- **Lint:** 0 errors, 0 warnings
- **Compliance Score:** 100% (53/53 requirements ✅)
- **Live Demo Flow:** `pnpm dev` → Verifier (3004) + Wallet (5174) → `/authorize` → consent → `/wallet-present` → SD-JWT VC + KB-JWT validated → disclosedClaims in UI
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)
- **Demo Scenarios:** 5 clickable scenarios incl. Revoked Credential flow

### Recent additions (since Session 11)
- **Repo Hardening & Hygiene:** `master` branch protection live (PR-only + required CI checks + **verified/signed commits** + no force-push/deletion); SSH commit signing configured and verified end-to-end (`verified: true`); **all 17 Dependabot alerts cleared → 0 open**; paperclip orchestrator runtime (a committed 1,895-file PostgreSQL data dir + phantom submodule) purged from `master` tracking and gitignored — docs `PAPERCLIP.md`/`MITCH_COMPANY.md` retained; pnpm temp stubs (`_tmp_*`) ignored.
- **Certification Readiness Artefacts (E-42):** Created formal `SECURITY_TARGET_CC_READY.md` mapping miTch security functions to Common Criteria (ISO/IEC 15408) requirements.
- **OID4VCI Batch Issuance (E-41):** Implemented `/batch_credential` endpoint support in `oid4vci` package. Enables parallel issuance of multiple credentials (e.g., PID + EAA) in a single session.
- **EUDI Trust List (TSL) Integration:** `EUDITrustListResolver` implemented in `shared-crypto`, providing dynamic lookup and validation of trusted issuers/verifiers with fail-closed logic. Operational documentation added in `docs/ops/TRUST_ANCHOR_ARCHITECTURE.md`.
- **Compliance Gap Sprint:** Achieved 100% EUDI CIR coverage. Completed mapping for LoA High (WebAuthn binding), Proximity (ISO 18013-5), GDPR Data Subject Rights, and formal Certification Readiness.
- **StatusList PoC:** `SDJWTStatusResolver` implemented in `shared-crypto`, wiring the `@mitch/revocation-statuslist` package for live revocation fetch capability.
- **Turbo v2 & Vite 6:** Completed migration of all apps and packages to Turbo v2 and Vite 6, clearing remaining Dependabot alerts.
- **Hardware Binding:** Finalized implementation and documentation (ADR-013) for hardware-bound identity keys, satisfying eIDAS LoA High requirements.
- **`@mitch/data-flow`** package: Transaction view — Audit-Entries nach `decision_id` gruppiert, Claims/Lifecycle/Shredding sichtbar (Phase 1).
- **Data Flow transparency in wallet-pwa:** `VP_GENERATED` Audit-Event in `WalletService`; `claimsWithheld` aus `claims_requested` vs. `claims_shared` abgeleitet und im `DataFlowPanel` angezeigt (Phase 2).
- **Plain-language minimization summary:** `summarizeTransaction()` erzeugt verifizierbare Kurz-Zusammenfassungen aus bestehenden `DataFlowTransaction`-Feldern (z. B. bewiesen statt offengelegt, zurückgehaltene Claims, Shredding-Status) — ohne Risk Scoring oder Spekulation (Phase 3).
- **`@mitch/mdoc`** package: CBOR codec, COSE Sign1 ES256, **COSE_Mac0** (HMAC-SHA-256, RFC 9052 §6), ISO 18013-5 types, MSO digest verification, DeviceAuth (Sign1 + Mac0), **vollständige Offline-Verifikation** (`verifyMdocOffline()` — 5-Step fail-closed Pipeline: Issuer Auth, MSO Digests, Validity, DocType, Device Auth), x5chain Zertifikatsextraktion + SPKI-Parser, `decodeMdoc()` für integer-keyed CBOR Maps, DeviceResponse Parser, **ECDH Session Key Derivation** (`deriveSessionMacKey()` — ECDH P-256 + HKDF-SHA-256, ISO 18013-5 §9.1.1.5) — 169 tests; **Wallet-Integration** (`addMdocCredential`, mdoc-Presentation-Path, Demo-mDL-Seed, 3 Integrationstests); **Verifier-Integration**: `verifyMdocPresentation()` in `@mitch/oid4vp-verifier` (base64url DeviceResponse → offline verification → claim extraction, 9 tests), `mso_mdoc` Format in OID4VP-Typen + `MdocConstraints` für Namespace/Element-Filterung; **Hybrid Issuance**: `buildMdocDocument()` Issuance-Pipeline (claims→MSO→COSE_Sign1→CBOR), `mso_mdoc` in OID4VCI-Typen, issuer-mock `POST /credential/mdoc` (mDL, 7 Elements), 13 Builder-Tests inkl. build→verify Roundtrip.
- **brainpoolP384r1 Support (E-21):** Echte RFC 5639 §3.6 Parameter + SHA-384 in `shared-crypto/src/brainpool.ts` — keygen, sign, verify, ECDH, key export. 16 Brainpool-Tests (7 P256r1, 7 P384r1, 2 Cross-Curve Isolation).
- **PQC Readiness:** `shared-crypto/src/pqc.ts` (ML-DSA, ML-KEM via @noble/post-quantum) + `crypto-agility.ts` (algorithm registry, negotiation)
- **SPRINT_PLAN.md F-01–F-18:** recovery SSS, verifier binding, safe glob, CSP, ci-security — details in [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
- **EUDI Compliance Hardening (E-30–E-33):** CIR 2024/2981 Certification Analysis (`docs/compliance/`); CIR 2024/2982 **Data Erasure (I9)** & **Reporting Mechanism** (WalletService logic + DataFlow UI buttons); 77% (41/53) CIR compliance score.
- **Proximity Presentation (E-50):** `ProximityView` UI + QR Device Engagement (ISO 18013-5) + `WalletService.generateProximityResponse` implemented (Mock transport).
- **Hardware-bound Identity (T-31):** WebAuthn-backed Identity Key implemented in `WalletService` for LoA High compliance.
- **EHDS Compliance (T-C2, T-C3):** Global Secondary-Use Opt-Out in `PolicyEditor`; Localized medical terms (`CLAIM_DICTIONARY`) for EU-wide patient mobility.

### Completion Summary
Phase 0–1 complete, Phase 2–3 (Hardening) 94% functionally covered. miTch is technically ready for the EUDI Wallet Pilot Phase.
Detailliertes Task-Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
