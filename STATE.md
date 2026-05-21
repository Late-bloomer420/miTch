# STATE.md — Current Operating State

> **Rolle:** Operativer Health-Snapshot — was läuft, was ist deployed, was ist der aktuelle technische Zustand.
> Für Task-Tracking (was ist erledigt, was ist offen) siehe [`docs/BACKLOG.md`](docs/BACKLOG.md).

**Date:** 2026-05-16
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
- **Tests:** 43/43 turbo tasks pass; 1618 individual tests (26 packages); 169/169 mdoc tests; 218/218 shared-crypto tests; 73/73 wallet-pwa tests; 52/52 oid4vp-verifier tests
- **Lint:** 0 errors, 0 warnings
- **Audit:** 7 npm vulnerabilities (4 high, 3 moderate — `undici` ≥7.0.0 <7.24.0, `flatted` <3.4.0; alle in devDependency-Ketten)
- **Live Demo Flow:** `pnpm dev` → Verifier (3004) + Wallet (5173) → `/authorize` → consent → `/wallet-present` → SD-JWT VC + KB-JWT validated → disclosedClaims in UI
- **Live Demo:** https://late-bloomer420.github.io/miTch/ (GitHub Pages, self-contained HTML)
- **Demo Scenarios:** 5 clickable scenarios incl. Revoked Credential flow

### Recent additions (since Session 10+)
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
Alle P0 + P1 Gaps geschlossen. Phase 0–1 complete, Phase 2–3 teilweise.
Detailliertes Task-Tracking mit Einzel-IDs: [`docs/BACKLOG.md`](docs/BACKLOG.md)

---

## Session History

Vollständiger Verlauf abgeschlossener Sessions: [`docs/SESSION_HISTORY.md`](docs/SESSION_HISTORY.md)
