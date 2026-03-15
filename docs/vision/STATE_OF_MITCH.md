# State of miTch — March 2026

> What's built, what's next, what's vision.

## Layer 1: The Forgetting Layer ✅ BUILT

| Component | Status | Evidence |
|---|---|---|
| Policy Engine (fail-closed, 31+ deny codes) | ✅ Production-ready | 1411 tests, 0 false allows |
| SD-JWT VC + Selective Disclosure | ✅ Implemented | shared-crypto |
| OID4VP / OID4VCI / SIOPv2 / DPoP / HAIP | ✅ Implemented | oid4vp, oid4vci |
| AES-256-GCM encrypted storage | ✅ Implemented | secure-storage |
| HKDF Pairwise DIDs (unlinkability) | ✅ Implemented | shared-crypto |
| Crypto-shredding (ephemeral keys) | ✅ Implemented | shared-crypto |
| WORM Audit Log | ✅ Implemented | audit-log |
| Merkle Batch Anchoring | ✅ Implemented | anchor-service |
| WebAuthn Step-Up Auth | ✅ Implemented | webauthn-verifier |
| Post-Quantum Readiness (ML-DSA, ML-KEM) | ✅ Implemented | shared-crypto/pqc.ts |
| StatusList2021 Revocation | ✅ Implemented | revocation-statuslist |
| Nullifier-based Sybil Protection | ✅ Implemented | predicates |

## Layer 2: Local Insight Engine ❌ NOT STARTED

The vision (VISION_CORE.md) describes local-only computation — same model classes as institutions, running on device. iPhone 16 / Pixel 9 are capable. No code exists yet.

Prerequisite: E2E flow must work first (data must flow into the wallet before insight can be computed on it).

## Layer 3: ZK Proof Layer ❌ NOT STARTED

Bulletproofs range proofs for specific claims. Research horizon. PQC readiness (Layer 1) is a stepping stone.

## Infrastructure

| Component | Status |
|---|---|
| CI/CD (GitHub Actions) | ✅ 4/4 green |
| Test Coverage | ⚠️ ~50-65% (P0 gaps being closed) |
| Standalone Demo (GitHub Pages) | ✅ Live |
| 26 packages + 3 apps | ✅ All building |
| CIR Compliance | 82% |
| Audit Findings | ✅ All closed (F-01 to F-18) |

## What's Next (Priority Order)

1. **Test Coverage → 80%** (Claude working on it now)
2. **E2E Flow** — wire wallet-pwa ↔ verifier-demo as real OID4VP flow
3. **Phase 6 Refactoring** — WalletService decomposition (docs/REFACTORING_ROADMAP.md)
4. **Daily Review MVP** — minimum viable UX in wallet-pwa
5. **Innsbruck Pilot** — first real partner conversation

## Vision vs. Reality Gap

| Vision Doc | Code Reality |
|---|---|
| WHY_USERS_CARE (Daily Review) | No UI yet — audit-log exists but no daily review UX |
| PLATFORM_ECOSYSTEM (Plugin Modules) | No module system — monorepo packages only |
| SHADOW_PROFILES (AI Act Explanations) | No implementation — concept only |
| OUTREACH_INNSBRUCK (Partner Conversations) | No conversations started yet |
| REGULATORY_CALENDAR (Go-to-Market) | Regulations are live — miTch isn't deployed yet |