# miTch — Use Case → Code Map

> Links product use cases to implementation packages. Updated 2026-03-12.

| Use Case                            | Status                     | Key Packages                                                          | Docs                                 |
| ----------------------------------- | -------------------------- | --------------------------------------------------------------------- | ------------------------------------ |
| Age Verification (18+)              | ✅ Demo + Tests            | policy-engine, predicates, shared-crypto, demo-liquor-store           | docs/DEMO_SCRIPT.md                  |
| Student Discount (Innsbruck)        | ✅ Demo                    | predicates, policy-engine                                             | docs/modules/student-discount-ibk.md |
| Ad-Tech Blind Provider              | ✅ Types + Nullifier + SDK | predicates, verifier-sdk, wallet-core, shared-types                   | memory: mitch-adtech-\*.md           |
| Social Login Privacy                | ✅ Demo + Spec             | shared-crypto (pairwise DID), policy-engine                           | docs/modules/social-login-privacy.md |
| EHDS Health Data                    | ✅ Demo + Break-Glass      | webauthn-verifier, policy-engine, audit-log                           | docs/00-welt/48*EHDS*\*.md           |
| Phone Number Verification (mi.call) | 📋 Concept only            | —                                                                     | docs/00-welt/application_domains.md  |
| E2E Wallet ↔ Verifier Flow          | ⚠️ Apps exist, not wired   | wallet-pwa, verifier-demo, issuer-mock, oid4vp, oid4vci, verifier-sdk | —                                    |
| Daily Review UX                     | 📋 Vision only             | —                                                                     | docs/vision/UX_DAILY_REVIEW.md       |
| Local Insight Engine                | 📋 Vision only (Layer 2)   | —                                                                     | docs/vision/VISION_CORE.md           |
| ZK Proof Layer                      | 📋 Vision only (Layer 3)   | —                                                                     | docs/vision/VISION_CORE.md           |
| Post-Quantum Crypto                 | ✅ Implemented             | shared-crypto (pqc.ts)                                                | docs/specs/93*PQ_Readiness*\*.md     |
| Ski Pass / Einheimischentarif       | 📋 Concept                 | —                                                                     | docs/vision/OUTREACH_INNSBRUCK.md    |
| Housing / Tenant Verification       | 📋 Concept                 | —                                                                     | docs/vision/OUTREACH_INNSBRUCK.md    |

## B2B / Enterprise Use Cases

> Verifier-side (relying party pays). See `docs/b2b-use-cases/README.md`.

| Use Case                       | Status     | Key Packages                                                                                        | Docs                                                     |
| ------------------------------ | ---------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Fintech / Reusable KYC         | 📋 Concept | policy-engine, predicates, verifier-sdk, oid4vci, revocation-statuslist, audit-log                  | docs/b2b-use-cases/01_module_fintech_kyc.md              |
| iGaming Compliance             | 📋 Concept | policy-engine (rate-limiter, proof-fatigue), webauthn-verifier, revocation-statuslist, verifier-sdk | docs/b2b-use-cases/02_module_igaming_compliance.md       |
| Supply Chain / B2B Credentials | 📋 Concept | policy-engine (jurisdiction), mdoc, anchor-service, oid4vci, verifier-sdk                           | docs/b2b-use-cases/03_module_supply_chain_credentials.md |
| Healthcare / EHDS Mediation    | 📋 Concept | policy-engine, webauthn-verifier, predicates (nullifier), audit-log, anchor-service                 | docs/b2b-use-cases/04_module_healthcare_ehds.md          |

## Package Coverage by Use Case

| Package               | Use Cases Served                                                          |
| --------------------- | ------------------------------------------------------------------------- |
| policy-engine         | ALL (core)                                                                |
| shared-crypto         | ALL (core)                                                                |
| predicates            | Age, Student, Ad-Tech, Social Login, Fintech, iGaming, Supply Chain, EHDS |
| oid4vp / oid4vci      | E2E Flow, Fintech, Supply Chain                                           |
| verifier-sdk          | Ad-Tech, E2E Flow, Fintech, iGaming, Supply Chain, Healthcare (all B2B)   |
| wallet-core           | Ad-Tech (CRDT sync)                                                       |
| audit-log             | EHDS, Daily Review (future), Fintech, iGaming, Supply Chain               |
| webauthn-verifier     | EHDS Break-Glass, iGaming step-up, Healthcare                             |
| revocation-statuslist | Fintech, iGaming (self-exclusion), Supply Chain, Healthcare               |
| mdoc                  | Supply Chain (ISO 18013-5 site access)                                    |
| anchor-service        | Audit anchoring, Supply Chain, Healthcare                                 |
| poc-hardened          | Standalone demo (all use cases)                                           |
