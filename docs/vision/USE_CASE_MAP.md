# miTch — Use Case → Code Map

> Links product use cases to implementation packages. Updated 2026-03-12.

| Use Case | Status | Key Packages | Docs |
|---|---|---|---|
| Age Verification (18+) | ✅ Demo + Tests | policy-engine, predicates, shared-crypto, demo-liquor-store | docs/DEMO_SCRIPT.md |
| Student Discount (Innsbruck) | ✅ Demo | predicates, policy-engine | docs/modules/student-discount-ibk.md |
| Ad-Tech Blind Provider | ✅ Types + Nullifier + SDK | predicates, verifier-sdk, wallet-core, shared-types | memory: mitch-adtech-*.md |
| Social Login Privacy | ✅ Demo + Spec | shared-crypto (pairwise DID), policy-engine | docs/modules/social-login-privacy.md |
| EHDS Health Data | ✅ Demo + Break-Glass | webauthn-verifier, policy-engine, audit-log | docs/00-welt/48_EHDS_*.md |
| Phone Number Verification (mi.call) | 📋 Concept only | — | docs/00-welt/application_domains.md |
| E2E Wallet ↔ Verifier Flow | ⚠️ Apps exist, not wired | wallet-pwa, verifier-demo, issuer-mock, oid4vp, oid4vci, verifier-sdk | — |
| Daily Review UX | 📋 Vision only | — | docs/vision/UX_DAILY_REVIEW.md |
| Local Insight Engine | 📋 Vision only (Layer 2) | — | docs/vision/VISION_CORE.md |
| ZK Proof Layer | 📋 Vision only (Layer 3) | — | docs/vision/VISION_CORE.md |
| Post-Quantum Crypto | ✅ Implemented | shared-crypto (pqc.ts) | docs/specs/93_PQ_Readiness_*.md |
| Ski Pass / Einheimischentarif | 📋 Concept | — | docs/vision/OUTREACH_INNSBRUCK.md |
| Housing / Tenant Verification | 📋 Concept | — | docs/vision/OUTREACH_INNSBRUCK.md |

## Package Coverage by Use Case

| Package | Use Cases Served |
|---|---|
| policy-engine | ALL (core) |
| shared-crypto | ALL (core) |
| predicates | Age, Student, Ad-Tech, Social Login |
| oid4vp / oid4vci | E2E Flow |
| verifier-sdk | Ad-Tech, E2E Flow |
| wallet-core | Ad-Tech (CRDT sync) |
| audit-log | EHDS, Daily Review (future) |
| webauthn-verifier | EHDS Break-Glass |
| anchor-service | Audit anchoring |
| poc-hardened | Standalone demo (all use cases) |