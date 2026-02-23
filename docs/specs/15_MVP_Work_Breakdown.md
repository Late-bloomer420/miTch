# 15 — MVP Work Breakdown (Epics → Tasks → Owners → Estimates)

Stand: 2026-02-11

## E1 — Policy Runtime (Core)
- Define policy schema v0 freeze (Owner: Architecture, Est: 1d)
- Implement deterministic evaluator (Owner: Backend, Est: 3d)
- Implement deny reason catalog and mapping (Owner: Backend, Est: 1d)
- Add migration/version compatibility checks (Owner: Backend, Est: 1d)

## E2 — Binding & Replay Defense
- Canonical request hash function + test vectors (Owner: Security Eng, Est: 2d)
- Nonce store with TTL + replay rules (Owner: Platform, Est: 2d)
- Audience/expiry/clock-skew validator (Owner: Backend, Est: 1d)
- Adversarial replay/context-swap tests (Owner: QA/Security, Est: 2d)

## E3 — Key Management (Wallet/Device)
- Key lifecycle implementation (generate/use/rotate/destroy) (Owner: Wallet Eng, Est: 3d)
- OS keystore integration baseline (Owner: Wallet Eng, Est: 2d)
- Local disclosure receipt trail (Owner: Wallet Eng, Est: 2d)

## E4 — Issuer + Verifier Integration
- Issuer adapter (real or high-fidelity simulator) (Owner: Integrations, Est: 4d)
- Verifier API v1 schemas + validation (Owner: Backend, Est: 2d)
- Revocation/status strategy implementation (Owner: Integrations, Est: 2d)

## E5 — RP Enablement
- RP API docs + quickstart (Owner: DevRel, Est: 2d)
- Reference RP client (Owner: SDK, Est: 3d)
- Integrate RP #1 and RP #2 (Owner: Integrations, Est: 4d)

## E6 — Privacy/Logging Controls
- Log redaction policy in code (Owner: Privacy Eng, Est: 2d)
- Retention matrix enforcement hooks (Owner: Platform, Est: 2d)
- Stable-ID/linkability lint checks (Owner: Privacy Eng, Est: 2d)

## E7 — Security Delivery & Ops
- CI security gates + dependency scan (Owner: DevSecOps, Est: 2d)
- SBOM generation + artifact signing (Owner: DevSecOps, Est: 2d)
- Incident and key-compromise runbooks (Owner: Ops/Security, Est: 2d)

## E8 — Test Evidence & Pilot Gate
- E2E test suite (Owner: QA, Est: 3d)
- Performance baseline (p50/p95) (Owner: QA/Platform, Est: 2d)
- MVP readiness checklist review (Owner: PM + Security + Architecture, Est: 1d)

---

## Suggested RACI (compact)
- **Accountable:** PM + Architecture Lead
- **Responsible:** Domain owners above
- **Consulted:** Privacy/Legal, Security
- **Informed:** Pilot partners, stakeholders

---

## Critical Path
E1 → E2 → E4 → E5 → E8

Any delay in E1/E2 propagates directly to pilot readiness.
