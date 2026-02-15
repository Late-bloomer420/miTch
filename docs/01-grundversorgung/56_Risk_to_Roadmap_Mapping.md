# 56 — Risk-to-Roadmap Mapping

Stand: 2026-02-11

## Purpose
Translate expanded external findings into concrete roadmap placement.

| Risk Theme | Target Phase | Owner | Artifact / Deliverable |
|---|---|---|---|
| Supply chain compromise | Phase 6 | DevSecOps | Dependency policy + SBOM + scanner gates |
| Revocation at scale | Phase 6-7 | Backend/Security | Status architecture + tests + SLA behavior |
| GDPR legal opinion | Pre-pilot | Product/Legal | External legal memo + role mapping |
| Backdoor pressure strategy | Phase 7 | Leadership/Legal | Security statement + jurisdiction strategy |
| Issuer trust inflation | Phase 8 | Governance/Product | Issuer metadata/reputation framework |
| Verifier exclusion/cartel risk | Phase 8 | Governance/Product | Verifier transparency + compatibility policy |
| DID resolver integrity | Phase 7 | Platform/Security | Multi-resolver design doc |
| Quantum readiness | Phase 7+ | Crypto/Security | Crypto agility plan + migration protocol |
| Jurisdiction conflict | Phase 8 | Policy/Legal | Jurisdiction policy profiles |
| Accessibility-security balance | Phase 7+ | Product/UX/Sec | Accessibility security testing protocol |

## Immediate “do now” list
1. Start legal opinion process (scoping + advisor shortlist).
2. Add dependency/SBOM gate to CI (if not already active).
3. Write revocation baseline implementation ticket for next sprint.
4. Publish conservative crypto-shredding language in public docs.
