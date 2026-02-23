# 12 — MVP Execution Plan (6 Weeks)

Stand: 2026-02-11  
Planning assumption: small core team, concept artifacts already available.

---

## Week 1 — Lock Technical Decisions

## Goals
- Freeze proof/credential stack for MVP predicates
- Freeze policy schema v0 and deny semantics
- Freeze request canonicalization inputs

## Deliverables
- Proof Strategy Matrix (final choices)
- Policy Schema v0 + deny reason taxonomy
- Canonical Request Hash Spec v1

## Exit Criteria
- Architecture review decision log approved
- No unresolved blocker in stack selection

---

## Week 2 — Build Deterministic Policy Runtime

## Goals
- Implement policy evaluator and strict gate precedence
- Implement fail-closed defaults everywhere

## Deliverables
- Evaluator runtime (schema validate → binding validate → policy evaluate)
- Deny reason codes in all rejection paths
- Initial unit and regression tests

## Exit Criteria
- Regression suite green for missing/unknown/ambiguous cases

---

## Week 3 — Binding + Replay Defense + Key Lifecycle

## Goals
- Make replay/context swap practically unworkable
- Implement key lifecycle baseline

## Deliverables
- Nonce/TTL store and replay checks
- Audience/expiry enforcement + clock skew policy
- Key generation/use/rotation/destruction paths

## Exit Criteria
- Adversarial replay test pack passes

---

## Week 4 — Issuer Integration + Verifier API

## Goals
- Integrate one issuer-like source and one verifier endpoint
- Provide strict RP request/response contract

## Deliverables
- Issuer adapter (real or high-fidelity simulator)
- Verifier API with versioned schema
- Status/revocation check strategy (privacy-preserving)

## Exit Criteria
- One E2E flow fully operational (issuer → wallet → verifier)

---

## Week 5 — RP Integration + Privacy/Logging Hardening

## Goals
- Onboard 2 RPs with minimal handholding
- Harden metadata/logging controls

## Deliverables
- RP reference integration package
- Logging minimization and retention controls
- Pairwise identity separation checks

## Exit Criteria
- Both RPs integrated and passing acceptance tests

---

## Week 6 — Pilot Readiness Evidence Pack

## Goals
- Prove readiness with measurable evidence
- Prepare go/no-go decision

## Deliverables
- E2E + adversarial + performance test report
- Security posture summary (software-only vs hardware-backed claims)
- Incident and compromise playbooks
- MVP readiness checklist completed

## Exit Criteria
- Go/No-Go review completed and signed

---

## Cross-Cutting Workstreams (run every week)

- **Security:** dependency scan, supply chain checks, secret hygiene
- **Privacy:** linkability review, logging discipline, data retention checks
- **Quality:** test automation + deterministic outcomes
- **Documentation:** update specs with implementation truth

---

## Risks and Mitigations

- **Risk:** proof stack indecision delays everything  
  **Mitigation:** timebox decision in Week 1 with explicit trade-off acceptance.

- **Risk:** replay defense complexity underestimated  
  **Mitigation:** adversarial tests from Week 2 onward, not at end.

- **Risk:** RP integration friction  
  **Mitigation:** strict schemas + example client + error code docs.

- **Risk:** privacy leaks via metadata/logs  
  **Mitigation:** formal retention matrix + identifier linting in CI.
