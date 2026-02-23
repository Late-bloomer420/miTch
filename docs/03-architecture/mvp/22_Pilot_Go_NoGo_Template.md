# 22 — Pilot Go/No-Go Template

Stand: 2026-02-11

Use this template for formal pilot readiness review.

---

## A) Review Metadata
- Date:
- Review chair:
- Participants:
- Scope (issuer/RPs/predicates):
- Build/commit reference:

---

## B) Gate Results (Pass/Fail)

### Security
- [ ] Replay/context-swap suite passed
- [ ] Critical vulnerabilities resolved or risk-accepted
- [ ] Key compromise runbook validated

### Privacy
- [ ] No raw PII in verifier logs
- [ ] No stable cross-RP identifiers persisted
- [ ] Retention matrix controls validated

### Policy Correctness
- [ ] Fail-closed tests pass
- [ ] Deny reason code mapping deterministic
- [ ] Gate precedence validated

### Integration
- [ ] Issuer integration stable
- [ ] RP #1 integrated and accepted
- [ ] RP #2 integrated and accepted

### Reliability
- [ ] p50/p95 latency within target
- [ ] Error budget acceptable
- [ ] Incident response path tested

---

## C) Residual Risks
- Risk ID:
- Description:
- Owner:
- Mitigation status:
- Accepted until:

---

## D) Decision
- [ ] GO
- [ ] NO-GO
- [ ] GO with constraints

Constraints/Conditions:

---

## E) Sign-Off
- Product:
- Architecture:
- Security:
- Privacy/Compliance:
- Operations:
