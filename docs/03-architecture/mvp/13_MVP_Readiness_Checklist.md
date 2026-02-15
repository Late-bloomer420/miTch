# 13 — MVP Readiness Checklist

Use this as the final gate before pilot.

---

## A) Architecture & Policy
- [ ] Policy Schema versioned and frozen for MVP
- [ ] Gate precedence implemented exactly as specified
- [ ] All ambiguity/missing field paths fail closed
- [ ] Deny reason codes complete and documented

## B) Crypto & Proofs
- [ ] Proof stack selected and documented per predicate class
- [ ] Sign/verify behavior deterministic across environments
- [ ] Audience/nonce/expiry binding enforced
- [ ] Replay and context-swap tests pass

## C) Privacy & PII Boundary
- [ ] No raw PII stored in verification services
- [ ] Logs contain no stable cross-RP identifiers
- [ ] Retention matrix enforced in runtime
- [ ] Pairwise separation strategy verified

## D) Integrations
- [ ] One issuer integration operational
- [ ] Two RP integrations operational
- [ ] API schemas versioned and published
- [ ] RP can integrate from docs + examples only

## E) Security & Delivery
- [ ] Dependencies pinned and scanned
- [ ] SBOM generated for release
- [ ] Release artifacts signed/provenance tracked
- [ ] Secrets management and env segregation validated

## F) Reliability & Ops
- [ ] SLO/SLI defined for verification paths
- [ ] p50/p95 latency measured and acceptable
- [ ] Incident response playbook available
- [ ] Key compromise and rotation playbooks tested

## G) Governance & Honesty
- [ ] No unimplemented TEE/attestation/security claims in docs/code
- [ ] Residual risk documented clearly
- [ ] Go/No-Go decision recorded with owners

---

## Recommended Minimum Targets
- Verification success rate >= 99% in controlled pilot tests
- Deterministic deny behavior in 100% of malformed request tests
- Replay attack success rate = 0 in defined adversarial suite
- Zero raw-PII findings in verifier logs during pilot dry-runs
