# 16 — MVP Architecture Decision Log (ADR Index)

Stand: 2026-02-11

Use this file as the canonical decision register for all MVP-relevant architecture choices.
Each ADR must include: Context, Decision, Alternatives, Consequences, Owner, Date, Status.

---

## ADR-001 — Credential/Proof Stack for MVP
- **Status:** Proposed
- **Context:** Multiple candidate stacks (e.g., SD-JWT VC, BBS+, circuit-based proofs).
- **Decision (to finalize):** Select one primary stack for MVP predicates + one fallback.
- **Owner:** Architecture Lead
- **Acceptance evidence:** Interop test vectors + verifier implementation notes.

## ADR-002 — Policy Manifest Schema v0
- **Status:** Accepted
- **Context:** Need deterministic policy evaluation and versioning.
- **Decision:** Freeze schema v0 with strict validation and explicit deny reason codes.
- **Owner:** Backend Lead
- **Consequences:** Future changes require migration strategy and compatibility testing.

## ADR-003 — Gate Precedence Enforcement
- **Status:** Accepted
- **Context:** Avoid expensive checks before cheap rejection and prevent fail-open behavior.
- **Decision:** Enforce order: rate-limit → schema → binding → policy → crypto verify → WORM receipt.
- **Owner:** Security + Backend
- **Consequences:** Any bypass path is a release blocker.

## ADR-004 — Request Canonicalization + Binding
- **Status:** Proposed
- **Context:** Replay/context swap risks without stable canonical hashing and audience binding.
- **Decision (to finalize):** Define canonicalization algorithm and required bound fields (nonce, audience, expiry, requestHash).
- **Owner:** Security Engineering
- **Acceptance evidence:** Cross-implementation test vectors.

## ADR-005 — Key Protection Level Claims
- **Status:** Accepted
- **Context:** Prevent misleading TEE/attestation claims in Phase 0/MVP.
- **Decision:** Default protection level is software-backed unless hardware attestation is real and independently verifiable.
- **Owner:** Security Lead
- **Consequences:** Documentation and marketing must match implementation truth.

## ADR-006 — Revocation/Status Strategy
- **Status:** Proposed
- **Context:** Need status checks with minimal correlation leakage.
- **Decision (to finalize):** Select status architecture and degraded-mode deny rules.
- **Owner:** Integrations Lead
- **Acceptance evidence:** Privacy review + outage behavior tests.

## ADR-007 — Logging & Retention Policy
- **Status:** Accepted
- **Context:** Metadata can re-identify users even if payloads are minimized.
- **Decision:** No raw PII in verifier logs; no stable cross-RP identifiers; retention matrix enforced by field class.
- **Owner:** Privacy Engineering
- **Consequences:** Violations are compliance/security blockers.

## ADR-008 — RP Integration Contract v0
- **Status:** Proposed
- **Context:** External RPs need deterministic schemas and error semantics.
- **Decision (to finalize):** Publish `17_API_Contract_v0.md` as normative v0 contract.
- **Owner:** API/Platform Lead
- **Acceptance evidence:** Two independent RP integrations pass without custom exceptions.

---

## ADR Template

```markdown
### ADR-XXX — Title
- Status: Proposed | Accepted | Superseded | Rejected
- Date: YYYY-MM-DD
- Owner:

Context:

Decision:

Alternatives considered:

Consequences:

Evidence / validation:

Follow-ups:
```
