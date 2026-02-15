# 27 — ADR Closure Record (MVP v0)

Stand: 2026-02-11

This record closes priority ADRs for MVP execution. Re-open only with explicit change request.

---

## ADR-001 — Credential/Proof Stack for MVP
- **Status:** Accepted
- **Decision:** Primary format `sd-jwt-vc` for MVP; fallback `signed-attribute-attestation` for controlled integrations.
- **Rationale:** Faster ecosystem interoperability and simpler verifier surface for MVP timeline.
- **Constraints:** No cross-RP stable identifiers in proof artifacts.
- **Follow-up:** Re-evaluate BBS+/advanced ZK in post-MVP phase.

## ADR-004 — Canonicalization + Binding
- **Status:** Accepted
- **Decision:** Canonical JSON (sorted keys, UTF-8, NFC), SHA-256 base64url request hash; required binding fields nonce/audience/expiry/requestHash.
- **Rationale:** Deterministic verification and replay resistance with low implementation complexity.
- **Constraints:** Nonce consume must be atomic; clock skew fixed at ±90s for v0.

## ADR-006 — Revocation/Status Strategy
- **Status:** Accepted (MVP baseline)
- **Decision:** Online status check preferred; if unavailable, fail closed for high-risk predicates, configurable constrained grace for low-risk predicates.
- **Rationale:** Preserve trust guarantees while enabling controlled degraded operation.
- **Constraints:** No per-user profiling in status logs; service-level metrics only.

## ADR-008 — RP Integration Contract v0
- **Status:** Accepted
- **Decision:** `17_API_Contract_v0.md` is normative for MVP.
- **Rationale:** Single source for schema, errors, and behavior; reduces integration drift.
- **Constraints:** Backward-incompatible changes require version bump.

---

## Global Notes
- Any exception to fail-closed requires explicit documented approval.
- Security claims must match implemented reality (no unverified TEE/attestation claims).
- This closure record is binding for Sprint 1 implementation scope.
