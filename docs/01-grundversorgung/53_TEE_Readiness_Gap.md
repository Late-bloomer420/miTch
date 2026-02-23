# 53 — TEE Readiness Gap (Policy Engine)

Stand: 2026-02-11

## Current state
- No production TEE integration in policy execution path.
- Current posture is software-based controls + cryptographic verification + fail-closed gates.

## Gap to true TEE-backed assurance
1. Hardware-backed runtime for policy evaluation
2. Remote attestation verification in verifier flow
3. Key-binding to attested runtime identity
4. Attestation failure handling (deny-biased)
5. Operational lifecycle: attestation cert rotation, revocation, monitoring

## Risks while gap exists
- Client-side execution environment remains potentially tamperable.
- Security claims must remain explicit: software-only unless attestation is real and verified.

## Near-term mitigation (before TEE)
- Signed policy manifests
- Server-side re-validation
- Tamper-evident audit chain + `/audit/verify`
- Human review requirements on security-critical changes

## Decision rule
Do not market/claim TEE-grade guarantees until attestation checks are implemented and tested end-to-end.
