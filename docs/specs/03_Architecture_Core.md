# Architecture Core (Conceptual)

## Actors
- **User Device (miTch Wallet + Policy Engine)**: root of trust; holds user keys; enforces policy; generates proofs.
- **Issuer / State Provider**: authoritative source of base identity (passport, national eID, licenses).
- **Requester / Relying Party (RP)**: service that needs specific assurance (age, residency, license, etc.).
- **Verifier Components** (at RP or independent): verify signatures / proofs; validate credential status.

## Components (on user device)
1. **Policy Manifest**
   - Structured policy describing allowed predicates, request formats, and gate precedence.
2. **Proof Builder**
   - Produces derived proofs: ZK predicates, selective disclosure, signed attestations.
3. **Binding Layer**
   - Binds proofs to request context (e.g., request hash / nonce / audience).
4. **Key Guardian (honest)**
   - Manages ephemeral keys; no claims of hardware enclaves unless actually present & verified.
5. **Local Audit Trail (optional)**
   - A user-visible, locally stored record of what was shared and why.

## Server-side components (allowed, limited)
- **Verification API**
  - Verifies proof validity and policy compliance.
  - Does not store raw PII.
- **WORM logging**
  - Logs decision receipts, not identity attributes.
- **Rate Limiting**
  - Protects verification endpoints from DoS without needing user profiles.

## “Honesty check”
- Do not claim TEE/attestation if not implemented and independently verifiable.
- Security posture must be explicit about what is software-only vs hardware-backed.
