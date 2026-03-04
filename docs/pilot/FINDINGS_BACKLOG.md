# Findings Backlog

| ID | Priority | Owner | Description | Acceptance test |
|---|---|---|---|---|
| AI-01 | P0 | Security Engineering | Block insecure `did:web:localhost` resolution by default in production parity. | `src/packages/shared-crypto/test/did.test.ts` contains `DENY: did:web localhost is blocked by default`. |
| AI-05 | P0 | Protocol Engineering | Ensure capability/risk negotiation does not silently allow unsafe revocation posture. | `src/packages/policy-engine/src/__tests__/capability-negotiation.test.ts` denies security-critical mismatch and downgrade attempts. |
| AI-06 | P0 | Crypto Platform | Remove legacy default mock fallback from `resolveDID()` path. | `src/packages/shared-crypto/test/did.test.ts` contains `DENY: legacy resolveDID no longer allows mock fallback`. |
| AI-02 | P1 | [UNASSIGNED] | Clarify WebAuthn timeout reason-code policy (`PRESENCE_REQUIRED` vs `REAUTH_REQUIRED`). | Add deterministic mapping test once product/security decision is approved. |
| AI-04 | P1 | [UNASSIGNED] | Define final audit export schema for external auditor handoff. | Add schema-validation tests for export payload after schema is approved. |
| AI-03 | P2 | [UNASSIGNED] | Add explicit scenario for `DENY_POLICY_MISMATCH` in tabletop coverage matrix. | Documentation update references explicit step + test link. |
