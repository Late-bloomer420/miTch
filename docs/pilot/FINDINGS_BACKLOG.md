# Findings Backlog

| ID | Priority | Owner | Description | Acceptance test |
|---|---|---|---|---|
| AI-01 | P0 ✅ CLOSED | Security Engineering | Block insecure `did:web:localhost` resolution by default in production parity. | `src/packages/shared-crypto/test/did.test.ts` contains `DENY: did:web localhost is blocked by default`. |
| AI-05 | P0 ✅ CLOSED | Protocol Engineering | Ensure capability/risk negotiation does not silently allow unsafe revocation posture. | `src/packages/policy-engine/src/__tests__/capability-negotiation.test.ts` denies security-critical mismatch and downgrade attempts. |
| AI-06 | P0 ✅ CLOSED | Crypto Platform | Remove legacy default mock fallback from `resolveDID()` path. | `src/packages/shared-crypto/test/did.test.ts` contains `DENY: legacy resolveDID no longer allows mock fallback`. |
| AI-02 | P1 ✅ CLOSED | Crypto Platform | Clarify WebAuthn timeout reason-code policy (`PRESENCE_REQUIRED` vs `REAUTH_REQUIRED`). | `src/packages/policy-engine/src/__tests__/webauthn-reason-map.test.ts` — 8 deterministic mapping tests passing (CHALLENGE_EXPIRED→PRESENCE_REQUIRED, CHALLENGE_NOT_FOUND→REAUTH_REQUIRED, etc.). |
| AI-04 | P1 ✅ CLOSED | Crypto Platform | Define final audit export schema for external auditor handoff. | `src/packages/policy-engine/src/__tests__/audit-export-schema.test.ts` — 19 schema-validation tests passing; schema spec at `docs/ops/AUDIT_EXPORT_SCHEMA_V1.md`. |
| AI-03 | P2 | [UNASSIGNED] | Add explicit scenario for `DENY_POLICY_MISMATCH` in tabletop coverage matrix. | Documentation update references explicit step + test link. |
