# Privacy Firewall Axioms

## 1. Non-Existence

Data that does not exist cannot be leaked.

- If a feature can be implemented with a proof or predicate, prefer the proof or predicate over raw attributes.
- Raw PII is toxic. Storing or transmitting it requires an explicit documented basis, minimization rationale, and protection.

## 2. User Sovereignty

The wallet is the primary custodian of user identity material.

- Private keys must not leave the device except through a deliberately designed, encrypted recovery path.
- Avoid central profiles and stable cross-context identifiers.

## 3. Fail-Closed

Uncertainty is a threat.

- `UNKNOWN` must stop the flow.
- Implicit ALLOW is forbidden.
- Any parser, resolver, verifier, policy, revocation, or storage ambiguity must resolve to DENY or a hard error unless a stricter documented rule exists.

## 4. Explicit Intent

Nothing should happen by accident.

- Permissions, scopes, purposes, and audiences must be exact.
- "Improve UX" is not a legal basis for collecting or sharing personal data.

## 5. Audit Without Leakage

Evidence should prove control behavior without reconstructing the user.

- Audit records should use hashes, reason codes, policy hashes, timestamps, and signed decision artifacts.
- Audit logs must not become a shadow identity database.
