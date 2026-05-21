# DecisionCapsule Model

`DecisionCapsule` is deterministic audit evidence for policy-engine decisions. It proves that a decision occurred and records why, while minimizing privacy risk.

## What it captures

- Decision metadata (`capsuleId`, `decisionId`, `policyId`, `policyVersion`, `requestId`, `timestamp`)
- Outcome metadata (`verdict`, `responseMode`)
- Policy reasoning (`reasonCodes`, `deniedClaims`, optional predicate disclosure references)
- Deterministic references and hashes (`verifierRef`, `inputHash`, `policyHash`)
- Explicit storage guardrails (`rawClaimsStored: false`, `proofMaterialStored: false`)

## What it deliberately avoids

The capsule and hashed input representation do **not** store:

- Raw requested claim values
- Credential values (including raw birthdate)
- Full verifier DID
- Raw nonce values
- Full audience DID
- Proof or token material

## Model intent and limits

The DecisionCapsule model is a precursor for tamper-evident append-only audit logging. By itself, it is **not** a WORM log implementation and **not** a cryptographic proof system.
