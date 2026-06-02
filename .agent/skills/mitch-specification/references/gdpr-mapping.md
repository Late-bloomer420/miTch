# GDPR Architecture Mapping

Use this as a spec drafting aid. Confirm details against current repo docs and implementation before making legal or compliance claims.

| GDPR principle                     | miTch architectural control                                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Lawfulness, fairness, transparency | PolicyManifest purpose, signed decision artifacts, user-facing consent/prompt surfaces.                  |
| Purpose limitation                 | Predicate requests and policy rules must carry explicit purpose and audience.                            |
| Data minimization                  | Prefer zero-knowledge proofs, predicates, selective disclosure, pairwise DIDs, and ephemeral processing. |
| Accuracy                           | Issuer signatures, credential validity checks, revocation/status checks, and trusted schema validation.  |
| Storage limitation                 | Wallet custody, minimized disclosure to the verifier (less data exists to retain), TTLs, crypto-shredding, secure storage deletion semantics. miTch cannot enforce what a verifier does out-of-band; it minimizes what the verifier receives. |
| Integrity and confidentiality      | AES-GCM/JWE, signature verification, WebAuthn/step-up auth, nonce and presentation binding.              |
| Accountability                     | Audit logs, evidence packs, deny reason codes, DecisionCapsule `policy_hash`, reproducible tests.        |

## Article 25 Checks

Every spec should state:

- Which raw data is avoided entirely.
- Which actor holds custody.
- Which values are ephemeral.
- Which storage is encrypted.
- Which unknown states fail closed.
- Which evidence proves the behavior without creating a shadow profile.

## Data Subject Rights

Avoid server-side copies by design. When a component must store something, document:

- access path,
- correction path,
- erasure or crypto-shredding path,
- retention period,
- audit evidence retained after erasure.
