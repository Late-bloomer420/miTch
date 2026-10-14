# AskMI security-target draft — assessment input, not assurance

**Qualified:** 2026-10-14. This file is a draft engineering description, not an accredited Common Criteria security target,
evaluated TOE, EAL4+ readiness determination, LoA High claim or certification result.

## Intended security objectives and current boundaries

| Objective | Existing component | Evidence limit / open work |
|---|---|---|
| User/key presence | WebAuthn / IdentityKeyGuardian | Platform/config-dependent; no certified wallet-security assurance |
| Credential integrity | ECDSA / SD-JWT / COSE helpers | Internal primitive tests; exact official-profile matrix unvalidated |
| Storage confidentiality | SecureStorage AES-GCM | Local encrypted storage; not whole-process/backup assurance |
| Request minimisation | Policy + selective disclosure | Active HTTP eligibility/scope incomplete (#170) |
| Unlinkability | Pairwise DIDs + legacy B+C pool | Stored-SD-JWT reuse (#171), F-20 and network/issuer correlation remain |
| Revocation / trust | Status-list and JSON trust prototypes | Exact signer/profile/freshness/ETSI deployment requirements remain open |
| Audit | Hash-chain and Tier-2 schema helpers | Sink/retention/durability (#172/F-19) not universally enforced |

## Assurance work still required

Define the TOE and trust boundary, selected role/profile, assumptions and threat model;
trace requirements to exact code/tests; commission independent review and applicable evaluation;
record vulnerability findings, operational controls and conformance artifacts.
Repository-controlled test runs are internal testing, not independent ATE evidence.
TypeScript interfaces and package separation do not prove runtime isolation against malicious code.

[Current register](../security/REPO_EVIDENCE_STATUS_2026-10-14.md), [requirement traceability](EUDI_CIR_MATRIX.md),
[roadmap](../RELEASE_READINESS_ROADMAP.md), GAP-1/GAP-4 and #170–#173 govern current gaps.
No statement here closes those gates.
