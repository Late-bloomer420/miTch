# AskMI verifier narrative — intended value and current evidence

AskMI's hypothesis is purpose-bound identity request governance: a relying party should request only the attributes justified
by its declared workflow, and receive an explainable, evidence-linked result.

The repository provides policy, selective-disclosure, audit and reference integration components. That is implementation work,
not proof of an end-to-end released product. The real SD-JWT demo currently discloses numeric age; its HTTP request binding,
eligibility/scope and single-use lifecycle are incomplete (#170/#171). Local predicate signatures are not evidenced ZK derivations.

Audit integrity/schema helpers are implemented, but actual output minimisation/retention/durability and revision-bound evidence
remain #172/#173/F-19. Browser buffer overwrite does not guarantee all process copies or verifier data are erased.

The browser wallet, mock issuer and public site are reference/synthetic demonstrations. AskMI is not certified, production-ready,
an identity provider or an issuer-equivalent attestation service. No LoA High, official-wallet interoperability or compliance percentage is established.

The DACH travel/hospitality governance/evidence offer remains a buyer hypothesis under #142/#143.
G0/G1 are open; no public 20/8/3 tally is evidenced. Discovery/readiness work must not be represented as a live credential pilot.

[Current findings](../../security/REPO_EVIDENCE_STATUS_2026-10-14.md),
[dated evidence](../../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md),
[release roadmap](../../RELEASE_READINESS_ROADMAP.md) and [claim map](../marketing/06-claim-evidence-map.md)
define what may be said today and what still needs proof.
