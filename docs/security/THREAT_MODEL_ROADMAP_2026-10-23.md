# miTch STRIDE × LINDDUN — Security Roadmap (2026-10-23)

**Status: planned, not security-proven.** Audited baseline: `624cf9af919fe58a7cba34a05b316b17e49c7e0f` (15 October 2026). Verify each finding against current HEAD before claiming current exploitability or closure.

## Boundary and invariant
Wallet TB-W is the privacy boundary; verifier TB-S is separately responsible for session integrity. Verifier requests are hostile input, even when signed. Before sending, enforce:
`Claims(serializedPresentation) ⊆ Claims(request) ∩ Claims(policy) ∩ Claims(consent) ∩ Claims(authenticatedRPAuthorization)`.
Bind immutable canonical request hash, RP identity, purpose, scope, consent and expiry. Any ambiguity → DENY. No centralized identity storage, tracking, blockchain identity dependency or asset custody.

## P0 — Enforcement (release blocker)
- #170: server-owned nonce/state/client_id/audience/requestHash, eligibility independent of cryptographic validity, atomic session consumption.
- #180: mandatory wallet disclosure PEP; actual serialized bytes checked immediately before transmission.
- #181: adversarial malicious-RP suite; fail closed on parser/PDP/trust errors, mutation after consent, excess claims, replay and cross-session mixup.
**Exit:** all negative tests pass on pinned commit and the wallet never sends unauthorized claims. Until then, privacy-first policy enforcement = **NOT PROVEN**.

## P1 — Privacy
- #171: atomic single-use reserve/consume, concurrency, retry and honest cleanup receipts.
- #182 and #97: issuer-authenticated age predicate, no numeric age or DOB in age-only profile; document SD-JWT linkability and ZKP limitations.
- #183: RP authentication and EUDI registered-attribute checks; strict subset or DENY.
- #184, #172, #173: encrypted user-controlled local audit, no raw VP/SD-JWT/PII in centralized telemetry, purpose-bound evidence.
- #186: XSS/process-compromise threat analysis and key isolation.
**Exit:** single-use cannot double-present; no stable correlators claimed absent without evidence; trust and privacy regressions pass.

## P2 — Assurance
- #185: CI audit exit-code gates; commit/runtime/test ID/command/artifact hash; SBOM, signed provenance, OpenID4VP/VCI+HAIP conformance, official-wallet interop, independent pentest.
**Exit:** independently inspectable evidence; OpenID conformance must not be described as EUDI certification.

## STRIDE × LINDDUN register
T-01 request substitution (#180/#181); T-02 RP spoofing (#183); T-03 replay (#170); T-04 excess disclosure (#180); T-05 PEP bypass (#180); T-06 numeric age (#182); T-07 linkability (#171/#182); T-08 single-use race (#171); T-09 audit tracking (#184); T-10 key compromise (#186); T-11 fail-open (#181); T-12 consent mismatch (#180/#181).

## Governance and limits
Four-eyes review for wallet PEP, OID4VP, session store, crypto, policy and CI; verify branch protection. A DecisionCapsule signature is defense in depth, not protection against compromised browser process. Pre-disclosure enforcement cannot guarantee post-disclosure erasure by a malicious RP. Preserve evidence per source; never substitute an unscoped repository pointer for test artifacts.

Sources: user-supplied `deep-research-report.md` and `WHAT_MITCH_IS_NOT.md`; prior issues #170/#171/#97 and PR #174.
