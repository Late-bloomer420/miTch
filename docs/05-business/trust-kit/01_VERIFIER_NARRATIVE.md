# Verifier Narrative — Purpose-bound disclosure and evidence

> **GTM-01** · One-page narrative for relying parties · Date: 2026-05-25
> Lead message: **Prove only what is needed.**

## The problem you have

To stay compliant — age gates, KYC, professional-registry checks — you are pushed to collect
identity data. The moment you store it, you own a **PII honeypot**: a GDPR liability, a breach target,
and a cost center. Most "privacy" offerings answer this with a policy promise. A promise does not
survive a database compromise.

## What miTch does

miTch sits **between the wallet and the verifier** and mediates the proof instead of the data.

- The design starts at the wallet edge and releases only the profile-selected attributes or proofs.
- The target age recipe is a **scoped age result**. The real SD-JWT reference path currently releases numeric age; a locally signed predicate is not an issuer-authenticated ZK derivation.
- The proof travels over **ephemeral keys**; applicable controlled buffers/keys are cleaned up. Stored-SD-JWT single-use integration remains #171; verifier retention is separate.
- Every disclosure decision is **auditable** and bound to a `DecisionCapsule` (`verdict`,
  `decision_id`, `policy_hash`).

The policy aims to minimise disclosure for the transaction. Original-request and application eligibility/scope enforcement on the real SD-JWT demo route remains #170.

## The three states you can always see

For each request the wallet surfaces: **requested → allowed → withheld**. The user (and your audit
trail) can see exactly what was asked for, what was released, and what was held back.

## What makes this different

- **Data minimization by construction** — implemented in policy/selection components; enforcement must also be integrated at the chosen protocol/application boundary.
- **Fail-closed** — ambiguous, malformed, or unsafe-downgrade requests resolve to **DENY**, never to a
  silent ALLOW. (See the technical appendix for the reason-code contract.)
- **Zero identity custody** — miTch does not store, consolidate, or broker identity data on a central
  server. Disclosed values can reach an RP-deployed verifier; custody and retention depend on that deployment.

## What miTch is *not* (boundaries)

- It is **not** an identity provider or a data broker.
- It does **not** provide browser-wide tracking enforcement; protections are **wallet-scoped**.
- It is **not** certified. It is **readiness-mapped** against eIDAS 2.0 / EUDI and GDPR Art. 25.
  See the [security sign-off](04_SECURITY_SIGNOFF.md) and [compliance evidence index](03_COMPLIANCE_EVIDENCE_INDEX.md).

## Current pilot scope

The frozen pilot scenario is **age verification (18+)** only. Everything else (health/EHDS,
professional licensing, proximity/offline mDL) is on the roadmap with partial implementation — treat
it as direction, not delivered product, until the selected path has its own integration and applicable external evidence.

## What to do next

Open the live demo and watch the requested/allowed/withheld flow:
**https://late-bloomer420.github.io/miTch/**

Then read the [technical appendix](02_TECHNICAL_APPENDIX.md) for the integration contract.

## Evidence for this offer

The detailed component links in the [claim map](../marketing/06-claim-evidence-map.md) and existing trust-kit appendix remain useful. [Dated observations](../../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) qualify overlapping integration claims only. The DACH hospitality offer remains a buyer hypothesis under #142/#143; G0/G1 are not closed by these documentation changes.
