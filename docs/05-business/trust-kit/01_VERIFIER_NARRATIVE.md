# Verifier Narrative — Proof, Not PII

> **GTM-01** · One-page narrative for relying parties · Date: 2026-05-25
> Lead message: **Prove only what is needed.**

## The problem you have

To stay compliant — age gates, KYC, professional-registry checks — you are pushed to collect
identity data. The moment you store it, you own a **PII honeypot**: a GDPR liability, a breach target,
and a cost center. Most "privacy" offerings answer this with a policy promise. A promise does not
survive a database compromise.

## What miTch does

miTch sits **between the wallet and the verifier** and mediates the proof instead of the data.

- The user's real identity attributes stay **local to their wallet** (edge-first).
- When you need a check, miTch helps produce a **scoped cryptographic proof** — e.g. *"holder is over
  18"* — instead of a birth date.
- The proof travels over **ephemeral keys**; after the transaction, residual material is
  **crypto-shredded** so there is structurally less to leak.
- Every disclosure decision is **auditable** and bound to a `DecisionCapsule` (`verdict`,
  `decision_id`, `policy_hash`).

The verifier gets the **minimum proof required**. Raw data stays out of the request path.

## The three states you can always see

For each request the wallet surfaces: **requested → allowed → withheld**. The user (and your audit
trail) can see exactly what was asked for, what was released, and what was held back.

## What makes this different

- **Data minimization by construction** — enforced by the policy engine and protocol, not only by a
  contract clause.
- **Fail-closed** — ambiguous, malformed, or unsafe-downgrade requests resolve to **DENY**, never to a
  silent ALLOW. (See the technical appendix for the reason-code contract.)
- **Zero identity custody** — miTch does not store, consolidate, or broker identity data on a central
  server. It is blind to the contents of the proofs it mediates.

## What miTch is *not* (boundaries)

- It is **not** an identity provider or a data broker.
- It does **not** provide browser-wide tracking enforcement; protections are **wallet-scoped**.
- It is **not** certified. It is **readiness-mapped** against eIDAS 2.0 / EUDI and GDPR Art. 25.
  See the [security sign-off](04_SECURITY_SIGNOFF.md) and [compliance evidence index](03_COMPLIANCE_EVIDENCE_INDEX.md).

## Current pilot scope

The frozen pilot scenario is **age verification (18+)** only. Everything else (health/EHDS,
professional licensing, proximity/offline mDL) is on the roadmap with partial implementation — treat
it as direction, not delivered product, until the evidence index marks it `✅`.

## What to do next

Open the live demo and watch the requested/allowed/withheld flow:
**https://late-bloomer420.github.io/miTch/**

Then read the [technical appendix](02_TECHNICAL_APPENDIX.md) for the integration contract.
