# Compliance Gap Report — May 2026

> **Correction 2026-10-27 (issue #235):** the original version of this report claimed 100% (53/53) CIR coverage, "fully compliant for LoA High", and "technically ready for the EUDI Wallet Pilot Phase". Those claims violated the vocabulary rule in `docs/MATURITY_AND_LIMITATIONS.md` §3 (no "fully compliant" / readiness percentages without a named external authority and evidence) and contradicted the accepted product boundary (`docs/tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md`: AskMI does not claim EUDI certification). The original was archived at `archive/COMPLIANCE_GAP_REPORT_MAY_2026_ORIGINAL.md`. This version restates the facts within their honest scope.

**Status:** superseded summary — the canonical per-requirement mapping is [`EUDI_CIR_MATRIX.md`](EUDI_CIR_MATRIX.md); the canonical maturity statement is [`docs/MATURITY_AND_LIMITATIONS.md`](../MATURITY_AND_LIMITATIONS.md); the canonical regulatory-role statement is [`docs/04-legal/REGULATORY_ROLE_MAP.md`](../04-legal/REGULATORY_ROLE_MAP.md).

## What is actually true

- **Internally mapped requirements:** the CIR matrix records repository component implementations for the requirements it maps. This is an internal engineering mapping, not a conformance decision, certification, or objective readiness score.
- **No external validation:** no independent security audit, certification, conformance decision, or notified-body evaluation exists for AskMI as a whole (`docs/MATURITY_AND_LIMITATIONS.md`).
- **No LoA High claim:** LoA High requires certified WSCA/WSCD-grade key protection. AskMI's honest hardware state is a software WebCrypto runtime with WebAuthn/passkeys as the real hardware seam; no TEE/WSCD is used (`docs/_core/10_KEY_PROTECTION_REALITY.md`). The earlier claim that WebAuthn binding "satisfies" LoA High is withdrawn.
- **Boundary:** AskMI is not an EUDI Wallet Solution and does not claim EUDI certification; `wallet-pwa` is a reference harness. Which CIRs apply at all depends on role — see the [Regulatory Role Map](../04-legal/REGULATORY_ROLE_MAP.md).
- **Demo scope:** trust-list/issuer interoperability evidence comes from `issuer-mock`, `verifier-demo` and local trust material. This does not establish interoperability with national EUDI Wallets, production issuers, or relying parties.

## Known open gaps (non-exhaustive)

- Formal external evaluation (Common Criteria / accredited CAB) — not started; no EUDI certification is claimed or implied.
- CIR 2024/2983 (verification of qualified attestations) — unmapped in this repository.
- WRPRC / RP registration / intended-use certificates — not implemented (Wave-2 gap, `docs/eudi/EUDI_SOURCE_BASELINE.md`).
- Hosted AskMI-as-intermediary — deferred by ADOPT-1.0; a new role decision is required before such a product shape ships.

## Reading rule

Compliance documents in this repository are engineering analyses, not legal advice or proof of compliance (§3, `docs/MATURITY_AND_LIMITATIONS.md`). Historical coverage percentages from the original report must not be quoted as readiness scores.

---
*Original report: 2026-05-25 (archived) · Correction: 2026-10-27, issue #235*
