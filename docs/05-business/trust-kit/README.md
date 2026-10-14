# Commercial Trust Kit

> **Owner:** Compliance & Evidence Lead · **Epic:** MIT-5 (GTM-01 … GTM-04)
> **Status:** Draft for review · **Date:** 2026-05-25
> **Audience:** Verifiers / relying parties evaluating miTch, and their legal and security reviewers.

This kit is the verifier-facing trust package for miTch ("The Forgetting Layer"). It exists so a
relying party can decide whether to integrate miTch **without** trusting marketing copy — every claim
points back to repository evidence, and every gap is named rather than hidden.

## What is in the kit

| # | Document | Answers | Source task |
|---|----------|---------|-------------|
| 1 | [`01_VERIFIER_NARRATIVE.md`](01_VERIFIER_NARRATIVE.md) | Why miTch exists, in one page — "proof, not PII". | GTM-01 |
| 2 | [`02_TECHNICAL_APPENDIX.md`](02_TECHNICAL_APPENDIX.md) | Supported protocols, verifier obligations, failure behavior. | GTM-02 |
| 3 | [`03_COMPLIANCE_EVIDENCE_INDEX.md`](03_COMPLIANCE_EVIDENCE_INDEX.md) | Where the canonical evidence lives, and which gaps need legal review. | GTM-03 |
| 4 | [`04_SECURITY_SIGNOFF.md`](04_SECURITY_SIGNOFF.md) | Whether the public claims overstate security, privacy, or certification status. | GTM-04 |

## Reading order

- **Business / procurement reader:** start with (1), skim (3).
- **Integration engineer:** read (2), then (3) for status flags.
- **Security / legal reviewer:** read (4) first — it lists which claims are approved as-is and which
  require correction before external publication.

## Ground rules for this kit (non-hype contract)

1. **No claim without a pointer.** Every capability claim links to a spec, test, or source file.
2. **Status is explicit.** `✅ implemented`, `🟡 partial`, `🔴 not implemented`, `⚠️ needs legal review`.
3. **Certification ≠ certifiability.** miTch is *readiness-mapped*, not certified. See (4).
4. **Pilot scope is age verification (18+) only.** Claims outside that scope are roadmap, not product.

## Canonical evidence (single source of truth)

- Operational health snapshot: [`STATE.md`](../../../STATE.md)
- P0 closure evidence: [`docs/ops/EVIDENCE_PACK_P0.md`](../../ops/EVIDENCE_PACK_P0.md)
- EUDI / CIR compliance matrix: [`docs/compliance/EUDI_CIR_MATRIX.md`](../../compliance/EUDI_CIR_MATRIX.md)
- Pilot dry run record: [`docs/pilot/PILOT_DRY_RUN_01.md`](../../pilot/PILOT_DRY_RUN_01.md)
- Capability negotiation spec: [`docs/protocol/CAP_NEGOTIATION_V1.md`](../../protocol/CAP_NEGOTIATION_V1.md)
- Documentation authority map: [`docs/DOCS_CANON.md`](../../DOCS_CANON.md)

> If any statement in this kit conflicts with `STATE.md` or the Evidence Pack, **the canonical source
> wins** and this kit must be corrected.
