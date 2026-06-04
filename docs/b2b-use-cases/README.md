# B2B / Enterprise Use Cases

Stand: 2026-05-23

This directory documents miTch's **business-to-business** use cases — where the paying customer
is a **verifier / relying party** (a bank, operator, buyer, or hospital), not an end consumer.
Each vertical has two documents:

- a **business case** (concise positioning, ICP, monetization, KPI — mirrors
  `docs/specs/33_Business_Case_01_Age_Verification.md`), and
- a **module spec** (deep integration design — mirrors `docs/modules/student-discount-ibk.md`).

All four verticals reuse the same core: a verifier requests a **predicate**, the wallet returns a
signed `DecisionProofPayload` (booleans + binding, no PII), and the relying party verifies it with
`@askmi/verifier-sdk`. The differentiator is the same across every vertical: **the customer's
breach surface shrinks instead of growing, because the verifier never holds the underlying data.**

> Status: all four are **concept / design** documents (verifier-side integration). They are not
> yet wired end-to-end. See `docs/vision/USE_CASE_MAP.md` for implementation status of the
> underlying packages.

---

## The Documents

| Vertical                 | Business Case                                      | Module Spec                                 |
| ------------------------ | -------------------------------------------------- | ------------------------------------------- |
| Fintech / KYC layering   | [01](01_business_case_fintech_kyc.md)              | [01](01_module_fintech_kyc.md)              |
| iGaming compliance       | [02](02_business_case_igaming_compliance.md)       | [02](02_module_igaming_compliance.md)       |
| Supply chain / B2B creds | [03](03_business_case_supply_chain_credentials.md) | [03](03_module_supply_chain_credentials.md) |
| Healthcare / EHDS        | [04](04_business_case_healthcare_ehds.md)          | [04](04_module_healthcare_ehds.md)          |

---

## Regulatory Tailwind by Vertical

| Vertical     | Primary regulatory levers                                                    |
| ------------ | ---------------------------------------------------------------------------- |
| Fintech      | GDPR Art. 5(1)(c), DORA, 6AMLD Art. 8, EBA/GL/2022/15, eIDAS 2.0, MiCA/TFR   |
| iGaming      | GlüStV 2021 (incl. §6h), UKGC LCCP 17, ADM/RUA, DGOJ, GDPR Art. 9            |
| Supply chain | CSRD/ESRS, CSDDD, CBAM, EU Forced Labour Reg., Dir. 2005/36/EC, GDPR Art. 28 |
| Healthcare   | EHDS Art. 5/8/11/14/31/46, GDPR Art. 9, NIS2                                 |

---

## Prioritization Matrix

Same weighting as `docs/specs/34_Use_Case_Prioritization_Matrix.md`:
Pain(30%) + Willingness(25%) + Integration Ease(20%) + Regulatory Simplicity(15%) +
Differentiation(10%). Scores 1 (low) – 5 (high).

| Use case               | Pain | Willingness | Integration Ease | Regulatory Simplicity | Differentiation | Weighted |
| ---------------------- | ---: | ----------: | ---------------: | --------------------: | --------------: | -------: |
| iGaming compliance     |    5 |           5 |                3 |                     3 |               4 | **4.20** |
| Fintech / KYC layering |    5 |           4 |                3 |                     2 |               4 | **3.80** |
| Healthcare / EHDS      |    4 |           4 |                2 |                     3 |               5 | **3.55** |
| Supply chain / B2B     |    4 |           3 |                2 |                     3 |               4 | **3.20** |

### Recommended sequencing

1. **iGaming** — highest willingness to pay, active regulator pressure, deepest point-of-play pain
   (see `docs/_core/04_MARKET.md`).
2. **Fintech / KYC** — largest TAM and recurring-revenue shape; DORA tailwind.
3. **Healthcare / EHDS** — strongest differentiation and regulatory tailwind (2027), but longer
   sales cycle; leverages existing EHDS work (`docs/00-welt/49_EHDS_Compliance_Map.md`).
4. **Supply chain** — large but slowest decision cycle; urgency rises as CSDDD transposes (2026).

> Note: file numbers (`01..04`) follow the verticals' canonical order, not the ranking above.

---

## Shared Integration Pattern

Every vertical integrates the same way on the relying-party side:

```typescript
import { VerifierSDK } from '@askmi/verifier-sdk';

const sdk = new VerifierSDK({ verifierDid, privateKey, replayCheck });
const { proof } = await sdk.verifyPresentation(req.body);
if (proof.allPassed) {
  /* grant — store only the WORM receipt, never PII */
}
```

- Proof shape: `PredicateRequest` → `DecisionProofPayload` (`@askmi/shared-types`).
- Policy: fail-closed evaluation in `@askmi/policy-engine` (deny codes in `deny-reason-codes.ts`).
- Audit: WORM receipts via `@askmi/audit-log` (GDPR Art. 32 / EHDS Art. 31).

---

## Related

- Consumer use cases: `docs/modules/`
- Use-case → code map: `docs/vision/USE_CASE_MAP.md`
- Market / willingness-to-pay analysis: `docs/_core/04_MARKET.md`
- Enterprise revenue model: `docs/vision/PLATFORM_ECOSYSTEM.md`
- Regulatory calendar: `docs/vision/REGULATORY_CALENDAR.md`
