# 23 — Implementation Sequence v0 (Build Order)

Stand: 2026-02-11

## Phase A — Contract Freeze (Week 1)
1. Accept ADR-001/004/006/008
2. Freeze `17_API_Contract_v0.md`
3. Freeze `20_Canonicalization_and_Binding_Spec_v0.md`
4. Freeze `21_Deny_Reason_Code_Catalog.md`

**Exit:** No open normative ambiguities for MVP scope.

---

## Phase B — Core Runtime (Week 2)
1. Schema validator
2. Policy evaluator (deterministic)
3. Deny-code mapper
4. Gate precedence enforcement

**Exit:** Fail-closed regression suite green.

---

## Phase C — Security Controls (Week 3)
1. Nonce store + replay prevention
2. Audience/expiry/clock-skew validation
3. Crypto verify path + algorithm policy
4. WORM receipt writer

**Exit:** Adversarial replay/context-swap suite green.

---

## Phase D — Integrations (Week 4-5)
1. Issuer adapter
2. Verifier API endpoint v0
3. RP integration #1
4. RP integration #2

**Exit:** 2 RPs pass E2E with deterministic outcomes.

---

## Phase E — Pilot Gate (Week 6)
1. Run `18_Test_Plan_Adversarial_and_E2E.md`
2. Validate `19_Data_Retention_Matrix.md`
3. Complete `13_MVP_Readiness_Checklist.md`
4. Decide using `22_Pilot_Go_NoGo_Template.md`

**Exit:** Formal Go/No-Go decision logged.
