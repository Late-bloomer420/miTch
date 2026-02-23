# 54 — External Security Findings Integration (VON_CLAUDE)

Stand: 2026-02-11

This file captures key findings from `VON_CLAUDE.txt` and maps them to miTch actions.

## Priority P0 (immediate)
1. Crypto-shredding hardware gap
   - Action: keep claims conservative; document best-effort in browser environments.
2. Proof fatigue / social engineering
   - Action: add risk-tiered consent and re-auth for high-risk requests.

## Priority P1 (near term)
3. Client-side policy tamper risk
   - Action: strengthen signed policy + server-side re-validation + integrity checks.
4. Recovery attack surface
   - Action: define recovery threat model + guardian controls + delay/alert model.

## Priority P2 (pre-pilot legal)
5. GDPR legal opinion
   - Action: commission external legal memo for role mapping + erasure interpretation.

## Additional findings tracked
- Issuer compromise and trust anchor governance
- Browser isolation limits
- Logging integrity limitations without complete event coverage

## Integration status
- Added to risk register and mitigation docs:
  - `47_Risk_Register_Extended_Human_and_Governance.md`
  - `48_Mitigations_ProofFatigue_PolicyTamper_Recovery_GDPR.md`
- Added TEE-specific gap doc:
  - `53_TEE_Readiness_Gap.md`

## Next implementation tickets
- Add proof-fatigue risk signals in UX/policy flow
- Add recovery security concept doc and tests
- Add legal review task owner and milestone in pilot plan
