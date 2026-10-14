# Compliance Evidence Index

> **GTM-03** · Owner: Compliance & Evidence Lead · Date: 2026-05-25
> Purpose: give a reviewer a single map from each compliance claim to its **canonical** evidence,
> and to **flag where legal review is still required**. This index does not itself certify anything.

Status legend: ✅ evidence present & current · 🟡 partial / in progress · 🔴 not implemented ·
⚠️ **legal review required before external use**.

## 1. Evidence sources (canonical)

| Topic | Canonical document | Role |
|-------|--------------------|------|
| Operational health (tests, lint, audit, demo) | [`STATE.md`](../../../STATE.md) | What runs right now |
| P0 closure (security + fail-closed proof) | [`docs/ops/EVIDENCE_PACK_P0.md`](../../ops/EVIDENCE_PACK_P0.md) | P0 evidence |
| EUDI / eIDAS 2.0 CIR coverage | [`docs/compliance/EUDI_CIR_MATRIX.md`](../../compliance/EUDI_CIR_MATRIX.md) | Per-requirement status |
| CIR 2024/2981 certification analysis | [`docs/compliance/CIR_2024_2981_Certification_Analysis.md`](../../compliance/CIR_2024_2981_Certification_Analysis.md) | Certification gap analysis |
| GDPR crypto-shredding rationale | [`docs/04-legal/MEMO_GDPR_SHREDDING.md`](../../04-legal/MEMO_GDPR_SHREDDING.md) | Art. 17 / erasure basis |
| Certification & trust readiness | [`docs/04-legal/certification_readiness_mapping.md`](../../04-legal/certification_readiness_mapping.md) | Kantara / eIDAS / GDPR posture |
| Pilot execution record | [`docs/pilot/PILOT_DRY_RUN_01.md`](../../pilot/PILOT_DRY_RUN_01.md) | Pilot evidence |
| Capability negotiation / fail-closed | [`docs/protocol/CAP_NEGOTIATION_V1.md`](../../protocol/CAP_NEGOTIATION_V1.md) | Downgrade & deny contract |
| Public claim → code map | [`docs/05-business/marketing/06-claim-evidence-map.md`](../marketing/06-claim-evidence-map.md) | Claim provenance |

## 2. Claim → evidence index

| Compliance claim | Evidence | Status |
|------------------|----------|--------|
| Data minimization by construction | `policy-engine/src/engine.ts`, `oid4vp/src/policy-bridge.ts`, CIR 2981-5 | ✅ |
| Fail-closed policy (no silent ALLOW) | `policy-engine/src/engine.ts`, `allow-assertion.ts`, `CAP_NEGOTIATION_V1.md` | ✅ |
| Selective disclosure (SD-JWT `_sd`) | `shared-crypto/sd-jwt-vc.ts`, CIR 2977-7, 2982-11 | ✅ |
| Key binding / holder binding | `createKeyBindingJWT`, CIR 2977-5/6 | ✅ |
| Replay protection (nonce, DPoP `jti`) | `nonce-store.ts`, `dpop.ts`, CIR 2979-7/12 | ✅ |
| Crypto-shredding / right to erasure | `WalletService.requestDataErasure`, `MEMO_GDPR_SHREDDING.md`, CIR 2982-16 | ✅ |
| Auditable decisions (DecisionCapsule) | `shared-types/src/audit.ts`, `audit-log/src/index.ts` | ✅ |
| Requested / allowed / withheld visibility | `data-flow` package, `DataFlowPanel.tsx` | ✅ |
| Pairwise / unlinkable subject | `computePairwiseSub()`, `pairwise-did.ts`, CIR 2982-4/10 | ✅ |
| Live credential-status revocation | `status` claim read; live fetch endpoint, CIR 2982-14 | 🟡 |
| EUDI Trust List integration | local `trustedVerifiers` set only, CIR 2982-15 | 🟡 |
| LoA "High" (hardware/TEE binding) | software-only PoC, CIR 2981-1 | 🟡 ⚠️ |
| Common Criteria (ISO/IEC 15408) | not started, CIR 2981-2 | 🔴 ⚠️ |
| Batch issuance | not implemented, CIR 2977-13 | 🔴 |
| Proximity / offline (ISO 18013-5) | `@askmi/mdoc` partial, CIR 2982-18 | 🟡 |

## 3. Compliance posture summary (from CIR matrix, 2026-03-06)

| CIR | Total | ✅ | 🟡 | 🔴 |
|-----|-------|----|----|----|
| 2024/2977 PID & EAA | 15 | 13 | 2 | 1 |
| 2024/2979 Integrity & Core | 15 | 14 | 1 | 0 |
| 2024/2982 Protocols & Interfaces | 18 | 13 | 4 | 1 |
| 2024/2981 Certification | 5 | 1 | 3 | 1 |
| **Total** | **53** | **41 (77%)** | **10 (19%)** | **3 (4%)** |

## 4. Legal-review gaps (⚠️ must be reviewed before external publication)

The following are **not** matters of code status but of legal/regulatory framing. They must be cleared
by a qualified reviewer before any of these statements appear in customer-facing material:

1. **Certification language.** "Certifiable", "readiness-mapped", and "compatible" must never be
   presented as "certified". No EUDI conformity assessment, Common Criteria evaluation, or eIDAS Trust
   List registration has been completed. → [`certification_readiness_mapping.md`](../../04-legal/certification_readiness_mapping.md),
   [`CIR_2024_2981_Certification_Analysis.md`](../../compliance/CIR_2024_2981_Certification_Analysis.md).
2. **eIDAS 2.0 / EUDI "compatibility".** Substantiated as architectural compatibility at 77% CIR
   coverage — **not** as a qualified or notified wallet. Framing must say so.
3. **GDPR "übererfüllt" (over-fulfilled) erasure claim.** The crypto-shredding erasure argument
   (`MEMO_GDPR_SHREDDING.md`) is a strong design position but is **not** a regulator ruling. Needs DPO /
   counsel review before being stated as legal fact.
4. **EHDS / health-data (GDPR Art. 9) claims.** Out of pilot scope; partial implementation. Must be
   marked roadmap, not delivered, in any external claim.
5. **LoA "High".** Currently software-only. Any assurance-level claim must be qualified as PoC.

## 5. Handover

- Items in §4 are **owned by legal/DPO review**, not engineering — they are flagged here, not resolved.
- Public-claim wording is gated by the [security sign-off](04_SECURITY_SIGNOFF.md), which checks the
  marketing surface against this index.
