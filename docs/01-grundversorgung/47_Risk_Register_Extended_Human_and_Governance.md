# 47 — Risk Register Extended (Human + Governance)

Stand: 2026-02-11

## Purpose
Capture non-technical and socio-technical risks that can invalidate otherwise strong cryptographic architecture.

---

## R-H1 — Proof Fatigue / Consent Blindness
- **Risk:** Users approve sensitive requests reflexively.
- **Impact:** Over-disclosure, trust erosion, abuse potential.
- **Mitigation:** Risk-tiered prompts, deny-by-default for high-risk, purpose clarity, cooldowns.
- **Status:** Open

## R-H2 — Social Engineering Against User Decisions
- **Risk:** Attackers trick users into authorizing harmful disclosure.
- **Impact:** Privacy breach despite technical controls.
- **Mitigation:** Strong warning UX, suspicious-request heuristics, out-of-band confirmation for high-risk flows.
- **Status:** Open

## R-G1 — Client-side Policy Tampering
- **Risk:** Local policy engine modified/bypassed on compromised device.
- **Impact:** Unauthorized ALLOW outcomes.
- **Mitigation:** Signed policy manifests, server-side re-validation, tamper-evident receipts, integrity checks.
- **Status:** Open

## R-G2 — Recovery as Backdoor
- **Risk:** Recovery process re-centralizes trust or is exploitable.
- **Impact:** Account takeover, coercion, key compromise.
- **Mitigation:** Explicit recovery threat model, guardian quorum, anti-coercion controls, fail-safe resets.
- **Status:** Open

## R-L1 — GDPR Role/Flow Ambiguity
- **Risk:** Unclear controller/processor roles and retention basis.
- **Impact:** Compliance exposure, legal friction, pilot blockage.
- **Mitigation:** External legal opinion, RoPA mapping, DPIA-aligned artifacts, minimization evidence.
- **Status:** Open

## R-HW1 — Crypto Shredding Hardware Gap
- **Risk:** “Key destruction = erasure” claim may be weaker on non-hardware-backed storage.
- **Impact:** Residual data risk and overclaim risk.
- **Mitigation:** Explicit protection-level taxonomy (software vs hardware-backed), conservative claims, optional hardware-backed profile.
- **Status:** Open
