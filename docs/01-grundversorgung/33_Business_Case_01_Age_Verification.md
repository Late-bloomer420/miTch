# 33 — Business Case 01: Privacy-Preserving Age Verification (18+)

Stand: 2026-02-11

## 1) Positioning (core clarification)
miTch is **not** an Identity Provider.
miTch is a **user-controlled authorization/proof mediation layer**:
- authoritative identity data (e.g., DOB) stays with issuer/state systems and/or user-controlled wallet storage
- requester gets only the **minimal proof** needed for the specific purpose (e.g., `age >= 18`)
- requester does **not** receive raw DOB unless policy and law explicitly require it

This aligns with the project’s non-negotiables (minimization, fail-closed, no centralized identity custody).

---

## 2) Problem
Online services need reliable age checks but often over-collect data (full ID upload, DOB storage), creating legal and security risk.

## 3) Solution
For each verification request:
1. RP asks for predicate (`age >= 18`) with purpose + policy reference.
2. User device/wallet validates request against local policy.
3. Proof is generated using issuer-backed credential/status context.
4. RP receives an allow/deny + receipt reference; no raw identity payload.

---

## 4) Why now
- Growing compliance pressure on age-gated digital services
- High cost/risk of current over-collection approaches
- Better mobile hardware + NFC + eID app workflows enable stronger identity bootstrapping

---

## 5) ICP (Ideal Customer Profile)
- EU-focused platforms with legal age-gating needs
- E-commerce categories with age-restricted products
- Digital content/services requiring compliance controls

---

## 6) MVP scope
- Predicate: `age_gte=18` (mandatory)
- Optional second predicate: `residency_eq=AT/EU`
- 1 issuer integration path
- 2 RPs for pilot
- Deterministic deny codes + WORM receipts (PII-minimal)

---

## 7) Monetization options
- Per-verification pricing (volume tiers)
- Monthly platform fee + bundled verification quota
- Enterprise compliance plan (audit/reporting features)

---

## 8) KPI for pilot success
- Verification success rate in controlled pilot
- Replay/context-swap blocked rate (target 100% blocked)
- Raw PII leakage findings (target 0)
- p95 verification latency target compliance
- RP integration time-to-first-success

---

## 9) Risk notes
- Issuer/status integration fidelity determines real trust value
- Degraded mode policy must remain deny-biased for high-risk cases
- Metadata minimization in logs/telemetry is critical

---

## 10) Messaging sentence (external)
“miTch helps services verify age eligibility with cryptographic proof while keeping raw identity data out of requester systems.”
