# Security Sign-Off on Public Claims

> **GTM-04** · Reviewer role: Security Engineer (sign-off), Compliance & Evidence Lead (evidence)
> Date: 2026-05-25 · Disposition: **CONDITIONAL — one blocking correction required before publication.**

## 1. Scope

This sign-off checks the **public-facing claims** in the Commercial Trust Kit and the existing
marketing/pitch surface against the canonical evidence in
[`03_COMPLIANCE_EVIDENCE_INDEX.md`](03_COMPLIANCE_EVIDENCE_INDEX.md), [`STATE.md`](../../../STATE.md),
and the [CIR matrix](../../compliance/EUDI_CIR_MATRIX.md). Objective: **no claim may overstate
security, privacy, or certification status.**

## 2. Verdict summary

| Surface | Verdict |
|---------|---------|
| `01_VERIFIER_NARRATIVE.md` (this kit) | ✅ Approved — claims are scoped and pointer-backed |
| `02_TECHNICAL_APPENDIX.md` (this kit) | ✅ Approved — status flags match CIR matrix |
| `03_COMPLIANCE_EVIDENCE_INDEX.md` (this kit) | ✅ Approved — gaps flagged, no certification claim |
| `docs/presentation/PITCH.md` | 🔴 **Blocked** — contains an overstated security claim (F-1) |
| Certification framing across surfaces | 🟡 Conditional — see F-2 |

## 3. Findings

### F-1 — "0 NPM Vulnerabilities" is false (BLOCKING) 🔴

- **Claim:** `docs/presentation/PITCH.md` states *"0 NPM Vulnerabilities, alle P0- und P1-
  Sicherheitslücken vollständig geschlossen"*.
- **Evidence:** [`STATE.md`](../../../STATE.md) (2026-05-16) records **7 npm vulnerabilities
  (4 high, 3 moderate)** — `undici`, `flatted` — all in **devDependency** chains.
- **Why it matters:** "0 vulnerabilities" is a verifiable, falsifiable security claim. It is currently
  false and would not survive a `pnpm audit` by a prospective verifier.
- **Required correction:** Replace with an accurate, defensible statement, e.g. *"No known
  vulnerabilities in runtime dependencies; 7 advisories remain in dev-only dependency chains
  (4 high, 3 moderate), tracked for upgrade."* Confirm the runtime-vs-dev split before publishing.
- **Owner of fix:** marketing/pitch copy owner (UX/Product). Tracked as a delegated follow-up issue
  (see §5). **This kit does not edit `PITCH.md`** — out of scope for the Compliance Evidence Lead.

### F-2 — Certification language must not imply "certified" (CONDITIONAL) 🟡

- **Risk:** terms like *"zertifizierbar"*, *"EU-first"*, *"compliance interface of the future"* can read
  as achieved certification.
- **Evidence:** CIR 2024/2981 certification row is **1/5** implemented; Common Criteria **not started**;
  LoA High is **software-only**; no EUDI Trust List registration.
- **Required guardrail:** every external surface must phrase certification as *readiness / mapping*,
  never as a completed conformity assessment. Defer to the §4 legal-review gaps in the evidence index.
- **Status:** acceptable **only** with that guardrail applied. The three kit documents already comply.

### F-3 — "Over-fulfilled GDPR" / EHDS claims need legal qualification (NON-BLOCKING) 🟡

- The crypto-shredding erasure position and EHDS/Art. 9 readiness are strong but are **design claims**,
  not regulator rulings, and EHDS is out of pilot scope. They must be marked accordingly. Flagged in
  evidence index §4(3)(4); owned by legal/DPO review, not this sign-off.

## 4. What is cleared

The following claims are supported by current evidence and are **approved for verifier-facing use**:

- Fail-closed policy / no silent ALLOW — `policy-engine`, `CAP_NEGOTIATION_V1`.
- Data minimization by construction; selective disclosure — `sd-jwt-vc.ts`, `policy-bridge.ts`.
- Replay protection, key binding, response encryption — `nonce-store.ts`, `dpop.ts`, `haip.ts`.
- Auditable, decision-bound disclosure; requested/allowed/withheld visibility — `audit-log`, `data-flow`.
- "No raw PII custody" / zero identity custody — wallet-scoped, edge-first design.
- eIDAS 2.0 / EUDI **compatibility at 77% CIR coverage** — stated as coverage, not certification.

## 5. Disposition

**Sign-off is CONDITIONAL.** The three Trust Kit documents are cleared as written. External
publication of the broader pitch is **blocked on F-1** (false "0 vulnerabilities" claim), which is
delegated to the copy owner via a follow-up issue. F-2/F-3 are guardrails, not blockers, provided the
certification and legal-review framing in the evidence index is honored.

Re-sign required after F-1 is corrected and the dev/runtime vulnerability split is confirmed against a
fresh `pnpm audit`.
