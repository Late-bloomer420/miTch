# MIT-21 — Trust-Surface UX Review: Consent, DataFlow & Minimization Clarity

**Epic:** MIT-4 — Product Trust Surface
**Author:** UX Product Designer (agent)
**Date:** 2026-05-25
**Scope:** Consent prompt, DataFlow panel, and minimization messaging in `wallet-pwa`, reviewed for age-verification clarity.
**Constraint (epic-level):** Improve understandability **without increasing metadata leakage** — no new data fields, no new telemetry, no additional identifiers surfaced to verifiers. All changes below are presentation-only.

---

## Method

Reviewed the live trust surface against the product promise *"proof, not PII"* using the canonical age-verification flow (`age >= 18` proven from an `AgeCredential`):

- `src/apps/wallet-pwa/src/components/ConsentModal.tsx` — the disclosure consent prompt
- `src/apps/wallet-pwa/src/components/DataFlowPanel.tsx` — post-transaction history
- `src/packages/data-flow/src/summary.ts` — plain-language transaction summary
- `src/apps/wallet-pwa/src/utils/i18n.ts` — claim/reason dictionaries

---

## Findings (prioritized)

### F1 — CRITICAL: Consent prompt labels *proven* claims as *disclosed*

**Where:** `ConsentModal.tsx:248-275`
**What:** The claims block has one header — `WOULD BE DISCLOSED (strictly limited)` — and renders **both** `proven_claims` (ZKP predicates, e.g. `age >= 18`) and `allowed_claims` (raw values, e.g. `birthDate`) underneath it.

**Why it's confusing:** A zero-knowledge proven predicate is *not disclosed* — that is the entire point of the product. Showing `age >= 18` under a header that says "WOULD BE DISCLOSED" tells the user the opposite of what actually happens, on the exact flow (age verification) that is the flagship demo. It also contradicts the DataFlow panel, which correctly says *"bewiesen statt offengelegt"* (proven instead of disclosed) for the same data.

**Required change:** Split the block into two clearly captioned groups and use an accurate parent header:
- Parent header: `WHAT THIS VERIFIER LEARNS` (neutral — covers both proof and disclosure).
- Proven group caption: `✅ Proven — value NOT disclosed`.
- Disclosed group caption: `⚠️ Disclosed — raw value shared`.
- Render each caption only when that group is non-empty.

**Status:** ✅ Implemented in this PR (see `ConsentModal.tsx`, `ClaimChips` + claims section; covered by new tests in `ConsentModal.test.tsx`).

---

### F2 — HIGH: Trust surface flips language mid-flow (EN consent → DE DataFlow)

**Where:** `ConsentModal.tsx` (chrome copy hardcoded English: "Data Disclosure Request", "VERIFIER", "Decline", "Approve Disclosure") vs `DataFlowPanel.tsx` / `summary.ts` (hardcoded German: "Datenflüsse", "Vergessen", "Schlüssel aktiv", "bewiesen statt offengelegt").

**Why it's confusing:** Within a single user journey the language switches. `utils/i18n.ts` already has full `de/en/es/nl` dictionaries for *claims* and *reason codes*, but the surrounding chrome strings bypass it. A user who approves a disclosure in English then sees its record in German.

**Required change (→ MIT-22):** Route all chrome copy through `utils/i18n.ts` (extend the dictionaries with UI strings; key off `getBrowserLanguage()`). No behavior change, no new data. Pick one language per session consistently.

---

### F3 — MEDIUM: "Risk" framing undersells minimization

**Where:** `ConsentModal.tsx:50-56` (`riskLabel`) — a ZKP-only, no-raw-data disclosure is labeled `✅ Low Risk — Standard Disclosure`.

**Why it's confusing:** For a minimization product, calling the *best-case* (proof-only, nothing disclosed) a "Standard Disclosure" frames the safe path as ordinary rather than as the privacy win it is. "Risk" language also primes users to think in threat terms when the headline should be how little leaves the wallet.

**Required change (→ MIT-22, pending compliance review MIT-24):** When `proven_claims` exist and `allowed_claims` is empty, lead with a minimization-positive line (e.g. `✅ Proof only — no personal data leaves your wallet`) instead of/above the generic risk banner. Keep the risk banner for MEDIUM/HIGH. Wording must clear MIT-24 compliance-language review before merge (claim must match implemented behavior).

---

### F4 — LOW: "ZKP" is jargon

**Where:** `ConsentModal.tsx:272` (`✅ ZKP only — no raw data`) and the `--proven` styling vocabulary.

**Why it's confusing:** "ZKP" is an engineering term. End users do not parse it.

**Required change (→ MIT-22):** Prefer plain language — `✅ Proof only — no personal data shared`. Keep "zero-knowledge proof" available as secondary/tooltip text for technical audiences, not as the primary label.

---

## Metadata-leakage guardrail (epic constraint)

None of the above adds data. F1 (implemented) only **re-labels and regroups data already present** in the `DecisionCapsule`. F2–F4 are copy/i18n routing. No new fields are sent to verifiers, no new telemetry is recorded, and no additional identifiers are surfaced. The minimization message becomes clearer precisely because we stop *overstating* what is shared.

---

## Handoff

- **F1** — done in this change; verified by `ConsentModal.test.tsx`.
- **F2, F3, F4** — required changes for **MIT-22** (implement approved trust-surface copy). F3 wording is gated on **MIT-24** (compliance language review) before merge.
- **MIT-23** (QA desktop/mobile) should verify the new two-group consent layout has no overflow/regression on narrow viewports.
