# B2B Business Case 04 — Healthcare / EHDS Access Mediation

Stand: 2026-05-23
Vertical: Hospitals · Telemedicine platforms · Pharmacies · Pharma research (secondary use)
Status: Concept — builds on existing EHDS work (`docs/00-welt/49_EHDS_Compliance_Map.md`)

## 1) Positioning

miTch is **not** an EHR / hospital information system and **not** a central health registry.

miTch is a **proof-mediation layer** for **inter-system** health requests — between hospital and
ambulance, hospital and insurer, clinician and pharmacy, data holder and research body:

- The full record stays in the source system (the EHR, the national patient summary, ELGA, etc.).
- The requesting party receives only the **permission / eligibility proof** it needs
  (`insurance_active`, `practitioner_credentialed`, `consent_primary_use`, `hdab_permit_present`).
- Consent boundaries (primary vs. secondary use), break-glass, and single-use prescriptions are
  enforced fail-closed by `@askmi/policy-engine`, with a WORM audit trail for Art. 31 export.

## 2) Problem

Cross-organisation health workflows today move **far more data than the decision requires**:
a full patient summary is transferred to confirm insurance is active; a research body receives
identifiable records to run an aggregate study; a prescription can be redeemed twice. Health data
is GDPR Art. 9 special-category, hospitals are NIS2 essential entities, and EHDS adds explicit
duties around consent, secondary-use opt-out, and auditability. Over-disclosure is simultaneously
a privacy breach, a compliance failure, and a security liability.

## 3) Solution

For each inter-system request:

1. The requester asks for a permission predicate (e.g. `insurance_active AND
practitioner_credentialed AND consent_primary_use.scope=treatment`).
2. The policy engine enforces EHDS rules locally: `denySecondaryUse`, `requiresHdabPermit`,
   geo-scope, and break-glass — fail-closed.
3. Single-use artefacts (ePrescription) are bound to a nullifier; a second redemption fails with
   `DENY_CREDENTIAL_DISPENSED`.
4. Emergency access uses a WebAuthn step-up (`@askmi/webauthn-verifier`); the grant is logged as
   `ALLOW_BREAK_GLASS_ACTIVATED` and the patient is notified.

## 4) Why now

- **EHDS Regulation** (in force 2025, applicable from 2027): primary-use consent (Art. 8),
  secondary-use opt-out (Art. 11), single-use ePrescription (Art. 14), HDAB permits (Art. 46),
  audit export (Art. 31) — all map directly onto existing miTch mechanisms.
- **GDPR Art. 9:** explicit-consent / necessity gating is mandatory for health data.
- **NIS2:** hospitals are essential entities — minimising identity transfer shrinks breach radius.
- **Austria's ELGA** is already live, giving an early pilot surface ahead of EHDS Phase 2.

## 5) ICP (Ideal Customer Profile)

- Large hospitals / Klinikum groups with cross-border or inter-org exchange needs.
- Telemedicine platforms handling Art. 9 data at scale.
- Pharma / research organisations needing HDAB-gated secondary-use access.
- Primary buyer: **Hospital CIO / Head of Digital Health**. Secondary: **DPO** (telemedicine).
  Tertiary: **Research-data / HDAB liaison**.

## 6) MVP scope

- Predicates: `insurance_active`, `practitioner_credentialed`, `consent_primary_use.scope`,
  `consent_secondary_use_opt_in` (default false), `hdab_permit_present`.
- Break-glass via WebAuthn step-up + audit alert.
- ePrescription single-use nullifier.
- 1 source-system bridge (ELGA-style) + 1 requester pilot (insurer or pharmacy).

## 7) Monetization options

- Per-request mediation pricing for inter-org exchanges.
- Compliance-platform subscription with Art. 31 audit export + consent management.
- Research-access module: HDAB-permit-gated secondary-use pipeline (per-study fee).

## 8) KPI for pilot success

- Secondary-use requests without an HDAB permit blocked (target: 100%,
  `DENY_HDAB_PERMIT_REQUIRED`).
- Opt-out honoured on every secondary-use attempt (target: 100%, `DENY_SECONDARY_USE_DENIED`).
- Double-redemption of an ePrescription blocked (target: 100%, `DENY_CREDENTIAL_DISPENSED`).
- Every break-glass event audited + patient-notified (target: 100%).
- Raw record leakage in permission checks (target: 0).

## 9) Risk notes

- **"miTch can't replace our EHR."** Correct — it isn't meant to. miTch mediates **requests
  between** systems; the EHR/ELGA record is untouched. This is the central framing.
- Break-glass policy must remain deny-biased and always audited; emergency access is logged and
  notified, never silent.
- Geo-scope for third-country requests must default to `eu-only` / `eu-plus-adequacy`
  (`DENY_GEO_SCOPE_VIOLATION`).

## 10) Messaging sentence (external)

"miTch lets one health system prove eligibility to another — insurance active, clinician
credentialed, consent in scope — without transferring the patient's record, and with an audit
trail EHDS Art. 31 can export."
