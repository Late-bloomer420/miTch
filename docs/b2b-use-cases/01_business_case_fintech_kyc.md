# B2B Business Case 01 — Fintech / Reusable KYC Layering

Stand: 2026-05-23
Vertical: Banking · Neobanks · PSD2 AISPs · Crypto exchanges
Status: Concept (verifier-side integration via `@askmi/verifier-sdk`)

## 1) Positioning

miTch is **not** a KYC provider and **not** an identity broker.

miTch is a **proof-mediation layer** that sits between a customer's wallet and a
relying party's backend:

- The authoritative KYC record stays with the **issuing bank** (the regulated entity that
  ran the original onboarding). miTch never holds it.
- A second institution receives only the **minimal predicate** it needs to make a decision
  (e.g. `kyc_completed_within_24m = true`, `aml_risk_band ∈ {low, medium}`), not the
  underlying name, DOB, address, or transaction history.
- Each presentation is bound to the requesting verifier's DID and a fresh nonce, so a proof
  issued for one institution cannot be replayed against another.

This keeps miTch consistent with its non-negotiables: data minimisation, fail-closed,
no centralised identity custody.

## 2) Problem

Every regulated financial institution re-runs full KYC/AML onboarding for every new customer,
even when an equivalent check was completed weeks earlier at another EU institution. The cost
is real (€15–€40 per onboarding in vendor + manual review) and the **liability is worse**:
each institution now stores a full copy of the customer's identity documents, becoming another
breach target and another GDPR Art. 5(1)(c) minimisation problem. DORA (in force Jan 2025)
makes every additional PII store a reportable ICT third-party risk.

## 3) Solution

For each onboarding or step-up event:

1. The relying party requests a **predicate** (e.g. `kyc_completed_within_24m AND
aml_risk_band ∈ {low, medium} AND jurisdiction_eq=EU`) with a stated purpose.
2. The customer's wallet evaluates the request against local policy (fail-closed) and the
   bank-issued credential.
3. The wallet returns a signed `DecisionProofPayload` — booleans + a binding to the verifier
   DID and nonce. No raw attributes leave the device.
4. The relying party verifies the proof with `@askmi/verifier-sdk` and logs a WORM receipt
   for audit. Stale or revoked source credentials fail closed (`DENY_CREDENTIAL_TOO_OLD`,
   `DENY_CREDENTIAL_REVOKED`).

## 4) Why now

- **DORA (Jan 2025):** less PII custody = smaller breach surface = lower reportable ICT risk.
- **6AMLD + EBA/GL/2022/15:** risk-based, ongoing due diligence permits proof of a prior check
  rather than mandatory re-collection.
- **eIDAS 2.0 / EUDIW rollout (2025–2026):** bank-issued attestations become a wallet attribute,
  giving miTch a standards-based issuance path (`@askmi/oid4vci`, SD-JWT VC).
- **Crypto Travel Rule (TFR):** exchanges need counterparty assurance above €1,000 without
  exchanging full customer dossiers.

## 5) ICP (Ideal Customer Profile)

- EU neobanks and challenger banks with high onboarding volume and thin margins.
- PSD2 AISPs / account-aggregation fintechs that must avoid re-KYC liability.
- Regulated crypto exchanges (CASPs under MiCA) needing Travel Rule counterparty checks.
- Primary buyer: **MLRO / AML Officer**. Secondary: **Head of Compliance**. Tertiary: **CISO** (DORA).

## 6) MVP scope

- Predicate set: `kyc_completed_within_24m` (mandatory), `aml_risk_band` (`in` low/medium),
  `sanctions_clear`, `jurisdiction_eq=EU`, `age_gte=18`.
- 1 issuing-bank integration (SD-JWT VC over `@askmi/oid4vci`).
- 2 relying-party pilots verifying via `@askmi/verifier-sdk` with replay-check hook.
- Fail-closed deny codes + WORM receipts (PII-minimal, anti-oracle verifier messages).

## 7) Monetization options

- Per-verification pricing with volume tiers (verifier pays).
- Monthly compliance-platform fee bundling a verification quota + audit-export.
- Enterprise plan: BaFin/FMA/EBA-ready audit reporting, status-list revocation feeds.

## 8) KPI for pilot success

- Re-KYC unit-cost avoided per reused proof (target: > €15).
- Raw PII leakage findings in pilot (target: 0).
- Replay / verifier-swap blocked rate (target: 100%, via `DENY_BINDING_NONCE_REPLAY`).
- p95 verification latency within SLA.
- Relying-party integration time-to-first-success (target: < 1 day with the SDK).

## 9) Risk notes

- **"Our regulator won't accept a third-party KYC proof."** miTch does not replace the source
  check — the originating **bank remains the issuer and the legally responsible KYC entity**.
  miTch only mediates a re-presentable, freshness-bound proof. Frame against EBA/GL/2022/15
  on remote onboarding and shared due-diligence reliance.
- Issuer integration fidelity (freshness, revocation) determines real trust value.
- Degraded mode (status source unavailable) must remain deny-biased
  (`DENY_STATUS_SOURCE_UNAVAILABLE`).

## 10) Messaging sentence (external)

"miTch lets a second bank trust a first bank's KYC with a cryptographic proof — no customer
dossier changes hands, and your breach surface shrinks instead of growing."
