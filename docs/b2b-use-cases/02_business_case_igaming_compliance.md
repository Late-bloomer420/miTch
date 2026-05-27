# B2B Business Case 02 — iGaming / Online Gambling Compliance

Stand: 2026-05-23
Vertical: Licensed sports betting · Online casinos · Operators under GlüStV / UKGC / ADM / DGOJ
Status: Concept (verifier-side integration via `@mitch/verifier-sdk`)

## 1) Positioning

miTch is **not** a player identity database and **not** a self-exclusion registry.

miTch is a **proof-mediation layer** between the player's wallet and the operator's platform:

- The operator gets a **boolean decision** at the point of play (`age_gte=18`,
  `not_self_excluded`, `deposit_capacity_ok`) — not the player's name, birthday, or income.
- Self-exclusion and age status are sourced from authoritative registers (OASIS/BZgA, GAMSTOP,
  RUA) and presented as predicates; the operator never ingests the underlying record.
- Each session proof is bound to the operator DID and a fresh nonce, and per-operator pairwise
  DIDs keep the same player unlinkable across operators while still verifiably excluded everywhere.

## 2) Problem

Licensed operators must verify age, identity, self-exclusion status, and (in some jurisdictions)
affordability before play — and then retain that identity data for years. The result is a large,
permanently growing store of **special-category-adjacent data** (problem-gambling flags, income),
which is both a GDPR Art. 9 exposure and a prime breach target. Regulators (Germany's GGL under
GlüStV 2021, the UKGC, Italy's ADM, Spain's DGOJ) actively audit and fine for both verification
failures **and** data-handling failures.

## 3) Solution

For each registration and high-risk action:

1. The operator requests predicates (`age_gte=18 AND not_self_excluded AND
deposit_limit_remaining_gte=<stake>`) with purpose.
2. The wallet evaluates against authoritative credentials and local policy (fail-closed).
3. For high-value transactions, the policy engine requires a WebAuthn step-up
   (`@mitch/webauthn-verifier`) before a fresh proof is emitted.
4. The operator verifies via `@mitch/verifier-sdk` and stores a WORM receipt. A player who enters
   self-exclusion has their credential revoked → instant `DENY_CREDENTIAL_REVOKED` at every operator.

## 4) Why now

- **GlüStV 2021:** GGL is actively enforcing age, identity, and OASIS self-exclusion duties.
- **UKGC LCCP 17 + affordability:** age verification before deposit, plus financial-vulnerability
  checks that today demand intrusive income disclosure.
- **GDPR Art. 9 scrutiny:** problem-gambling flags are sensitive; minimising their spread reduces
  board-level risk.
- High **willingness to pay** in this sector (see `docs/_core/04_MARKET.md`): fines and licence
  risk dwarf integration cost.

## 5) ICP (Ideal Customer Profile)

- Licensed EU/UK operators (sports betting, casino) under active regulator pressure.
- Multi-jurisdiction operators needing one mechanism across DE/UK/IT/ES rule sets.
- Primary buyer: **Head of Compliance / VP Product**. Secondary: **DPO** (Art. 9 risk).
  Tertiary: **state-regulator liaison** for pilots.

## 6) MVP scope

- Predicates: `age_gte=18` (mandatory), `not_self_excluded` (mandatory),
  `jurisdiction_in=[DE,…]`, optional `deposit_limit_remaining_gte`.
- Self-exclusion modelled as a revocable credential (status-list backed).
- WebAuthn step-up on a configurable high-stake threshold.
- 1 register/issuer bridge + 1 operator pilot verifying via the SDK.

## 7) Monetization options

- Per-verification pricing (registration + per-session checks), volume tiers.
- Compliance-platform subscription with regulator-ready audit export.
- Premium module: affordability predicate via PSD2 rail (income band, no statements).

## 8) KPI for pilot success

- Self-excluded players blocked at session start (target: 100%, via `DENY_CREDENTIAL_REVOKED`).
- Raw PII / income leakage to operator (target: 0).
- Replay / cross-operator proof reuse blocked (target: 100%, `DENY_BINDING_NONCE_REPLAY`).
- Step-up enforced on every above-threshold transaction (target: 100%).
- Operator audit-export accepted in a mock regulator review.

## 9) Risk notes

- **"GlüStV §6h requires us to retain identity for years."** miTch does not remove the operator's
  record-keeping duty — it removes the **point-of-play PII surface**. The authoritative copy stays
  with the issuer/eID; the operator keeps hashed WORM receipts that evidence each check without
  storing raw identity per session.
- Self-exclusion register integration fidelity is the trust anchor; revocation latency must be low.
- Affordability predicate must avoid becoming a new income data store — reduce locally, retain
  only the boolean.

## 10) Messaging sentence (external)

"miTch proves a player is of age, not self-excluded, and within their limits — without your
platform ever storing their identity, so a breach can't leak what you never held."
