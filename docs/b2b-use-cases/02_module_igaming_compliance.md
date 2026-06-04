# Module Concept: iGaming Compliance — Age, Self-Exclusion & Affordability

## "Prove the Player Is Allowed to Play — Without Holding Who They Are"

> Not implementation-ready. Concept and design only.
> Verifier-side integration via `@askmi/verifier-sdk`. Companion business case:
> `02_business_case_igaming_compliance.md`.

---

## The Problem

A licensed operator must, before play, confirm a player is 18+, correctly identified, not
self-excluded, and (in the UK and increasingly elsewhere) financially able to bet. Today it does
this by collecting and **retaining** full identity and financial data.

A typical operator account therefore stores:

- Full name, date of birth, government ID scan
- Address and contact details
- Self-exclusion / problem-gambling status (GDPR Art. 9 special-category-adjacent)
- Income or affordability evidence (bank statements, payslips)

For three boolean questions: **"Is this player of legal age? Not self-excluded? Within their
limits?"**

Every operator becomes a long-lived honeypot of sensitive data, regulated for both verification
failures (GGL, UKGC, ADM, DGOJ) **and** data-protection failures (GDPR Art. 9).

---

## The miTch Answer

A signed predicate proof answering only what the licence requires:

```
age_gte_18:               ✓
not_self_excluded:        ✓
jurisdiction:             DE   (licensed scope)
deposit_limit_remaining:  ≥ requested stake
step_up_present:          ✓   (high-value actions)
valid_until:              <short session window>
```

Name: not shared. Birthday: not shared. ID scan: not shared. Income: not shared (only a band
boolean, computed locally). The wallet derives a **pairwise DID** per operator, so the same
player is unlinkable across operators — yet a self-exclusion still propagates to all of them via
credential revocation.

---

## Data Sources (Ingestion)

### Path A — eID / age credential

Age and identity bootstrap from a national eID (eIDAS 2.0) or bank-issued credential over
`@askmi/oid4vci`. Output predicate: `age_gte=18`. Raw DOB never leaves the wallet.

### Path B — Self-exclusion register bridge

OASIS (BZgA, Germany), GAMSTOP (UK), or RUA (Italy) status is modelled as a **revocable
credential**: holding it asserts "not currently self-excluded." Entering self-exclusion revokes
it via `@askmi/revocation-statuslist`, so the next check at any operator fails closed
(`DENY_CREDENTIAL_REVOKED`). The operator learns only the boolean, never the register record.

### Path C — Affordability (optional, PSD2 rail)

For UKGC-style affordability, an income band is derived from Open Banking data **locally**
(see `01_module_fintech_kyc.md`, Path B) and reduced to `monthly_disposable_income_gte=<stake>`.
The statements never reach the operator.

---

## The Transformation — What the Module Does

The operator sends a `PredicateRequest`:

```
predicates:  [ igaming-session-v1 ]
verifierDid: did:web:operator.example
nonce:       <random>
purpose:     "Session start — age, self-exclusion, limit check"
```

The policy engine (`@askmi/policy-engine`) evaluates fail-closed:

```
PredicateClause path=credentialSubject.birthDate    op=gte type=age_years value=18
PredicateClause path=selfExclusion.active           op=eq  type=boolean   value=false
PredicateClause path=session.jurisdiction           op=in  type=string[]  value=[DE]
PredicateClause path=limits.remaining               op=gte type=number    value=<stake>
```

- Deposit-limit and session-frequency logic reuse `rate-limiter.ts` and `proof-fatigue.ts`.
- Above the high-stake threshold, the engine returns `DENY_REAUTH_REQUIRED` until a WebAuthn
  step-up (`@askmi/webauthn-verifier`) is completed; the resulting proof is AAD-bound into the
  bet authorisation.
- A revoked self-exclusion credential → `DENY_CREDENTIAL_REVOKED`, regardless of operator.

---

## What the Verifier (Operator) Receives

| Data field                      | Shared? | Why                                         |
| ------------------------------- | ------- | ------------------------------------------- |
| `age_gte_18: true`              | ✅ Yes  | Mandatory age gate                          |
| `not_self_excluded: true`       | ✅ Yes  | Mandatory register check                    |
| `jurisdiction: DE`              | ✅ Yes  | Licensed-scope enforcement                  |
| `deposit_limit_remaining_ok`    | ✅ Yes  | Affordability / limit gate                  |
| `step_up_present: true`         | ✅ Yes  | High-value action assurance                 |
| `decision_id` + `nonce` binding | ✅ Yes  | Anti-replay, bound to this operator         |
| Full name                       | ❌ No   | Not needed to authorise play                |
| Date of birth                   | ❌ No   | `age_gte` predicate suffices                |
| Self-exclusion record           | ❌ No   | Only the boolean leaves the register bridge |
| Income / bank statements        | ❌ No   | Reduced to a band boolean locally           |
| Cross-operator identity         | ❌ No   | Pairwise DID — unlinkable across operators  |

---

## Verifier Integration (Operator Side)

```typescript
import { VerifierSDK } from '@askmi/verifier-sdk';

const sdk = new VerifierSDK({
  verifierDid: 'did:web:operator.example',
  privateKey: await getMyPrivateKey(),
  replayCheck: async (nonce) => {
    const seen = await db.has(nonce);
    if (!seen) await db.save(nonce);
    return seen;
  },
});

app.post('/session/authorize', async (req, res) => {
  try {
    const { proof } = await sdk.verifyPresentation(req.body);
    if (!proof.allPassed) return res.status(403).send('Not eligible'); // anti-oracle
    await worm.appendReceipt(proof); // §6h-style evidence, no raw PII
    res.json({ session: 'authorized' });
  } catch (err) {
    if (err.name === 'ReplayDetectedError') return res.status(409).end();
    res.status(400).send('Verification failed');
  }
});
```

---

## Example Flows

1. **OASIS cross-check, boolean only.** Operator queries `not_self_excluded` against the BZgA
   register bridge and receives a single boolean — no name, no birthdate.
2. **UKGC affordability without statements.** A PSD2-rail income-band predicate
   (`monthly_disposable_income_gte=<deposit>`) is proven; the operator never sees salary or lines.
3. **High-stakes step-up.** When cumulative deposits cross the configured threshold, the engine
   demands a WebAuthn step-up; the fresh proof is AAD-bound to the next bet.

---

## Regulatory Context

| Regulation                   | Relevance                                            |
| ---------------------------- | ---------------------------------------------------- |
| GlüStV 2021 (DE)             | Age, identity, OASIS self-exclusion; GGL enforcement |
| GlüStV §6h                   | Record-keeping satisfied by hashed WORM receipts     |
| UKGC LCCP 17 + affordability | Age before deposit; financial-vulnerability checks   |
| Italy ADM / RUA              | National self-exclusion register                     |
| Spain DGOJ RD 958/2020       | Deposit limits, affordability                        |
| GDPR Art. 9                  | Minimise spread of problem-gambling (sensitive) data |

---

## Packages Used

| Package                        | Role in this module                                      |
| ------------------------------ | -------------------------------------------------------- |
| `@askmi/policy-engine`         | Fail-closed eval; `rate-limiter.ts`, `proof-fatigue.ts`  |
| `@askmi/predicates`            | Age / self-exclusion / limit DSL; `nullifier.ts`         |
| `@askmi/shared-crypto`         | Pairwise DID per operator (cross-operator unlinkability) |
| `@askmi/webauthn-verifier`     | Step-up auth for high-value actions                      |
| `@askmi/revocation-statuslist` | Self-exclusion = revocation, propagates everywhere       |
| `@askmi/verifier-sdk`          | Operator-side verification + replay-check                |
| `@askmi/audit-log`             | WORM receipts for GGL/UKGC inspection                    |

Relevant deny codes: `DENY_CREDENTIAL_REVOKED` (self-exclusion), `DENY_REAUTH_REQUIRED`
(step-up), `DENY_RATE_LIMIT_EXCEEDED` (limits), `DENY_JURISDICTION_INCOMPATIBLE`,
`DENY_BINDING_NONCE_REPLAY`.

---

## Open Questions for This Module

- Will OASIS/BZgA, GAMSTOP, and RUA expose a status bridge that can back a revocable credential,
  or is an intermediary attestor required?
- Is "self-exclusion as revocation" acceptable to regulators as evidence of a real-time check,
  given status-list refresh latency?
- Affordability: which PSD2 aggregator and which income-band thresholds satisfy UKGC guidance
  without retaining transaction data?
- Does §6h record-keeping accept hashed WORM receipts in lieu of stored identity copies? Needs a
  regulator conversation.

---

## Next Step

Talk to one licensed operator's compliance lead about whether a boolean
`not_self_excluded + age_gte_18 + within_limits` proof at session start — backed by register
revocation — would satisfy their GGL/UKGC obligations while shrinking their Art. 9 exposure.
That conversation is validation, not sales.
