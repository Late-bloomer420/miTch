# Module Concept: Reusable KYC Layering — Fintech & Banking

## "Trust Another Bank's Check Without Holding Another Bank's Data"

> Not implementation-ready. Concept and design only.
> Verifier-side integration via `@askmi/verifier-sdk`. Companion business case:
> `01_business_case_fintech_kyc.md`.

---

## The Problem

A customer who completed full KYC at Bank A three months ago opens an account at Neobank B.
Today, Neobank B re-runs the entire onboarding: ID document upload, liveness check, PEP and
sanctions screening, address verification — and then **stores all of it**.

A re-collected KYC file exposes (and forces Neobank B to retain):

- Full legal name
- Date of birth
- Government ID document scan
- Residential address
- Tax identifiers / national ID number
- Source-of-funds documentation

For a single question: **"Has this person passed an equivalent KYC/AML check recently, and are
they low-risk?"**

The duplication costs €15–€40 per onboarding and converts every institution into another
breach target — directly at odds with GDPR Art. 5(1)(c) and DORA's ICT third-party risk regime.

---

## The miTch Answer

A signed predicate proof — a `DecisionProofPayload` — answering only the decision question:

```
kyc_completed_within_24m: ✓
aml_risk_band:            low
sanctions_clear:          ✓
pep_screened_within_12m:  ✓
jurisdiction:             EU
issued_by:                <bank LEI / DID>
valid_until:              <freshness window>
```

Name: not shared. DOB: not shared. ID scan: not shared. Address: not shared.
Transaction history: never requested.

The relying party gets exactly enough to clear onboarding or a step-up gate. The wallet binds
the proof to the requesting verifier's DID and a fresh nonce, so it cannot be replayed elsewhere.

---

## Data Sources (Ingestion)

### Path A — Issuing-bank credential (recommended)

The bank that performed the original KYC issues an SD-JWT Verifiable Credential over OID4VCI.

- Issuance: `@askmi/oid4vci` (wallet-side), bank acts as issuer.
- Claims: `kyc_completed_at`, `aml_risk_band`, `sanctions_screened_at`, `pep_screened_at`,
  `residency_jurisdiction`, `birthDate`.
- Advantage: the regulated entity that owns the liability remains the issuer of record.

### Path B — PSD2 / Open Banking attribute (for solvency-style predicates)

For affordability or solvency predicates, transaction data is pulled under an AISP licence
(directly or via an aggregator such as Klarna Kosma / Tink), processed **locally**, reduced to a
predicate, and the raw data is destroyed.

- Authentication: bank SCA (OAuth2 / OIDC).
- Output: e.g. `monthly_inflow_gte`, never the statement lines.

**miTch reduces whichever source is available to the same predicate shape. The verifier never
sees which path produced it.**

---

## The Transformation — What the Module Does

The relying party sends a `PredicateRequest` (`@askmi/shared-types`):

```
predicates:  [ kyc-reusable-v1 ]
verifierDid: did:web:neobank-b.example
nonce:       <random>
purpose:     "Account opening — reusable KYC reliance"
```

The wallet evaluates the predicate DSL locally against the bank credential:

```
PredicateClause  path=credentialSubject.kycCompletedAt op=gte  type=date    value=now-24m
PredicateClause  path=credentialSubject.amlRiskBand    op=in   type=string[] value=[low,medium]
PredicateClause  path=credentialSubject.sanctionsClear op=eq   type=boolean value=true
PredicateClause  path=credentialSubject.residency      op=eq   type=string  value=EU
```

The policy engine (`@askmi/policy-engine`) applies fail-closed checks before any proof is built:
freshness, issuer trust, revocation, jurisdiction. If all clauses pass → the wallet emits a
signed `DecisionProofPayload`. If not → a deny code, never a partial disclosure.

---

## What the Verifier Receives

| Data field                       | Shared? | Why                                         |
| -------------------------------- | ------- | ------------------------------------------- |
| `kyc_completed_within_24m: true` | ✅ Yes  | The decision-relevant fact                  |
| `aml_risk_band: low`             | ✅ Yes  | Risk-based onboarding requirement           |
| `sanctions_clear: true`          | ✅ Yes  | Mandatory screening outcome                 |
| `issuer LEI/DID`                 | ✅ Yes  | Which regulated entity attested             |
| `valid_until`                    | ✅ Yes  | Freshness bound (prevents stale reliance)   |
| `decision_id` + `nonce` binding  | ✅ Yes  | Anti-replay, bound to this verifier         |
| Full legal name                  | ❌ No   | Not needed to clear the gate                |
| Date of birth                    | ❌ No   | `age_gte` predicate suffices                |
| ID document scan                 | ❌ No   | Never leaves the issuing bank               |
| Residential address              | ❌ No   | `jurisdiction_eq` predicate suffices        |
| Transaction history              | ❌ No   | Reduced to predicate locally, raw destroyed |

---

## Verifier Integration (Relying-Party Side)

```typescript
import { VerifierSDK } from '@askmi/verifier-sdk';

const sdk = new VerifierSDK({
  verifierDid: 'did:web:neobank-b.example',
  privateKey: await getMyPrivateKey(),
  replayCheck: async (nonce, decisionId) => {
    const seen = await db.has(nonce);
    if (!seen) await db.save(nonce);
    return seen; // true → ReplayDetectedError
  },
});

app.post('/onboard/verify', async (req, res) => {
  try {
    const result = await sdk.verifyPresentation(req.body);
    // result.proof.allPassed === true → reuse KYC, skip re-collection
    await worm.appendReceipt(result.proof); // GDPR Art. 32 evidence
    res.json({ onboardingPath: 'reuse-kyc' });
  } catch (err) {
    if (err.name === 'ReplayDetectedError') return res.status(409).end();
    res.status(400).send('Verification failed'); // anti-oracle: generic
  }
});
```

The verifier stores **only** the WORM receipt (hashed binding + booleans), not customer PII.

---

## Example Flows

1. **Cross-border neobank onboarding.** A Sparkasse customer opens an Austrian neobank account
   and presents a reusable KYC proof. Neobank B skips €15–€40 of re-onboarding and holds no
   new identity copy.
2. **AISP solvency check without transactions.** A lending aggregator requests
   `kyc_completed_within_24m AND monthly_inflow_gte=<x>`; the bank statement never crosses the
   boundary — only the booleans do.
3. **Crypto Travel Rule (TFR / MiCA).** For a transfer above €1,000, exchange A asks exchange B
   for `customer_kyc_completed AND sanctions_clear AND jurisdiction_eq=EU` before initiating —
   counterparty assurance with no dossier exchange.

---

## Regulatory Context

| Regulation               | Relevance                                                      |
| ------------------------ | -------------------------------------------------------------- |
| GDPR Art. 5(1)(c)        | Data minimisation — predicate instead of dossier               |
| GDPR Art. 32             | WORM receipts as integrity-protected processing evidence       |
| DORA (Jan 2025), Art. 28 | Less PII custody → smaller ICT third-party breach surface      |
| 6AMLD Art. 8             | Risk-based ongoing due diligence permits reliance on prior KYC |
| EBA/GL/2022/15           | Remote onboarding + reliance on third-party due diligence      |
| eIDAS 2.0 / EUDIW        | Bank attestation as a wallet credential                        |
| MiCA + TFR (Travel Rule) | CASP counterparty assurance above thresholds                   |

---

## Packages Used

| Package                        | Role in this module                                        |
| ------------------------------ | ---------------------------------------------------------- |
| `@askmi/policy-engine`         | Fail-closed evaluation; `jurisdiction.ts`, `geo-scope.ts`  |
| `@askmi/predicates`            | DSL evaluation (`gte`, `in`, `eq`) over bank credential    |
| `@askmi/shared-types`          | `PredicateRequest`, `DecisionProofPayload` shapes          |
| `@askmi/shared-crypto`         | Pairwise DID per verifier; ECDSA proof; PQC migration path |
| `@askmi/oid4vci`               | Bank-issued SD-JWT VC issuance                             |
| `@askmi/oid4vp`                | Presentation flow                                          |
| `@askmi/verifier-sdk`          | Relying-party verification + replay-check hook             |
| `@askmi/revocation-statuslist` | Fail-closed if KYC credential is revoked                   |
| `@askmi/audit-log`             | WORM receipts for supervisory inspection                   |

Relevant deny codes (`@askmi/policy-engine` → `deny-reason-codes.ts`):
`DENY_CREDENTIAL_TOO_OLD`, `DENY_CREDENTIAL_REVOKED`, `DENY_UNTRUSTED_ISSUER`,
`DENY_JURISDICTION_INCOMPATIBLE`, `DENY_BINDING_NONCE_REPLAY`, `DENY_STATUS_SOURCE_UNAVAILABLE`.

---

## Open Questions for This Module

- Which credential schema do EU banks converge on for a reusable KYC attestation
  (SD-JWT VC claim set)? Needs an issuer design partner.
- Freshness window: is 24 months defensible for low-risk bands under 6AMLD, or should it be
  risk-band-dependent (e.g. 12 months for medium)?
- AISP path: aggregator-first (Klarna Kosma / Tink) vs. own FMA/BaFin registration — see
  `docs/vision/REGULATORY_CALENDAR.md`.
- Liability framing: does the relying party need a written reliance agreement with the issuing
  bank, or does the signed credential + status list suffice as evidence?

---

## Next Step

Talk to one neobank MLRO about whether a freshness-bound reusable-KYC proof would let them skip
re-collection under their current EBA reliance interpretation. Talk to one issuing bank about
exposing a KYC attestation as an SD-JWT VC. That conversation is validation, not sales.
