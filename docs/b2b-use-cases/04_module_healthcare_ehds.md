# Module Concept: Healthcare / EHDS — Inter-System Access Mediation

## "Prove the Permission, Not the Patient"

> Not implementation-ready. Concept and design only.
> Builds on existing EHDS work — see `docs/00-welt/49_EHDS_Compliance_Map.md` and
> `docs/00-welt/48_EHDS_Gap_Analysis_and_Tasks.md`. Companion business case:
> `04_business_case_healthcare_ehds.md`.

---

## The Problem

Cross-organisation health workflows transfer the whole record to answer a narrow question.
To confirm a patient is insured, a full patient summary is shared. To run an aggregate study,
identifiable records are handed to a research body. A paper-equivalent prescription can be
redeemed at two pharmacies.

A typical inter-system exchange today moves:

- Full patient summary (diagnoses, medications, allergies, history)
- Insurance and demographic identifiers
- Practitioner and institutional identifiers
- For research: identifiable per-patient records

For questions as small as: **"Is this person insured? Is this clinician credentialed? Did the
patient consent to this use? Has this prescription already been dispensed?"**

Health data is GDPR Art. 9 special-category; hospitals are NIS2 essential entities. Every
over-disclosure is a privacy, compliance, and security liability at once.

---

## The miTch Answer

A signed permission proof carrying only the decision-relevant facts:

```
insurance_active:          ✓
practitioner_credentialed: ✓
consent_primary_use:       { scope: "treatment", expires_at: ... }
consent_secondary_use:     opt-out (default)
hdab_permit_present:       ✗ (research path only)
jurisdiction:              eu-only
valid_until:               <short window>
```

The full record stays in the EHR / ELGA / national patient summary. The requester gets the
permission, not the patient. Break-glass and single-use rules are enforced before any payload is
released.

---

## Data Sources (Ingestion)

### Path A — Patient summary / insurance credential

The source system (ELGA-style, or a national patient-summary service over `@mitch/oid4vci`)
issues SD-JWT VCs for insurance status and consent state. Selective disclosure
(`@askmi/shared-crypto`) exposes only the requested claim.

### Path B — Practitioner credential

A medical chamber / registry issues a practitioner credential (`credentialed`, `specialty`,
`jurisdiction`). Suspension revokes it via `@askmi/revocation-statuslist`.

### Path C — HDAB permit (secondary use)

A Health Data Access Body issues a permit credential. Without it, secondary-use requests fail
closed (`DENY_HDAB_PERMIT_REQUIRED`); with a global opt-out set, they fail with
`DENY_SECONDARY_USE_DENIED` even if a permit exists.

---

## The Transformation — What the Module Does

The requester sends a `PredicateRequest`:

```
predicates:  [ ehds-treatment-access-v1 ]
verifierDid: did:de:insurer.example
nonce:       <random>
purpose:     "Treatment eligibility check"
```

The policy engine (`@mitch/policy-engine`) evaluates EHDS rules fail-closed:

```
PredicateClause path=insurance.active            op=eq     type=boolean value=true
PredicateClause path=practitioner.credentialed   op=eq     type=boolean value=true
PredicateClause path=consent.primaryUse.scope    op=eq     type=string  value=treatment
geoScope        eu-only                                  → DENY_GEO_SCOPE_VIOLATION if outside
```

- Secondary use: `denySecondaryUse` → `DENY_SECONDARY_USE_DENIED`; missing permit →
  `DENY_HDAB_PERMIT_REQUIRED` (mapped in `49_EHDS_Compliance_Map.md`).
- ePrescription: bound to a single-use nullifier (`@mitch/predicates` → `nullifier.ts`); second
  redemption → `DENY_CREDENTIAL_DISPENSED`.
- Emergency: WebAuthn step-up (`@mitch/webauthn-verifier`) → grant logged as
  `ALLOW_BREAK_GLASS_ACTIVATED`, patient notified.

---

## What the Verifier Receives

| Data field                        | Shared? | Why                                       |
| --------------------------------- | ------- | ----------------------------------------- |
| `insurance_active: true`          | ✅ Yes  | Eligibility decision                      |
| `practitioner_credentialed: true` | ✅ Yes  | Authorisation to request                  |
| `consent_primary_use.scope`       | ✅ Yes  | Lawful-basis confirmation                 |
| `hdab_permit_present` (research)  | ✅ Yes  | Secondary-use gate                        |
| `decision_id` + `nonce` binding   | ✅ Yes  | Anti-replay, bound to this requester      |
| Full patient summary              | ❌ No   | Stays in the source EHR / ELGA            |
| Diagnoses / medication history    | ❌ No   | Not needed to confirm eligibility         |
| Insurance / national identifiers  | ❌ No   | Reduced to `insurance_active` boolean     |
| Identifiable research records     | ❌ No   | Secondary use is permit + aggregate gated |

---

## Verifier Integration (Requesting-System Side)

```typescript
import { VerifierSDK } from '@mitch/verifier-sdk';

const sdk = new VerifierSDK({
  verifierDid: 'did:de:insurer.example',
  privateKey: await getMyPrivateKey(),
  replayCheck: async (nonce) => {
    const seen = await db.has(nonce);
    if (!seen) await db.save(nonce);
    return seen;
  },
});

app.post('/eligibility/verify', async (req, res) => {
  try {
    const { proof } = await sdk.verifyPresentation(req.body);
    if (!proof.allPassed) return res.status(403).send('Not eligible'); // anti-oracle
    await worm.appendReceipt(proof); // EHDS Art. 31 audit export
    res.json({ eligible: true });
  } catch (err) {
    if (err.name === 'ReplayDetectedError') return res.status(409).end();
    res.status(400).send('Verification failed');
  }
});
```

---

## Example Flows

1. **Cross-border emergency (break-glass).** A French tourist is treated in Tirol; the clinician
   triggers a WebAuthn step-up and receives `insurance_active` + a minimal allergy/medication
   subset under an emergency legal basis. The grant is logged (`ALLOW_BREAK_GLASS_ACTIVATED`) and
   the patient notified. The full summary is never transferred.
2. **ePrescription single-use.** A clinician issues a nullifier-bound prescription credential; the
   pharmacy redeems it once; a second pharmacy attempt → `DENY_CREDENTIAL_DISPENSED`.
3. **HDAB-gated research.** A research org presents an HDAB permit; the engine checks
   `hdab_permit_present AND consent_secondary_use_opt_in=true` and allows only an aggregate query
   — never raw per-patient records.

---

## Regulatory Context

| Regulation / Article | miTch mechanism (per `49_EHDS_Compliance_Map.md`)           |
| -------------------- | ----------------------------------------------------------- |
| EHDS Art. 5          | Patient summary VC + SD-JWT                                 |
| EHDS Art. 8          | Primary-use consent + WebAuthn                              |
| EHDS Art. 8(5)       | Break-glass (`allowBreakGlass` + audit alert)               |
| EHDS Art. 11         | Secondary-use opt-out (`denySecondaryUse`)                  |
| EHDS Art. 14         | ePrescription single-use nullifier                          |
| EHDS Art. 31         | Audit export schema (`audit-export-schema.ts`)              |
| EHDS Art. 46         | HDAB permit (`requiresHdabPermit`)                          |
| GDPR Art. 9          | Special-category gating by necessity / explicit consent     |
| NIS2                 | Reduced identity transfer → smaller essential-entity breach |

---

## Packages Used

| Package                        | Role in this module                                                          |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `@mitch/policy-engine`         | EHDS rules: `denySecondaryUse`, `requiresHdabPermit`, geo-scope, break-glass |
| `@mitch/webauthn-verifier`     | Break-glass / emergency step-up                                              |
| `@mitch/predicates`            | Permission DSL; single-use `nullifier.ts` (Art. 14)                          |
| `@askmi/shared-crypto`         | SD-JWT VP, selective disclosure                                              |
| `@mitch/audit-log`             | WORM trail + Art. 31 export                                                  |
| `@askmi/revocation-statuslist` | Practitioner-suspension revocation                                           |
| `@mitch/verifier-sdk`          | Requesting-system verification + replay-check                                |
| `@mitch/anchor-service`        | Long-horizon audit anchoring (multi-year retention)                          |

Relevant deny codes: `DENY_HDAB_PERMIT_REQUIRED`, `DENY_SECONDARY_USE_DENIED`,
`DENY_GEO_SCOPE_VIOLATION`, `DENY_CREDENTIAL_DISPENSED`, `ALLOW_BREAK_GLASS_ACTIVATED`,
`DENY_CREDENTIAL_REVOKED`.

---

## Open Questions for This Module

- Which source systems (ELGA first) can issue insurance/consent state as SD-JWT VCs, and on what
  timeline relative to EHDS Phase 2 (2027)?
- Break-glass: what is the minimal allergy/medication subset acceptable to clinicians, and what
  legal basis string should be recorded?
- Secondary use: how is "aggregate-only" enforced technically once an HDAB permit is present —
  query-shape constraints, or a separate aggregation service?
- See open EHDS items in `docs/00-welt/48_EHDS_Gap_Analysis_and_Tasks.md` (break-glass and
  single-use nullifier are marked in-progress).

---

## Next Step

Talk to a hospital CIO or ELGA stakeholder about whether an inter-system **permission proof**
(insurance + credentialed + consent-in-scope) — leaving the EHR untouched — would reduce their
Art. 9 transfer surface while satisfying EHDS Art. 8/31. That conversation is validation, not sales.
