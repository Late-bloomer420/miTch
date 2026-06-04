# Module Concept: Supply Chain & Professional Credentials

## "Verify the Certificate and the License — Not the Contracts or the Person"

> Not implementation-ready. Concept and design only.
> Verifier-side integration via `@askmi/verifier-sdk`; in-person via `@askmi/mdoc`
> (ISO 18013-5). Companion business case: `03_business_case_supply_chain_credentials.md`.

---

## The Problem

Two related B2B questions, both currently answered by over-collecting data.

**Supplier qualification (CSRD/CSDDD/CBAM):** a buyer must prove its suppliers hold valid
certifications and pass due-diligence screening — and keep that evidence current across years and
sub-tiers. Today this is a folder of PDFs, manually re-collected and impossible to verify at a
glance.

**Site / professional access:** a worker arriving on a construction or industrial site shows a
physical license and ID card, exposing:

- Full name and photo
- National ID / social-security number
- Date of birth
- Home address

For a single question: **"Is this person currently licensed for this trade, recognised in this
country?"** — and for suppliers, **"Is this certificate valid, recent, and from an accredited
body?"**

The duplication is slow and unverifiable; the worker-data flow is a GDPR Art. 28 liability for
every site operator.

---

## The miTch Answer

A signed predicate proof carrying only the qualification fact:

```
# Supplier
iso_27001_valid:       ✓
iso_14001_valid:       ✓
last_audit_within_12m: ✓
forced_labour_screened:✓
issued_by:             <accredited body DID / LEI>

# Worker (mdoc on a site card)
license_valid:         ✓  (class A electrician)
recognised_in:         DE
valid_until:           <expiry>
```

For suppliers: contracts and full audit reports stay with the supplier and auditor. For workers:
name, photo, ID number, and address never leave the wallet/card — only the license boolean and
its jurisdiction recognition.

---

## Data Sources (Ingestion)

### Path A — Accredited-body audit credential

An accredited body (TÜV, DEKRA, BSI) issues an audit/certification VC over `@askmi/oid4vci`
(`iso_27001_valid`, `iso_14001_valid`, `audit_date`, `cbam_co2_per_tonne`). Only accredited
issuers are on the policy trust list; others → `DENY_UNTRUSTED_ISSUER`.

### Path B — Professional license credential (mdoc)

A chamber / licensing authority issues a license as an ISO 18013-5 mdoc (`@askmi/mdoc`) so it can
be presented by NFC tap at a site gate, offline if needed. Suspension revokes it via
`@askmi/revocation-statuslist`.

### Path C — Tier-2 rollup attestation

A Tier-1 supplier presents an anchored proof that _its_ Tier-2 holds a valid certificate, without
exposing the Tier-1→Tier-2 contract. Multi-year chains are anchored via `@askmi/anchor-service`
for non-repudiation.

---

## The Transformation — What the Module Does

The buyer sends a `PredicateRequest`:

```
predicates:  [ supplier-qualification-v1 ]
verifierDid: did:web:oem-buyer.example
nonce:       <random>
purpose:     "Supplier qualification — CSRD evidence"
```

The policy engine (`@askmi/policy-engine`) evaluates fail-closed:

```
PredicateClause path=cert.iso27001.valid     op=eq  type=boolean value=true
PredicateClause path=cert.iso14001.valid     op=eq  type=boolean value=true
PredicateClause path=audit.date              op=gte type=date    value=now-12m
PredicateClause path=screening.forcedLabour  op=eq  type=boolean value=true
```

- Stale audit → `DENY_CREDENTIAL_TOO_OLD`; non-accredited issuer → `DENY_UNTRUSTED_ISSUER`.
- For workers, cross-border recognition uses `jurisdiction.ts`; a license not recognised in the
  site country → `DENY_JURISDICTION_INCOMPATIBLE`.
- A suspended license / withdrawn certificate → `DENY_CREDENTIAL_REVOKED`.

---

## What the Verifier (Buyer / Site Operator) Receives

| Data field                        | Shared? | Why                                          |
| --------------------------------- | ------- | -------------------------------------------- |
| `iso_27001_valid: true`           | ✅ Yes  | Qualification fact                           |
| `last_audit_within_12m: true`     | ✅ Yes  | Freshness / CSRD currency requirement        |
| `forced_labour_screened: true`    | ✅ Yes  | Due-diligence requirement                    |
| `license_valid` + `recognised_in` | ✅ Yes  | Site-access authorisation                    |
| `issuer (accredited body)`        | ✅ Yes  | Trust anchor                                 |
| `decision_id` + `nonce` binding   | ✅ Yes  | Anti-replay, bound to this buyer             |
| Supplier contracts                | ❌ No   | Never leave the supplier                     |
| Full audit report                 | ❌ No   | Stays with auditor; only the boolean travels |
| Worker name / photo / ID number   | ❌ No   | Not needed to verify the license             |
| Worker home address / DOB         | ❌ No   | Never                                        |

---

## Verifier Integration

```typescript
import { VerifierSDK } from '@askmi/verifier-sdk';

const sdk = new VerifierSDK({
  verifierDid: 'did:web:oem-buyer.example',
  privateKey: await getMyPrivateKey(),
  replayCheck: async (nonce) => {
    const seen = await db.has(nonce);
    if (!seen) await db.save(nonce);
    return seen;
  },
});

app.post('/supplier/qualify', async (req, res) => {
  try {
    const { proof } = await sdk.verifyPresentation(req.body);
    if (!proof.allPassed) return res.status(403).send('Not qualified'); // anti-oracle
    await worm.appendReceipt(proof); // CSRD/CSDDD evidence pack
    res.json({ qualified: true });
  } catch (err) {
    if (err.name === 'ReplayDetectedError') return res.status(409).end();
    res.status(400).send('Verification failed');
  }
});
```

For on-site worker checks, the same proof is carried as an `@askmi/mdoc` presentation over NFC and
verified by a handheld reader — no name, no ID number, decision in seconds.

---

## Example Flows

1. **Tier-2 rollup.** An OEM verifies that a Tier-1 supplier's Tier-2 holds a valid ISO 14001
   certificate via an anchored proof chain — without seeing the Tier-1→Tier-2 contract.
2. **Cross-border professional license.** An Austrian electrician on a German site taps an mdoc
   card; the reader gets `license_class_A_valid AND recognised_in=DE` in seconds — no
   Sozialversicherungsnummer, no name.
3. **CBAM emissions attestation.** A steel supplier presents `embedded_co2_per_tonne_lte=<x>`
   issued by an EU-recognised verifier; the importer logs the WORM receipt for customs audit.

---

## Regulatory Context

| Regulation                  | Relevance                                               |
| --------------------------- | ------------------------------------------------------- |
| CSRD (2022/2464) + ESRS     | Auditable supplier ESG evidence from FY2024/2025        |
| CSDDD                       | Supply-chain due diligence with chain-of-evidence       |
| CBAM                        | Verified embedded-emissions data                        |
| EU Forced Labour Regulation | Verified labour-standard attestations                   |
| Directive 2005/36/EC        | Cross-border recognition of professional qualifications |
| GDPR Art. 28                | Predicate-only worker checks limit processor liability  |

---

## Packages Used

| Package                        | Role in this module                                  |
| ------------------------------ | ---------------------------------------------------- |
| `@askmi/policy-engine`         | Fail-closed eval; `jurisdiction.ts` recognition      |
| `@askmi/predicates`            | Certificate / license DSL (`eq`, `gte`, `exists`)    |
| `@askmi/oid4vci`               | Accredited-body credential issuance                  |
| `@askmi/mdoc`                  | ISO 18013-5 license for NFC site-access tap          |
| `@askmi/anchor-service`        | Merkle anchoring of multi-year audit chains          |
| `@askmi/revocation-statuslist` | Withdrawn certificate / suspended license revocation |
| `@askmi/verifier-sdk`          | Buyer-side verification + replay-check               |
| `@askmi/audit-log`             | WORM receipts as CSRD/CSDDD evidence                 |

Relevant deny codes: `DENY_CREDENTIAL_TOO_OLD`, `DENY_UNTRUSTED_ISSUER`,
`DENY_JURISDICTION_INCOMPATIBLE`, `DENY_CREDENTIAL_REVOKED`, `DENY_BINDING_NONCE_REPLAY`.

---

## Open Questions for This Module

- Which accredited bodies will issue audit/certification VCs, and on what schema? An issuer design
  partner (e.g. one TÜV entity) would anchor the pilot.
- Tier-2 rollup: what is the privacy/anchoring model that proves a sub-supplier's status without
  exposing the intermediate commercial relationship?
- Professional licenses: which authorities can issue ISO 18013-5 mdocs, and how is 2005/36/EC
  recognition encoded as jurisdiction data?
- CBAM: which verifier bodies are EU-recognised for embedded-emissions attestations?

---

## Next Step

Talk to one OEM procurement / supplier-risk lead about whether an anchored, freshness-bound
supplier-qualification proof would replace their PDF-collection process for CSRD evidence. Talk to
one accredited body about issuing a certification VC. That conversation is validation, not sales.
