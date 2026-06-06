# Audit Export Schema v1.1

**Status:** Normative
**Finding:** AI-04 (P1)
**Date:** 2026-06-06
**Depends on:** [METADATA_BUDGET_V1](./METADATA_BUDGET_V1.md), [ADR-011](../compliance/ADR/ADR-011.md)

## Purpose

Defines the formal Tier-2 schema for audit data exported to external auditors,
supervisory authorities, or controller-side compliance review. The schema is
designed to be:

- **Minimised:** no raw PII, no stable cross-RP user correlators.
- **Accountable:** lawful basis, purpose, data categories, policy hash,
  retention deadline, controller, and RoPA reference are explicit.
- **Tamper-evident:** records are hash-chained and the bundle has a stable
  bundle hash and chain tip.

This document does not set jurisdiction-specific retention periods. Those are
configuration parameters and require DPO/legal sign-off per sector and member
state.

## Two-Tier Boundary

Tier 1 is the wallet-held user transaction history. It may contain user-visible
detail because it lives under the user's control and supports access, review,
reporting, and deletion.

Tier 2 is the external audit export described here. It must remain PII-free and
must not become a substitute data lake for wallet history.

Sector overlays, such as AML, health, child protection, or tax retention, must
use a separate attributable store when Union or national law requires it. They
are not mixed into the Tier-2 export.

## AuditExportRecord

Each record represents a single policy-engine decision.

| Field | Type | Required | Description |
|---|---|---|---|
| `timestampBucket` | `string` (ISO-8601) | Yes | Rounded to 5-minute granularity |
| `requestId` | `string` (UUID v4) | Yes | Ephemeral request correlation ID |
| `verifierHash` | `string` (hex, 64 chars) | Yes | Salted SHA-256 of verifier identifier |
| `verdict` | `"ALLOW" \| "DENY" \| "PROMPT"` | Yes | Policy engine decision |
| `reasonCode` | `DenyReasonCode` | No | Present only when `verdict=DENY` |
| `protocolVersion` | `string` | Yes | Example: `"OID4VP-draft-23"` |
| `capabilityProfile` | `string` | Yes | Example: `"sd-jwt-vc+kb"` |
| `legalBasis` | `LawfulBasis` | Yes | One of the six GDPR Art. 6(1) bases |
| `purposeCode` | `string` token | Yes | Purpose-limitation code, not free text |
| `dataCategories` | `string[]` tokens | Yes | Claim names touched, never claim values |
| `policyHash` | `string` (hex, 64 chars) | Yes | SHA-256 of the authorising policy version |
| `retentionUntil` | `string` (ISO-8601) | Yes | Deadline after which this record expires |
| `prevRecordHash` | `string` (hex, 64 chars) | Yes | Previous record hash; genesis is 64 zeros |
| `recordHash` | `string` (hex, 64 chars) | Yes | SHA-256 over canonical record content |

`additionalProperties: false` — no extra fields permitted.

## AuditExportBundle

Wraps records for handoff with integrity guarantees.

| Field | Type | Description |
|---|---|---|
| `schemaVersion` | `"1.1"` | Schema version (pinned) |
| `exportedAt` | `string` (ISO-8601) | Export timestamp |
| `controller` | `AuditController` | Controller name, role contact, RoPA reference |
| `records` | `AuditExportRecord[]` | Ordered record chain |
| `bundleHash` | `string` (hex, 64 chars) | SHA-256 of canonicalized records |
| `chainTipHash` | `string` (hex, 64 chars) | Last `recordHash`, or genesis hash for empty exports |
| `recordCount` | `integer` | Record count for integrity cross-check |

## PII Exclusion

The following fields MUST NEVER appear anywhere in export records, including
nested debug payloads:

```text
subjectDid, name, dateOfBirth, email, rawVerifierId,
verifierId, age, address, phone, nationalId, ipAddress
```

`purposeCode` and `dataCategories` must be code tokens matching:

```text
^[A-Za-z][A-Za-z0-9_.:-]{0,127}$
```

This blocks free-text purposes and obvious raw values from entering the audit
surface. The `validateNoPii()` function enforces the key ban recursively and
checks purpose/data-category token shape.

## Anti-Correlation Properties

Per METADATA_BUDGET_V1:

- Verifier identity is a salted hash only; salt rotation remains profile-based.
- Timestamps are bucketed to 5-minute granularity.
- No raw subject DID or stable cross-RP user identifier is present.
- Claim values are never exported; only claim/category names are present.

## Integrity Verification

Machine verifiers can:

1. Recompute each `recordHash` from canonical record content.
2. Verify that each `prevRecordHash` equals the predecessor's `recordHash`.
3. Recompute `bundleHash` from the ordered records array.
4. Compare `recordCount` with `records.length`.
5. Compare `chainTipHash` with the last `recordHash`.

Helpers are exported from `src/packages/policy-engine/src/audit-export-schema.ts`:

- `appendAuditRecord()`
- `computeRecordHash()`
- `computeBundleHash()`
- `createAuditExportBundle()`
- `verifyHashChain()`
- `verifyAuditExportBundle()`
- `validateNoPii()`

## JSON Schema

Machine-readable JSON Schemas are exported from:

```text
src/packages/policy-engine/src/audit-export-schema.ts
```

Schema IDs:

- `https://mitch.id/schemas/audit-export-record/v1.1`
- `https://mitch.id/schemas/audit-export-bundle/v1.1`

## Source Files

| File | Purpose |
|---|---|
| `src/packages/policy-engine/src/audit-export-schema.ts` | Types, JSON Schemas, PII validator, hash-chain helpers |
| `src/packages/policy-engine/src/__tests__/audit-export-schema.test.ts` | Schema, PII, hash-chain, and bundle tests |
| `src/packages/policy-engine/src/audit-metadata.ts` | Underlying minimised audit metadata |
| `src/packages/policy-engine/src/deny-reason-codes.ts` | Canonical `DenyReasonCode` enum |
