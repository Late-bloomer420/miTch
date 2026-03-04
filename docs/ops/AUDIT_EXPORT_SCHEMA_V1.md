# Audit Export Schema v1

**Status:** Normative  
**Finding:** AI-04 (P1)  
**Date:** 2026-03-04  
**Depends on:** [METADATA_BUDGET_V1](./METADATA_BUDGET_V1.md)

## Purpose

Defines the formal schema for audit data exported to external auditors. The schema ensures **zero PII leakage** while providing sufficient decision metadata for compliance review.

## AuditExportRecord

Each record represents a single policy-engine decision.

| Field | Type | Required | Description |
|---|---|---|---|
| `timestampBucket` | `string` (ISO-8601) | ✅ | Rounded to 5-minute granularity |
| `requestId` | `string` (UUID v4) | ✅ | Ephemeral request correlation ID |
| `verifierHash` | `string` (hex, 64 chars) | ✅ | Salted SHA-256 of verifier DID |
| `verdict` | `"ALLOW" \| "DENY" \| "PROMPT"` | ✅ | Policy engine decision |
| `reasonCode` | `DenyReasonCode` | ❌ | Present only when `verdict=DENY` |
| `protocolVersion` | `string` | ✅ | e.g., `"OID4VP-draft-23"` |
| `capabilityProfile` | `string` | ✅ | e.g., `"sd-jwt-vc+kb"` |

**`additionalProperties: false`** — no extra fields permitted.

## AuditExportBundle

Wraps records for handoff with integrity guarantees.

| Field | Type | Description |
|---|---|---|
| `schemaVersion` | `"1.0"` | Schema version (pinned) |
| `exportedAt` | `string` (ISO-8601) | Export timestamp |
| `records` | `AuditExportRecord[]` | Decision records |
| `bundleHash` | `string` (hex, 64 chars) | SHA-256 of canonicalized records |
| `recordCount` | `integer` | Record count for integrity cross-check |

## PII Exclusion (Normative)

The following fields MUST NEVER appear in export records:

```
subjectDid, name, birthDate, email, rawVerifierId,
verifierId, age, address, phone, nationalId, ipAddress
```

This is a superset of `FORBIDDEN_LOG_FIELDS` from `audit-metadata.ts`. The `validateNoPii()` function enforces this programmatically.

## Anti-Correlation Properties

Per METADATA_BUDGET_V1:
- **Verifier identity:** Salted hash only; salt rotated monthly per deployment
- **Timestamps:** 5-minute bucket granularity prevents timing correlation
- **No stable cross-RP correlators** possible from exported data

## JSON Schema

Machine-readable JSON Schemas are exported from:
```
src/packages/policy-engine/src/audit-export-schema.ts
```

- `AUDIT_EXPORT_RECORD_JSON_SCHEMA` — validates individual records
- `AUDIT_EXPORT_BUNDLE_JSON_SCHEMA` — validates complete bundles

Schema IDs:
- `https://mitch.id/schemas/audit-export-record/v1`
- `https://mitch.id/schemas/audit-export-bundle/v1`

## Auditor Integration

External auditors receive:
1. An `AuditExportBundle` JSON file
2. This document as schema reference
3. The JSON Schema files for automated validation

Auditors can verify:
- Bundle integrity via `bundleHash`
- Record count via `recordCount`
- Schema compliance via JSON Schema validation
- No PII present (all identifier fields are hashed)

## Source Files

| File | Purpose |
|---|---|
| `src/packages/policy-engine/src/audit-export-schema.ts` | Types, JSON Schemas, PII validator |
| `src/packages/policy-engine/src/__tests__/audit-export-schema.test.ts` | Validation tests |
| `src/packages/policy-engine/src/audit-metadata.ts` | Underlying `AuditRecord` + `createAuditRecord()` |
| `src/packages/policy-engine/src/deny-reason-codes.ts` | Canonical `DenyReasonCode` enum |
