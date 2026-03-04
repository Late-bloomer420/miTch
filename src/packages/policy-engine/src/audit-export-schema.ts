/**
 * @module @mitch/policy-engine/audit-export-schema
 *
 * Formal Audit Export Schema for external auditor handoff.
 * Aligned with METADATA_BUDGET_V1 — no PII, no stable cross-RP correlators.
 *
 * AI-04 / P1: Define final audit export schema.
 */

import { DenyReasonCode } from './deny-reason-codes';

// ─── Core Export Record ─────────────────────────────────────────────

/**
 * A single audit export record suitable for external auditor consumption.
 * Contains NO PII. All identifiers are salted hashes.
 */
export interface AuditExportRecord {
  /** ISO-8601 timestamp bucketed to 5-minute granularity */
  timestampBucket: string;
  /** Ephemeral request correlation ID (UUID v4) */
  requestId: string;
  /** Salted SHA-256 of verifier DID — rotated periodically */
  verifierHash: string;
  /** Policy engine verdict */
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  /** Deny reason code (only present when verdict=DENY) */
  reasonCode?: DenyReasonCode;
  /** Protocol version used for this decision */
  protocolVersion: string;
  /** Capability profile negotiated for this session */
  capabilityProfile: string;
}

// ─── Export Bundle ──────────────────────────────────────────────────

/**
 * Complete audit export bundle for external auditor handoff.
 */
export interface AuditExportBundle {
  /** Schema version for forward compatibility */
  schemaVersion: '1.0';
  /** ISO-8601 export timestamp */
  exportedAt: string;
  /** Records in this export bundle */
  records: AuditExportRecord[];
  /** SHA-256 hash of canonicalized records array */
  bundleHash: string;
  /** Total record count (for integrity cross-check) */
  recordCount: number;
}

// ─── JSON Schema (programmatic) ────────────────────────────────────

/**
 * JSON Schema for AuditExportRecord, usable by external auditors
 * for validation without access to TypeScript types.
 */
export const AUDIT_EXPORT_RECORD_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://mitch.id/schemas/audit-export-record/v1',
  title: 'AuditExportRecord',
  description: 'Single policy-engine decision record for external audit. Contains NO PII.',
  type: 'object',
  required: [
    'timestampBucket',
    'requestId',
    'verifierHash',
    'verdict',
    'protocolVersion',
    'capabilityProfile',
  ],
  properties: {
    timestampBucket: {
      type: 'string',
      format: 'date-time',
      description: 'ISO-8601 timestamp bucketed to 5-minute granularity.',
    },
    requestId: {
      type: 'string',
      format: 'uuid',
      description: 'Ephemeral request correlation ID.',
    },
    verifierHash: {
      type: 'string',
      pattern: '^[a-f0-9]{64}$',
      description: 'Salted SHA-256 hex digest of verifier identifier.',
    },
    verdict: {
      type: 'string',
      enum: ['ALLOW', 'DENY', 'PROMPT'],
    },
    reasonCode: {
      type: 'string',
      description: 'Deny reason code from DenyReasonCode enum. Present only when verdict=DENY.',
    },
    protocolVersion: {
      type: 'string',
      description: 'Protocol version (e.g., "OID4VP-draft-23").',
    },
    capabilityProfile: {
      type: 'string',
      description: 'Negotiated capability profile (e.g., "sd-jwt-vc+kb").',
    },
  },
  additionalProperties: false,
} as const;

/**
 * JSON Schema for the full export bundle.
 */
export const AUDIT_EXPORT_BUNDLE_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://mitch.id/schemas/audit-export-bundle/v1',
  title: 'AuditExportBundle',
  description: 'Complete audit export bundle for external auditor handoff.',
  type: 'object',
  required: ['schemaVersion', 'exportedAt', 'records', 'bundleHash', 'recordCount'],
  properties: {
    schemaVersion: { type: 'string', const: '1.0' },
    exportedAt: { type: 'string', format: 'date-time' },
    records: {
      type: 'array',
      items: { $ref: 'https://mitch.id/schemas/audit-export-record/v1' },
    },
    bundleHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    recordCount: { type: 'integer', minimum: 0 },
  },
  additionalProperties: false,
} as const;

// ─── PII Guard ─────────────────────────────────────────────────────

/**
 * Fields that MUST NEVER appear in an export record.
 * Superset of FORBIDDEN_LOG_FIELDS from audit-metadata.ts.
 */
export const FORBIDDEN_EXPORT_FIELDS = [
  'subjectDid',
  'name',
  'birthDate',
  'email',
  'rawVerifierId',
  'verifierId',
  'age',
  'address',
  'phone',
  'nationalId',
  'ipAddress',
] as const;

/**
 * Validate that a serialized record contains none of the forbidden PII fields.
 * Returns list of violations (empty = clean).
 */
export function validateNoPii(record: Record<string, unknown>): string[] {
  const keys = Object.keys(record);
  const _serialized = JSON.stringify(record);
  const violations: string[] = [];

  for (const forbidden of FORBIDDEN_EXPORT_FIELDS) {
    if (keys.includes(forbidden)) {
      violations.push(`Forbidden field present as key: ${forbidden}`);
    }
  }

  return violations;
}
