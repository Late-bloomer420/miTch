import { describe, it, expect } from 'vitest';
import { DenyReasonCode } from '../deny-reason-codes';
import {
  type AuditExportRecord,
  AUDIT_EXPORT_RECORD_JSON_SCHEMA,
  AUDIT_EXPORT_BUNDLE_JSON_SCHEMA,
  FORBIDDEN_EXPORT_FIELDS,
  validateNoPii,
} from '../audit-export-schema';
import { createAuditRecord, FORBIDDEN_LOG_FIELDS } from '../audit-metadata';

// ─── Helpers ────────────────────────────────────────────────────────

function makeRecord(overrides?: Partial<AuditExportRecord>): AuditExportRecord {
  return {
    timestampBucket: '2026-03-04T12:05:00.000Z',
    requestId: '550e8400-e29b-41d4-a716-446655440000',
    verifierHash: 'a'.repeat(64),
    verdict: 'DENY',
    reasonCode: DenyReasonCode.UNKNOWN_VERIFIER,
    protocolVersion: 'OID4VP-draft-23',
    capabilityProfile: 'sd-jwt-vc+kb',
    ...overrides,
  };
}

// ─── Schema Structure Tests ─────────────────────────────────────────

describe('AuditExportRecord JSON Schema', () => {
  it('has all required fields defined', () => {
    const required = AUDIT_EXPORT_RECORD_JSON_SCHEMA.required;
    expect(required).toContain('timestampBucket');
    expect(required).toContain('requestId');
    expect(required).toContain('verifierHash');
    expect(required).toContain('verdict');
    expect(required).toContain('protocolVersion');
    expect(required).toContain('capabilityProfile');
  });

  it('disallows additional properties', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.additionalProperties).toBe(false);
  });

  it('verifierHash must be 64-char hex', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.verifierHash.pattern).toBe('^[a-f0-9]{64}$');
  });

  it('verdict enum is exhaustive', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.verdict.enum).toEqual([
      'ALLOW', 'DENY', 'PROMPT',
    ]);
  });

  it('reasonCode is optional (not in required)', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.required).not.toContain('reasonCode');
  });
});

describe('AuditExportBundle JSON Schema', () => {
  it('schema version is pinned to 1.0', () => {
    expect(AUDIT_EXPORT_BUNDLE_JSON_SCHEMA.properties.schemaVersion.const).toBe('1.0');
  });

  it('has required fields', () => {
    const required = AUDIT_EXPORT_BUNDLE_JSON_SCHEMA.required;
    expect(required).toEqual(
      expect.arrayContaining(['schemaVersion', 'exportedAt', 'records', 'bundleHash', 'recordCount']),
    );
  });
});

// ─── PII Exclusion Tests ────────────────────────────────────────────

describe('PII exclusion', () => {
  it('FORBIDDEN_EXPORT_FIELDS is a superset of FORBIDDEN_LOG_FIELDS', () => {
    for (const field of FORBIDDEN_LOG_FIELDS) {
      expect(FORBIDDEN_EXPORT_FIELDS).toContain(field);
    }
  });

  it('a clean record passes PII validation', () => {
    const record = makeRecord();
    expect(validateNoPii(record as unknown as Record<string, unknown>)).toEqual([]);
  });

  it('detects forbidden field injected into record', () => {
    const dirty = { ...makeRecord(), email: 'test@example.com' } as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.length).toBeGreaterThan(0);
    expect(violations[0]).toContain('email');
  });

  it('detects multiple forbidden fields', () => {
    const dirty = {
      ...makeRecord(),
      subjectDid: 'did:example:123',
      birthDate: '1990-01-01',
    } as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.length).toBe(2);
  });

  it('AuditExportRecord type keys do not overlap with forbidden fields', () => {
    const record = makeRecord();
    const keys = Object.keys(record);
    for (const forbidden of FORBIDDEN_EXPORT_FIELDS) {
      expect(keys).not.toContain(forbidden);
    }
  });

  it('createAuditRecord output has no forbidden export fields', () => {
    const auditRecord = createAuditRecord({
      verifierId: 'did:web:evil.example',
      requestId: 'req-pii-test',
      timestampMs: Date.now(),
      verdict: 'DENY',
      reasonCode: DenyReasonCode.EXPIRED,
      salt: 'test-salt',
    });
    const violations = validateNoPii(auditRecord as unknown as Record<string, unknown>);
    expect(violations).toEqual([]);
  });
});

// ─── Type Correctness Tests ─────────────────────────────────────────

describe('AuditExportRecord type correctness', () => {
  it('verdict only accepts valid values', () => {
    const record = makeRecord({ verdict: 'ALLOW' });
    expect(['ALLOW', 'DENY', 'PROMPT']).toContain(record.verdict);
  });

  it('timestampBucket is valid ISO-8601', () => {
    const record = makeRecord();
    expect(new Date(record.timestampBucket).toISOString()).toBe(record.timestampBucket);
  });

  it('timestampBucket is at 5-minute boundary', () => {
    const record = makeRecord();
    const minutes = new Date(record.timestampBucket).getMinutes();
    expect(minutes % 5).toBe(0);
    expect(new Date(record.timestampBucket).getSeconds()).toBe(0);
    expect(new Date(record.timestampBucket).getMilliseconds()).toBe(0);
  });

  it('verifierHash is 64-char lowercase hex', () => {
    const record = makeRecord();
    expect(record.verifierHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('ALLOW record has no reasonCode', () => {
    const record = makeRecord({ verdict: 'ALLOW', reasonCode: undefined });
    expect(record.reasonCode).toBeUndefined();
  });

  it('protocolVersion and capabilityProfile are present', () => {
    const record = makeRecord();
    expect(record.protocolVersion).toBeTruthy();
    expect(record.capabilityProfile).toBeTruthy();
  });
});
