import { describe, it, expect } from 'vitest';
import { DenyReasonCode } from '../deny-reason-codes';
import {
  type AuditExportRecord,
  type AuditExportRecordContent,
  AUDIT_EXPORT_RECORD_JSON_SCHEMA,
  AUDIT_EXPORT_BUNDLE_JSON_SCHEMA,
  FORBIDDEN_EXPORT_FIELDS,
  LAWFUL_BASES,
  GENESIS_HASH,
  validateNoPii,
  canonicalize,
  computeRecordHash,
  appendAuditRecord,
  createAuditExportBundle,
  computeBundleHash,
  verifyHashChain,
  verifyAuditExportBundle,
} from '../audit-export-schema';
import { createAuditRecord, FORBIDDEN_LOG_FIELDS } from '../audit-metadata';

// ─── Helpers ────────────────────────────────────────────────────────

function makeContent(
  overrides?: Partial<AuditExportRecordContent>,
): Omit<AuditExportRecordContent, 'prevRecordHash'> {
  return {
    timestampBucket: '2026-03-04T12:05:00.000Z',
    requestId: '550e8400-e29b-41d4-a716-446655440000',
    verifierHash: 'a'.repeat(64),
    verdict: 'DENY',
    reasonCode: DenyReasonCode.UNKNOWN_VERIFIER,
    protocolVersion: 'OID4VP-draft-23',
    capabilityProfile: 'sd-jwt-vc+kb',
    legalBasis: 'consent',
    purposeCode: 'age_verification',
    dataCategories: ['age_over_18'],
    policyHash: 'b'.repeat(64),
    retentionUntil: '2033-03-04T12:05:00.000Z',
    ...overrides,
  };
}

/** A single, internally-consistent genesis record. */
function makeRecord(overrides?: Partial<AuditExportRecordContent>): AuditExportRecord {
  return appendAuditRecord([], makeContent(overrides));
}

// ─── Schema Structure Tests ─────────────────────────────────────────

describe('AuditExportRecord JSON Schema', () => {
  it('has all required fields defined (incl. schema 1.1 accountability + chain)', () => {
    const required = AUDIT_EXPORT_RECORD_JSON_SCHEMA.required;
    for (const f of [
      'timestampBucket', 'requestId', 'verifierHash', 'verdict',
      'protocolVersion', 'capabilityProfile',
      'legalBasis', 'purposeCode', 'dataCategories', 'policyHash', 'retentionUntil',
      'prevRecordHash', 'recordHash',
    ]) {
      expect(required).toContain(f);
    }
  });

  it('disallows additional properties', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.additionalProperties).toBe(false);
  });

  it('verifierHash, policyHash and chain hashes must be 64-char hex', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.verifierHash.pattern).toBe('^[a-f0-9]{64}$');
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.policyHash.pattern).toBe('^[a-f0-9]{64}$');
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.prevRecordHash.pattern).toBe('^[a-f0-9]{64}$');
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.recordHash.pattern).toBe('^[a-f0-9]{64}$');
  });

  it('verdict enum is exhaustive', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.verdict.enum).toEqual(['ALLOW', 'DENY', 'PROMPT']);
  });

  it('legalBasis enum matches the six GDPR Art. 6(1) bases', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.legalBasis.enum).toEqual(LAWFUL_BASES);
    expect(LAWFUL_BASES).toHaveLength(6);
  });

  it('purposeCode and dataCategories use the same code-token pattern', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.purposeCode.pattern)
      .toBe(AUDIT_EXPORT_RECORD_JSON_SCHEMA.properties.dataCategories.items.pattern);
  });

  it('reasonCode is optional (not in required)', () => {
    expect(AUDIT_EXPORT_RECORD_JSON_SCHEMA.required).not.toContain('reasonCode');
  });
});

describe('AuditExportBundle JSON Schema', () => {
  it('schema version is pinned to 1.1', () => {
    expect(AUDIT_EXPORT_BUNDLE_JSON_SCHEMA.properties.schemaVersion.const).toBe('1.1');
  });

  it('has required fields incl. controller + chainTipHash (Art. 30/32)', () => {
    const required = AUDIT_EXPORT_BUNDLE_JSON_SCHEMA.required;
    expect(required).toEqual(
      expect.arrayContaining([
        'schemaVersion', 'exportedAt', 'controller', 'records', 'bundleHash', 'chainTipHash', 'recordCount',
      ]),
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
    expect(validateNoPii(makeRecord() as unknown as Record<string, unknown>)).toEqual([]);
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
      dateOfBirth: '1990-01-01',
    } as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.length).toBe(2);
  });

  it('flags a dataCategories entry that looks like a value, not a claim name', () => {
    // A raw value (with an email) must never appear as a data category.
    const dirty = {
      ...makeRecord({ dataCategories: ['birthDate', 'alice@example.com'] }),
    } as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.some((v) => v.includes('claim-name token'))).toBe(true);
  });

  it('flags a dataCategories entry that starts like a raw value, not a claim name', () => {
    const dirty = makeRecord({ dataCategories: ['1990-01-01'] }) as unknown as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.some((v) => v.includes('claim-name token'))).toBe(true);
  });

  it('flags free-text purpose codes', () => {
    const dirty = makeRecord({ purposeCode: 'Age verification for Alice' }) as unknown as Record<string, unknown>;
    const violations = validateNoPii(dirty);
    expect(violations.some((v) => v.includes('purpose-code token'))).toBe(true);
  });

  it('detects forbidden fields nested inside injected payloads', () => {
    const dirty = {
      ...makeRecord(),
      debug: { request: { subjectDid: 'did:example:123' } },
    } as Record<string, unknown>;
    expect(validateNoPii(dirty)).toEqual(['Forbidden field present as key: debug.request.subjectDid']);
  });

  it('AuditExportRecord type keys do not overlap with forbidden fields', () => {
    const keys = Object.keys(makeRecord());
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
    expect(validateNoPii(auditRecord as unknown as Record<string, unknown>)).toEqual([]);
  });
});

// ─── Accountability field tests (ADR-011) ───────────────────────────

describe('Accountability fields (GDPR Art. 30)', () => {
  it('carries a lawful basis, purpose code, data categories, policy hash and retention', () => {
    const r = makeRecord();
    expect(LAWFUL_BASES).toContain(r.legalBasis);
    expect(r.purposeCode).toBeTruthy();
    expect(Array.isArray(r.dataCategories)).toBe(true);
    expect(r.policyHash).toMatch(/^[a-f0-9]{64}$/);
    expect(new Date(r.retentionUntil).toISOString()).toBe(r.retentionUntil);
  });

  it('dataCategories carries claim names, not values', () => {
    const r = makeRecord({ dataCategories: ['age_over_18', 'residency'] });
    for (const c of r.dataCategories) {
      expect(c).toMatch(/^[A-Za-z0-9_.:-]{1,128}$/);
    }
  });
});

// ─── Hash-chain integrity tests (GDPR Art. 32) ──────────────────────

describe('Hash chain integrity', () => {
  it('genesis record links to GENESIS_HASH and has a valid recordHash', () => {
    const r = makeRecord();
    expect(r.prevRecordHash).toBe(GENESIS_HASH);
    const { recordHash, ...content } = r;
    expect(computeRecordHash(content)).toBe(recordHash);
  });

  it('appendAuditRecord links each record to its predecessor', () => {
    const r1 = makeRecord({ requestId: '11111111-1111-4111-8111-111111111111' });
    const r2 = appendAuditRecord(
      [r1],
      makeContent({ requestId: '22222222-2222-4222-8222-222222222222', verdict: 'ALLOW', reasonCode: undefined }),
    );
    expect(r2.prevRecordHash).toBe(r1.recordHash);
  });

  it('verifies an intact chain', () => {
    const r1 = makeRecord({ requestId: '11111111-1111-4111-8111-111111111111' });
    const r2 = appendAuditRecord(
      [r1],
      makeContent({ requestId: '22222222-2222-4222-8222-222222222222', verdict: 'ALLOW', reasonCode: undefined }),
    );
    const r3 = appendAuditRecord(
      [r1, r2],
      makeContent({ requestId: '33333333-3333-4333-8333-333333333333', verdict: 'PROMPT', reasonCode: undefined }),
    );
    expect(verifyHashChain([r1, r2, r3])).toEqual({ valid: true });
  });

  it('detects an edited field (recordHash mismatch)', () => {
    const r1 = makeRecord();
    const r2 = appendAuditRecord([r1], makeContent({ requestId: '22222222-2222-4222-8222-222222222222' }));
    const tampered = { ...r2, verdict: 'ALLOW' as const }; // edit content, keep old hash
    const result = verifyHashChain([r1, tampered]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects a deleted record (chain re-link broken)', () => {
    const r1 = makeRecord({ requestId: '11111111-1111-4111-8111-111111111111' });
    const r2 = appendAuditRecord([r1], makeContent({ requestId: '22222222-2222-4222-8222-222222222222' }));
    const r3 = appendAuditRecord(
      [r1, r2],
      makeContent({ requestId: '33333333-3333-4333-8333-333333333333' }),
    );
    // Drop the middle record — r3.prevRecordHash no longer matches r1.recordHash.
    const result = verifyHashChain([r1, r3]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('canonicalize is stable regardless of key insertion order', () => {
    const a = canonicalize({ b: 1, a: 2, c: [3, { y: 1, x: 2 }] });
    const b = canonicalize({ c: [3, { x: 2, y: 1 }], a: 2, b: 1 });
    expect(a).toBe(b);
  });
});

describe('Audit export bundle integrity', () => {
  function makeBundle() {
    const r1 = makeRecord({ requestId: '11111111-1111-4111-8111-111111111111' });
    const r2 = appendAuditRecord(
      [r1],
      makeContent({ requestId: '22222222-2222-4222-8222-222222222222', verdict: 'ALLOW', reasonCode: undefined }),
    );
    return createAuditExportBundle({
      exportedAt: '2026-03-04T12:10:00.000Z',
      controller: {
        name: 'AskMI Pilot Controller',
        contact: 'privacy@example.invalid',
        ropaRef: 'ropa:askmi:policy-engine:v1',
      },
      records: [r1, r2],
    });
  }

  it('creates a complete schema 1.1 bundle with stable hash and chain tip', () => {
    const bundle = makeBundle();
    expect(bundle.schemaVersion).toBe('1.1');
    expect(bundle.recordCount).toBe(2);
    expect(bundle.chainTipHash).toBe(bundle.records[1].recordHash);
    expect(bundle.bundleHash).toBe(computeBundleHash(bundle.records));
    expect(verifyAuditExportBundle(bundle)).toEqual({ valid: true });
  });

  it('uses GENESIS_HASH as chain tip for empty bundles', () => {
    const bundle = createAuditExportBundle({
      exportedAt: '2026-03-04T12:10:00.000Z',
      controller: { name: 'AskMI', contact: 'privacy@example.invalid', ropaRef: 'ropa:empty' },
      records: [],
    });
    expect(bundle.chainTipHash).toBe(GENESIS_HASH);
    expect(verifyAuditExportBundle(bundle)).toEqual({ valid: true });
  });

  it('detects a changed record count', () => {
    const bundle = { ...makeBundle(), recordCount: 3 };
    expect(verifyAuditExportBundle(bundle).reason).toBe('recordCount does not match records length');
  });

  it('detects a stale bundle hash after a record edit', () => {
    const bundle = makeBundle();
    const edited = {
      ...bundle,
      records: [{ ...bundle.records[0], purposeCode: 'igaming_age_gate' }, bundle.records[1]],
    };
    expect(verifyAuditExportBundle(edited).reason).toBe('bundleHash does not match records');
  });

  it('detects a stale chain tip', () => {
    const bundle = { ...makeBundle(), chainTipHash: 'f'.repeat(64) };
    expect(verifyAuditExportBundle(bundle).reason).toBe('chainTipHash does not match last record');
  });
});

// ─── Type Correctness Tests ─────────────────────────────────────────

describe('AuditExportRecord type correctness', () => {
  it('verdict only accepts valid values', () => {
    const record = makeRecord({ verdict: 'ALLOW', reasonCode: undefined });
    expect(['ALLOW', 'DENY', 'PROMPT']).toContain(record.verdict);
  });

  it('timestampBucket is valid ISO-8601 at a 5-minute boundary', () => {
    const record = makeRecord();
    expect(new Date(record.timestampBucket).toISOString()).toBe(record.timestampBucket);
    const minutes = new Date(record.timestampBucket).getMinutes();
    expect(minutes % 5).toBe(0);
  });

  it('verifierHash is 64-char lowercase hex', () => {
    expect(makeRecord().verifierHash).toMatch(/^[a-f0-9]{64}$/);
  });
});
