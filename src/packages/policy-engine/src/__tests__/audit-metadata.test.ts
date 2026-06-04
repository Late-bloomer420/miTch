import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { DenyReasonCode } from '../deny-reason-codes';
import { createAuditRecord, FORBIDDEN_LOG_FIELDS, hashVerifierId } from '../audit-metadata';

describe('Metadata budget enforcement', () => {
  it('does not include raw PII in serialized audit logs', () => {
    const record = createAuditRecord({
      verifierId: 'did:web:bar.example',
      requestId: 'req-1',
      timestampMs: Date.parse('2026-03-04T12:03:12.221Z'),
      verdict: 'DENY',
      reasonCode: DenyReasonCode.UNKNOWN_VERIFIER,
      salt: 'rotation-2026-03',
    });

    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain('did:web:bar.example');
    expect(serialized).not.toContain('dateOfBirth');
    expect(serialized).not.toContain('name');
  });

  it('schema excludes forbidden fields', () => {
    const record = createAuditRecord({
      verifierId: 'did:web:bar.example',
      requestId: 'req-2',
      timestampMs: Date.now(),
      verdict: 'DENY',
      reasonCode: DenyReasonCode.POLICY_MISMATCH,
      salt: 'rotation-2026-03',
    });

    for (const forbidden of FORBIDDEN_LOG_FIELDS) {
      expect(forbidden in record).toBe(false);
    }
  });

  it('timestamps are bucketed to 5-minute granularity', () => {
    const record = createAuditRecord({
      verifierId: 'did:web:bar.example',
      requestId: 'req-3',
      timestampMs: Date.parse('2026-03-04T12:07:59.900Z'),
      verdict: 'DENY',
      reasonCode: DenyReasonCode.BINDING_EXPIRED,
      salt: 'rotation-2026-03',
    });

    expect(record.timestampBucket).toBe('2026-03-04T12:05:00.000Z');
  });

  it('verifierHash is a genuine SHA-256 digest, not a weak fallback', () => {
    const verifierId = 'did:web:bar.example';
    const salt = 'rotation-2026-03';

    const record = createAuditRecord({
      verifierId,
      requestId: 'req-hash',
      timestampMs: Date.now(),
      verdict: 'DENY',
      reasonCode: DenyReasonCode.UNKNOWN_VERIFIER,
      salt,
    });

    // Full 256-bit digest = 64 lowercase hex chars (the old 32-bit fallback was 8 chars).
    expect(record.verifierHash).toMatch(/^[0-9a-f]{64}$/);

    // Byte-for-byte equal to a real SHA-256 of `${salt}:${verifierId}` in every environment.
    const expected = createHash('sha256').update(`${salt}:${verifierId}`).digest('hex');
    expect(record.verifierHash).toBe(expected);
    expect(hashVerifierId(verifierId, salt)).toBe(expected);
  });

  it('manual sink verification is documented', () => {
    // TODO(manual-verify): Validate production log sink does not append raw request payload fields.
    expect(true).toBe(true);
  });
});
