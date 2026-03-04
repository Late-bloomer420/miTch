import { createHash } from 'node:crypto';
import { DenyReasonCode } from './deny-reason-codes';

export interface AuditInput {
  verifierId: string;
  requestId: string;
  timestampMs: number;
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  reasonCode?: DenyReasonCode;
  salt: string;
}

export interface AuditRecord {
  timestampBucket: string;
  requestId: string;
  verifierHash: string;
  verdict: 'ALLOW' | 'DENY' | 'PROMPT';
  reasonCode?: DenyReasonCode;
}

export const FORBIDDEN_LOG_FIELDS = ['subjectDid', 'name', 'birthDate', 'email', 'rawVerifierId'] as const;

const BUCKET_MS = 5 * 60 * 1000;

export function createAuditRecord(input: AuditInput): AuditRecord {
  const bucketStart = Math.floor(input.timestampMs / BUCKET_MS) * BUCKET_MS;
  return {
    timestampBucket: new Date(bucketStart).toISOString(),
    requestId: input.requestId,
    verifierHash: hashVerifierId(input.verifierId, input.salt),
    verdict: input.verdict,
    reasonCode: input.reasonCode,
  };
}

export function hashVerifierId(verifierId: string, salt: string): string {
  return createHash('sha256').update(`${salt}:${verifierId}`).digest('hex');
}
