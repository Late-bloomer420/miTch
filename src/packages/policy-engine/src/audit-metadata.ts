import { DenyReasonCode } from './deny-reason-codes';

// Browser-safe SHA-256 hash (sync fallback for non-crypto environments)
function sha256Hex(data: string): string {
  // Use node:crypto if available, otherwise a simple deterministic hash
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createHash } = require('node:crypto');
    return createHash('sha256').update(data).digest('hex');
  } catch {
    // Fallback: simple but deterministic hash for browser environments
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }
}

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
  return sha256Hex(`${salt}:${verifierId}`);
}
