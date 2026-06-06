/**
 * @module @askmi/policy-engine/audit-export-schema
 *
 * Formal Audit Export Schema for external auditor handoff (Tier 2).
 * Aligned with METADATA_BUDGET_V1 — no PII, no stable cross-RP correlators.
 *
 * Schema 1.1 (ADR-011, docs/compliance/ADR/ADR-011.md) makes the export both
 * MINIMISED (GDPR Art. 5(1)(c), Art. 25; eIDAS 2 Art. 5a unlinkability) and
 * ACCOUNTABLE (Art. 30 RoPA: lawful basis, purpose, data categories, retention)
 * and TAMPER-EVIDENT (Art. 32: per-record hash chain).
 *
 * AI-04 / P1: Define final audit export schema.
 */

import { DenyReasonCode } from './deny-reason-codes';
import { sha256Hex } from './sha256-sync';

// ─── Lawful basis (GDPR Art. 6(1)(a)–(f)) ───────────────────────────

export type LawfulBasis =
  | 'consent' //                Art. 6(1)(a)
  | 'contract' //               Art. 6(1)(b)
  | 'legal_obligation' //       Art. 6(1)(c)
  | 'vital_interests' //        Art. 6(1)(d)
  | 'public_task' //            Art. 6(1)(e)
  | 'legitimate_interests'; //  Art. 6(1)(f)

export const LAWFUL_BASES: readonly LawfulBasis[] = [
  'consent',
  'contract',
  'legal_obligation',
  'vital_interests',
  'public_task',
  'legitimate_interests',
] as const;

/** Genesis predecessor hash for the first record in a chain (64 hex zeros). */
export const GENESIS_HASH = '0'.repeat(64);

/** Purpose/data-category codes only — never free text or values. */
export const CODE_PATTERN = /^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/;
/** Claim NAMES only — never values. Enforced on `dataCategories` entries. */
export const DATA_CATEGORY_PATTERN = CODE_PATTERN;

// ─── Core Export Record ─────────────────────────────────────────────

/**
 * A single audit export record suitable for external auditor consumption.
 * Contains NO PII. All identifiers are salted hashes.
 *
 * Schema 1.1 adds the accountability fields (legalBasis, purposeCode,
 * dataCategories, policyHash, retentionUntil) and the integrity chain
 * (prevRecordHash, recordHash). See ADR-011.
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

  // ── Schema 1.1 — accountability (GDPR Art. 30) ──
  /** Lawful basis for the processing — GDPR Art. 6(1) */
  legalBasis: LawfulBasis;
  /** Purpose code (NOT free text) — GDPR Art. 5(1)(b) purpose limitation */
  purposeCode: string;
  /** Claim NAMES touched (never values) — evidences Art. 5(1)(c) minimisation */
  dataCategories: string[];
  /** SHA-256 of the authorising policy version — accountability/reproducibility */
  policyHash: string;
  /** ISO-8601 instant after which this record must be erased — Art. 5(1)(e) */
  retentionUntil: string;

  // ── Schema 1.1 — integrity chain (GDPR Art. 32) ──
  /** recordHash of the previous record; GENESIS_HASH for the first */
  prevRecordHash: string;
  /** SHA-256 over the canonicalised record (excluding this field) + prevRecordHash */
  recordHash: string;
}

/** The record content that is hashed — everything except `recordHash` itself. */
export type AuditExportRecordContent = Omit<AuditExportRecord, 'recordHash'>;

// ─── Export Bundle ──────────────────────────────────────────────────

/** Controller identity for the bundle — GDPR Art. 30(1)(a). */
export interface AuditController {
  /** Controller legal name */
  name: string;
  /** Contact point (role-based mailbox, NOT a personal address) */
  contact: string;
  /** Reference to the Records of Processing Activities entry */
  ropaRef: string;
}

/**
 * Complete audit export bundle for external auditor handoff.
 */
export interface AuditExportBundle {
  /** Schema version for forward compatibility */
  schemaVersion: '1.1';
  /** ISO-8601 export timestamp */
  exportedAt: string;
  /** Controller identity — GDPR Art. 30(1)(a) */
  controller: AuditController;
  /** Records in this export bundle (chain order) */
  records: AuditExportRecord[];
  /** SHA-256 hash of canonicalized records array */
  bundleHash: string;
  /** recordHash of the last record — quick integrity tip (GENESIS_HASH if empty) */
  chainTipHash: string;
  /** Total record count (for integrity cross-check) */
  recordCount: number;
}

/** Result of a full export-bundle verification. */
export interface BundleVerification extends ChainVerification {
  reason?: string;
}

// ─── Canonicalisation + hashing ─────────────────────────────────────

/**
 * Deterministic JSON serialisation: object keys sorted recursively so the
 * same logical content always produces the same string (and thus hash).
 * Arrays keep their order (order is semantically meaningful here).
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value) ?? 'null';
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

/**
 * Compute the hash of a record. The hash binds the canonical record content
 * (everything but `recordHash`) to its `prevRecordHash`, so any edit to the
 * content OR a re-link of the chain changes the hash.
 */
export function computeRecordHash(content: AuditExportRecordContent): string {
  return sha256Hex(canonicalize(content));
}

/**
 * Append a record to a chain: links `prevRecordHash` to the previous record's
 * `recordHash` (or GENESIS_HASH) and computes this record's `recordHash`.
 */
export function appendAuditRecord(
  chain: readonly AuditExportRecord[],
  content: Omit<AuditExportRecordContent, 'prevRecordHash'>,
): AuditExportRecord {
  const prevRecordHash = chain.length > 0 ? chain[chain.length - 1].recordHash : GENESIS_HASH;
  const withPrev: AuditExportRecordContent = { ...content, prevRecordHash };
  return { ...withPrev, recordHash: computeRecordHash(withPrev) };
}

/** Compute the stable bundle hash from the ordered record list. */
export function computeBundleHash(records: readonly AuditExportRecord[]): string {
  return sha256Hex(canonicalize(records));
}

/** Build a complete schema 1.1 bundle with record count and chain tip filled in. */
export function createAuditExportBundle(args: {
  exportedAt: string;
  controller: AuditController;
  records: readonly AuditExportRecord[];
}): AuditExportBundle {
  const records = [...args.records];
  return {
    schemaVersion: '1.1',
    exportedAt: args.exportedAt,
    controller: args.controller,
    records,
    bundleHash: computeBundleHash(records),
    chainTipHash: records.length > 0 ? records[records.length - 1].recordHash : GENESIS_HASH,
    recordCount: records.length,
  };
}

/** Result of a hash-chain verification. */
export interface ChainVerification {
  valid: boolean;
  /** Index of the first broken record, or undefined when the chain is intact. */
  brokenAt?: number;
  reason?: string;
}

/**
 * Verify a record chain (Art. 32 tamper-evidence): each record's recordHash
 * must match its content, and its prevRecordHash must equal the predecessor's
 * recordHash (GENESIS_HASH for the first). Any deletion, insertion, reorder or
 * field edit breaks the chain.
 */
export function verifyHashChain(records: readonly AuditExportRecord[]): ChainVerification {
  let expectedPrev = GENESIS_HASH;
  for (let i = 0; i < records.length; i++) {
    const { recordHash, ...content } = records[i];
    if (content.prevRecordHash !== expectedPrev) {
      return { valid: false, brokenAt: i, reason: 'prevRecordHash does not link to predecessor' };
    }
    if (computeRecordHash(content) !== recordHash) {
      return { valid: false, brokenAt: i, reason: 'recordHash does not match record content' };
    }
    expectedPrev = recordHash;
  }
  return { valid: true };
}

/** Verify bundle-level counters, hashes, and the embedded record chain. */
export function verifyAuditExportBundle(bundle: AuditExportBundle): BundleVerification {
  if (bundle.schemaVersion !== '1.1') {
    return { valid: false, reason: 'unsupported schemaVersion' };
  }
  if (bundle.recordCount !== bundle.records.length) {
    return { valid: false, reason: 'recordCount does not match records length' };
  }
  const expectedTip = bundle.records.length > 0 ? bundle.records[bundle.records.length - 1].recordHash : GENESIS_HASH;
  if (bundle.chainTipHash !== expectedTip) {
    return { valid: false, reason: 'chainTipHash does not match last record' };
  }
  if (bundle.bundleHash !== computeBundleHash(bundle.records)) {
    return { valid: false, reason: 'bundleHash does not match records' };
  }
  return verifyHashChain(bundle.records);
}

// ─── JSON Schema (programmatic) ────────────────────────────────────

/**
 * JSON Schema for AuditExportRecord, usable by external auditors
 * for validation without access to TypeScript types.
 */
export const AUDIT_EXPORT_RECORD_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://mitch.id/schemas/audit-export-record/v1.1',
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
    'legalBasis',
    'purposeCode',
    'dataCategories',
    'policyHash',
    'retentionUntil',
    'prevRecordHash',
    'recordHash',
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
    legalBasis: {
      type: 'string',
      enum: LAWFUL_BASES,
      description: 'Lawful basis for processing — GDPR Art. 6(1)(a)–(f).',
    },
    purposeCode: {
      type: 'string',
      minLength: 1,
      maxLength: 128,
      pattern: CODE_PATTERN.source,
      description: 'Purpose code (not free text) — GDPR Art. 5(1)(b).',
    },
    dataCategories: {
      type: 'array',
      items: { type: 'string', pattern: CODE_PATTERN.source },
      description: 'Claim NAMES touched (never values) — GDPR Art. 5(1)(c).',
    },
    policyHash: {
      type: 'string',
      pattern: '^[a-f0-9]{64}$',
      description: 'SHA-256 of the authorising policy version.',
    },
    retentionUntil: {
      type: 'string',
      format: 'date-time',
      description: 'Instant after which the record must be erased — GDPR Art. 5(1)(e).',
    },
    prevRecordHash: {
      type: 'string',
      pattern: '^[a-f0-9]{64}$',
      description: 'recordHash of the predecessor; 64 zeros for the genesis record.',
    },
    recordHash: {
      type: 'string',
      pattern: '^[a-f0-9]{64}$',
      description: 'SHA-256 over canonical record content incl. prevRecordHash — GDPR Art. 32.',
    },
  },
  additionalProperties: false,
} as const;

/**
 * JSON Schema for the full export bundle.
 */
export const AUDIT_EXPORT_BUNDLE_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://mitch.id/schemas/audit-export-bundle/v1.1',
  title: 'AuditExportBundle',
  description: 'Complete audit export bundle for external auditor handoff.',
  type: 'object',
  required: ['schemaVersion', 'exportedAt', 'controller', 'records', 'bundleHash', 'chainTipHash', 'recordCount'],
  properties: {
    schemaVersion: { type: 'string', const: '1.1' },
    exportedAt: { type: 'string', format: 'date-time' },
    controller: {
      type: 'object',
      required: ['name', 'contact', 'ropaRef'],
      properties: {
        name: { type: 'string' },
        contact: { type: 'string' },
        ropaRef: { type: 'string' },
      },
      additionalProperties: false,
    },
    records: {
      type: 'array',
      items: { $ref: 'https://mitch.id/schemas/audit-export-record/v1.1' },
    },
    bundleHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    chainTipHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
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
  'dateOfBirth',
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
 * Validate that a serialized record contains none of the forbidden PII fields,
 * and that any `dataCategories` are claim NAMES (token pattern), not values.
 * Returns list of violations (empty = clean).
 */
export function validateNoPii(record: Record<string, unknown>): string[] {
  const violations: string[] = [];

  collectForbiddenKeys(record, '', violations);

  const purposeCode = record.purposeCode;
  if (typeof purposeCode === 'string' && !CODE_PATTERN.test(purposeCode)) {
    violations.push(`purposeCode is not a purpose-code token: ${purposeCode}`);
  }

  // dataCategories must be claim names, never values (no spaces, no PII-looking content).
  const cats = record.dataCategories;
  if (Array.isArray(cats)) {
    for (const c of cats) {
      if (typeof c !== 'string' || !DATA_CATEGORY_PATTERN.test(c)) {
        violations.push(`dataCategories entry is not a claim-name token: ${String(c)}`);
      }
    }
  }

  return violations;
}

function collectForbiddenKeys(value: unknown, path: string, violations: string[]): void {
  if (value === null || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => collectForbiddenKeys(item, `${path}[${i}]`, violations));
    return;
  }
  const obj = value as Record<string, unknown>;
  for (const [key, nested] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    if ((FORBIDDEN_EXPORT_FIELDS as readonly string[]).includes(key)) {
      violations.push(`Forbidden field present as key: ${currentPath}`);
    }
    collectForbiddenKeys(nested, currentPath, violations);
  }
}
