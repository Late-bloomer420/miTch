import { canonicalStringify, sha256 } from '@mitch/shared-crypto';
import type {
  ConsentReceiptExportFilters,
  ConsentReceiptExportScope,
  ConsentReceiptExportV1,
  ConsentReceiptV1,
} from '@mitch/shared-types';

export type StoredConsentReceiptEntry = ConsentReceiptV1;

export type { ConsentReceiptExportFilters, ConsentReceiptExportScope };
export type ConsentReceiptExport = ConsentReceiptExportV1;

const STORAGE_KEY = 'mitch_consent_receipt_history';
const MAX_HISTORY = 24;
let memoryHistory: StoredConsentReceiptEntry[] = [];

function isString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeReceipt(receipt: unknown): ConsentReceiptV1 | null {
  if (!receipt || typeof receipt !== 'object') return null;
  const candidate = receipt as Partial<ConsentReceiptV1>;
  const schemaVersion = candidate.schemaVersion;
  if (schemaVersion !== undefined && schemaVersion !== 1) return null;
  if (
    !isString(candidate.id) ||
    !isString(candidate.verifier) ||
    !isString(candidate.purpose) ||
    !isString(candidate.timestamp)
  ) {
    return null;
  }
  const claimsShared = Array.isArray(candidate.claimsShared)
    ? candidate.claimsShared
        .filter(isString)
        .map((claim) => claim.trim())
        .slice(0, 24)
    : [];
  const outcome = candidate.outcome;
  if (outcome !== 'SUCCESS' && outcome !== 'DENIED' && outcome !== 'ERROR') {
    return null;
  }
  return {
    schemaVersion: 1,
    id: candidate.id.trim(),
    verifier: candidate.verifier.trim(),
    purpose: candidate.purpose.trim(),
    claimsShared,
    timestamp: candidate.timestamp.trim(),
    outcome,
    decisionId: isString(candidate.decisionId) ? candidate.decisionId.trim() : null,
  };
}

function normalizeEntry(entry: unknown): StoredConsentReceiptEntry | null {
  if (!entry || typeof entry !== 'object') return null;
  const candidate = entry as Record<string, unknown>;

  if ('receipt' in candidate) {
    const legacyReceipt =
      candidate.receipt && typeof candidate.receipt === 'object'
        ? (candidate.receipt as Record<string, unknown>)
        : {};
    const receipt = normalizeReceipt({
      ...legacyReceipt,
      schemaVersion: 1,
      outcome: candidate.outcome,
      decisionId: candidate.decisionId,
    });
    if (!receipt) return null;
    return receipt;
  }

  return normalizeReceipt(candidate);
}

function readStorage(): StoredConsentReceiptEntry[] {
  try {
    if (typeof sessionStorage === 'undefined') return memoryHistory;
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(normalizeEntry)
      .filter((entry): entry is StoredConsentReceiptEntry => Boolean(entry));
  } catch {
    return memoryHistory;
  }
}

function writeStorage(entries: StoredConsentReceiptEntry[]): void {
  const trimmed = entries.slice(0, MAX_HISTORY);
  memoryHistory = trimmed;

  try {
    if (typeof sessionStorage === 'undefined') return;
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
  } catch {
    // Fall back to in-memory history when storage is unavailable.
  }
}

export function loadConsentReceiptHistory(): StoredConsentReceiptEntry[] {
  return readStorage();
}

export function appendConsentReceiptHistory(
  entry: StoredConsentReceiptEntry
): StoredConsentReceiptEntry[] {
  const current = readStorage();
  const next = [entry, ...current.filter((existing) => existing.id !== entry.id)];
  writeStorage(next);
  return next;
}

export async function buildConsentReceiptExport(
  entries: StoredConsentReceiptEntry[],
  options: {
    scope: ConsentReceiptExportScope;
    filters: ConsentReceiptExportFilters;
    auditAnchorHash: string | null;
  }
): Promise<ConsentReceiptExport> {
  const exportedAt = new Date().toISOString();
  const receipts = entries.map((entry) => ({
    schemaVersion: entry.schemaVersion,
    id: entry.id,
    verifier: entry.verifier,
    purpose: entry.purpose,
    claimsShared: entry.claimsShared,
    timestamp: entry.timestamp,
    outcome: entry.outcome,
    decisionId: entry.decisionId,
  }));
  const receiptSetHash = await sha256(
    canonicalStringify({
      scope: options.scope,
      filters: options.filters,
      auditAnchorHash: options.auditAnchorHash,
      receipts,
    })
  );
  const exportHash = await sha256(
    canonicalStringify({
      scope: options.scope,
      filters: options.filters,
      auditAnchorHash: options.auditAnchorHash,
      receiptSetHash,
    })
  );
  return {
    exportedAt,
    scope: options.scope,
    filters: options.filters,
    count: entries.length,
    auditAnchorHash: options.auditAnchorHash,
    receiptSetHash,
    exportHash,
    receipts,
  };
}
