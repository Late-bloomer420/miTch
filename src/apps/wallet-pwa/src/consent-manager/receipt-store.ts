import type { ConsentReceipt } from '@askmi/oid4vp';

export interface StoredConsentReceiptEntry {
  receipt: ConsentReceipt;
  outcome: 'SUCCESS' | 'DENIED' | 'ERROR';
  decisionId: string | null;
}

export interface ConsentReceiptExport {
  exportedAt: string;
  count: number;
  receipts: Array<{
    id: string;
    verifier: string;
    purpose: string;
    claimsShared: string[];
    timestamp: string;
    outcome: StoredConsentReceiptEntry['outcome'];
    decisionId: string | null;
  }>;
}

const STORAGE_KEY = 'mitch_consent_receipt_history';
const MAX_HISTORY = 24;
let memoryHistory: StoredConsentReceiptEntry[] = [];

function isString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function normalizeReceipt(receipt: unknown): ConsentReceipt | null {
  if (!receipt || typeof receipt !== 'object') return null;
  const candidate = receipt as Partial<ConsentReceipt>;
  if (!isString(candidate.id) || !isString(candidate.verifier) || !isString(candidate.purpose) || !isString(candidate.timestamp)) {
    return null;
  }
  const claimsShared = Array.isArray(candidate.claimsShared)
    ? candidate.claimsShared.filter(isString).map(claim => claim.trim()).slice(0, 24)
    : [];
  return {
    id: candidate.id.trim(),
    verifier: candidate.verifier.trim(),
    purpose: candidate.purpose.trim(),
    claimsShared,
    timestamp: candidate.timestamp.trim(),
  };
}

function normalizeEntry(entry: unknown): StoredConsentReceiptEntry | null {
  if (!entry || typeof entry !== 'object') return null;
  const candidate = entry as Partial<StoredConsentReceiptEntry>;
  const receipt = normalizeReceipt(candidate.receipt);
  const outcome = candidate.outcome;
  const decisionId = candidate.decisionId;
  if (!receipt || outcome !== 'SUCCESS' && outcome !== 'DENIED' && outcome !== 'ERROR') return null;
  return {
    receipt,
    outcome,
    decisionId: isString(decisionId) ? decisionId.trim() : null,
  };
}

function readStorage(): StoredConsentReceiptEntry[] {
  try {
    if (typeof sessionStorage === 'undefined') return memoryHistory;
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.map(normalizeEntry).filter((entry): entry is StoredConsentReceiptEntry => Boolean(entry));
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

export function appendConsentReceiptHistory(entry: StoredConsentReceiptEntry): StoredConsentReceiptEntry[] {
  const current = readStorage();
  const next = [entry, ...current.filter(existing => existing.receipt.id !== entry.receipt.id)];
  writeStorage(next);
  return next;
}

export function buildConsentReceiptExport(entries: StoredConsentReceiptEntry[]): ConsentReceiptExport {
  return {
    exportedAt: new Date().toISOString(),
    count: entries.length,
    receipts: entries.map(entry => ({
      id: entry.receipt.id,
      verifier: entry.receipt.verifier,
      purpose: entry.receipt.purpose,
      claimsShared: entry.receipt.claimsShared,
      timestamp: entry.receipt.timestamp,
      outcome: entry.outcome,
      decisionId: entry.decisionId,
    })),
  };
}
