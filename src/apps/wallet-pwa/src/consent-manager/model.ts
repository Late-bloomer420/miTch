import type { AuditLogEntry, PolicyEvaluationResult, VerifierRequest } from '@mitch/shared-types';
import { DataFlowService } from '@mitch/data-flow';
import type { DataFlowTransaction, IdentityFirewallAccess } from '@mitch/data-flow';
import type { ConsentReceipt } from './types';
import type { PrivacyConsent } from '../services/PrivacyAuditService';

const dataFlowService = new DataFlowService();

type ViewState = 'idle' | 'prompt' | 'approved' | 'denied';

export interface ConsentManagerEvidenceItem {
  label: string;
  value: string;
}

export interface ConsentManagerViewModel {
  state: ViewState;
  verifierLabel: string;
  decisionId: string | null;
  requestedClaims: string[];
  requestedProvenClaims: string[];
  allowedClaims: string[];
  provenClaims: string[];
  withheldClaims: string[] | null;
  identityAccessCount: number;
  identityAccesses: IdentityFirewallAccess[];
  transaction: DataFlowTransaction | null;
  evidence: ConsentManagerEvidenceItem[];
  privacyConsent: PrivacyConsent | null;
  consentReceipt: ConsentReceipt | null;
  hasDetails: boolean;
}

function uniqueOrdered(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function extractRequestedClaims(request?: VerifierRequest | null): string[] {
  if (!request) return [];
  if (request.requirements?.length) {
    return uniqueOrdered(request.requirements.flatMap((req) => req.requestedClaims ?? []));
  }
  return uniqueOrdered(request.requestedClaims ?? []);
}

function extractRequestedProvenClaims(request?: VerifierRequest | null): string[] {
  if (!request) return [];
  if (request.requirements?.length) {
    return uniqueOrdered(request.requirements.flatMap((req) => req.requestedProvenClaims ?? []));
  }
  return uniqueOrdered(request.requestedProvenClaims ?? []);
}

function collectEvidence(
  result: PolicyEvaluationResult | null,
  transaction: DataFlowTransaction | null,
  privacyConsent: PrivacyConsent | null,
  consentReceipt: ConsentReceipt | null
): ConsentManagerEvidenceItem[] {
  const evidence: ConsentManagerEvidenceItem[] = [];

  if (result?.decisionCapsule) {
    const capsule = result.decisionCapsule;
    evidence.push(
      { label: 'Decision', value: capsule.verdict },
      { label: 'Decision ID', value: capsule.decision_id },
      { label: 'Policy hash', value: capsule.policy_hash },
      { label: 'Request hash', value: capsule.request_hash },
      { label: 'Verifier', value: capsule.verifier_did }
    );
  }

  if (transaction) {
    evidence.push(
      { label: 'Transaction', value: transaction.transactionId },
      { label: 'Requested claims', value: String(transaction.claimsRequested?.length ?? 0) },
      { label: 'Allowed claims', value: String(transaction.claimsShared.length) },
      { label: 'Withheld claims', value: String(transaction.claimsWithheld?.length ?? 0) },
      { label: 'Identity signals', value: String(transaction.identityAccessCount) }
    );
  }

  if (privacyConsent) {
    evidence.push(
      { label: 'Privacy scan', value: privacyConsent.status },
      { label: 'Accepted trackers', value: String(privacyConsent.acceptedTrackers.length) },
      { label: 'Audit hash', value: privacyConsent.auditHash }
    );
  }

  if (consentReceipt) {
    evidence.push(
      { label: 'Consent receipt', value: consentReceipt.id },
      { label: 'Receipt verifier', value: consentReceipt.verifier },
      { label: 'Receipt claims', value: String(consentReceipt.claimsShared.length) },
      { label: 'Receipt timestamp', value: consentReceipt.timestamp },
      { label: 'Receipt outcome', value: consentReceipt.outcome },
      { label: 'Receipt decision ID', value: consentReceipt.decisionId ?? 'none' }
    );
  }

  return evidence;
}

export interface BuildConsentManagerInput {
  request: VerifierRequest | null;
  result: PolicyEvaluationResult | null;
  auditEntries: AuditLogEntry[];
  privacyConsent: PrivacyConsent | null;
  consentReceipt: ConsentReceipt | null;
}

export function buildConsentManagerViewModel({
  request,
  result,
  auditEntries,
  privacyConsent,
  consentReceipt,
}: BuildConsentManagerInput): ConsentManagerViewModel {
  const transactions = dataFlowService.buildTransactions(auditEntries);
  const decisionId = result?.decisionCapsule?.decision_id ?? null;
  const transaction = decisionId
    ? (transactions.find((tx) => tx.transactionId === decisionId) ?? null)
    : (transactions[0] ?? null);

  const requestedClaims = extractRequestedClaims(request);
  const requestedProvenClaims = extractRequestedProvenClaims(request);
  const allowedClaims = transaction?.claimsShared ?? [];
  const provenClaims = transaction?.provenClaims ?? [];
  const withheldClaims = transaction?.claimsWithheld ?? null;
  const identityAccesses = transaction?.identityAccesses ?? [];

  const state: ViewState = !result
    ? 'idle'
    : result.verdict === 'DENY'
      ? 'denied'
      : result.verdict === 'PROMPT'
        ? 'prompt'
        : 'approved';

  return {
    state,
    verifierLabel: transaction?.verifierLabel ?? request?.verifierId ?? 'Unknown verifier',
    decisionId,
    requestedClaims,
    requestedProvenClaims,
    allowedClaims,
    provenClaims,
    withheldClaims,
    identityAccessCount: transaction?.identityAccessCount ?? 0,
    identityAccesses,
    transaction,
    evidence: collectEvidence(result, transaction, privacyConsent, consentReceipt),
    privacyConsent,
    consentReceipt,
    hasDetails:
      requestedClaims.length > 0 ||
      requestedProvenClaims.length > 0 ||
      allowedClaims.length > 0 ||
      provenClaims.length > 0 ||
      (withheldClaims?.length ?? 0) > 0 ||
      identityAccesses.length > 0 ||
      Boolean(result?.decisionCapsule) ||
      Boolean(privacyConsent) ||
      Boolean(consentReceipt),
  };
}
