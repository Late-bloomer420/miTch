import { describe, expect, it } from 'vitest';
import type { AuditLogEntry, PolicyEvaluationResult, VerifierRequest } from '@askmi/shared-types';
import { buildConsentManagerViewModel } from '../model';
import type { PrivacyConsent } from '../../services/PrivacyAuditService';

let entryCounter = 0;

function makeEntry(
  overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>
): AuditLogEntry {
  return {
    id: overrides.id ?? `entry-${++entryCounter}`,
    timestamp: overrides.timestamp ?? '2026-05-21T10:00:00.000Z',
    action: overrides.action,
    previousHash: overrides.previousHash ?? 'prev',
    currentHash: overrides.currentHash ?? 'curr',
    metadata: overrides.metadata ?? {},
  };
}

describe('buildConsentManagerViewModel', () => {
  const request: VerifierRequest = {
    verifierId: 'did:askmi:verifier-liquor-store',
    requestedClaims: ['age', 'name', 'address'],
    requestedProvenClaims: ['age >= 18'],
  };

  const result: PolicyEvaluationResult = {
    verdict: 'PROMPT',
    reasonCodes: ['CONSENT_REQUIRED'],
    decisionCapsule: {
      decision_id: 'decision-001',
      verdict: 'PROMPT',
      request_hash: 'req-hash',
      policy_hash: 'policy-hash',
      verifier_did: 'did:askmi:verifier-liquor-store',
      authorized_requirements: [
        {
          credential_type: 'AgeCredential',
          allowed_claims: ['age'],
          proven_claims: ['age >= 18'],
          selected_credential_id: 'vc-1',
          issuer_trust_refs: [],
          requested_claims: ['age', 'name', 'address'],
        },
      ],
      risk_level: 'LOW',
      requires_presence: false,
      expires_at: '2026-05-21T10:05:00.000Z',
      audience: 'wallet-pwa',
      issued_at: '2026-05-21T10:00:00.000Z',
    },
  };

  const entries = [
    makeEntry({ action: 'VP_GENERATED', metadata: { decision_id: 'decision-001', claims_shared: ['age'], claims_requested: ['age', 'name', 'address'], proven_claims: ['age >= 18'], credential_types: ['AgeCredential'], used_zkp: true } }),
    makeEntry({ action: 'IDENTITY_ACCESS_DETECTED', metadata: { decision_id: 'decision-001', access_type: 'browser_api', surface: 'navigator.userAgent', actor_label: 'Google Chrome', field_class: 'fingerprint', persistence: 'device', linkability: 'cross_session', severity: 'warning', blocked: false, source: 'privacy_audit_service' } }),
  ];

  const privacyConsent: PrivacyConsent = {
    status: 'ACCEPT',
    acceptedTrackers: ['Google Chrome'],
    timestamp: '2026-05-21T10:00:00.000Z',
    auditHash: 'abc123',
  };

  const consentReceipt = {
    id: 'consent-001',
    verifier: 'did:askmi:verifier-liquor-store',
    purpose: 'Age verification',
    claimsShared: ['age'],
    timestamp: '2026-05-21T10:00:01.000Z',
  };

  it('builds the current decision view from request, result and audit entries', () => {
    const model = buildConsentManagerViewModel({
      request,
      result,
      auditEntries: entries,
      privacyConsent,
      consentReceipt,
    });

    expect(model.state).toBe('prompt');
    expect(model.decisionId).toBe('decision-001');
    expect(model.requestedClaims).toEqual(['age', 'name', 'address']);
    expect(model.allowedClaims).toEqual(['age']);
    expect(model.withheldClaims).toEqual(['name', 'address']);
    expect(model.identityAccessCount).toBe(1);
    expect(model.evidence.some(item => item.label === 'Decision ID')).toBe(true);
    expect(model.evidence.some(item => item.label === 'Privacy scan')).toBe(true);
  });

  it('falls back to idle state when no result exists', () => {
    const model = buildConsentManagerViewModel({
      request: null,
      result: null,
      auditEntries: [],
      privacyConsent: null,
      consentReceipt: null,
    });

    expect(model.state).toBe('idle');
    expect(model.hasDetails).toBe(false);
  });
});
