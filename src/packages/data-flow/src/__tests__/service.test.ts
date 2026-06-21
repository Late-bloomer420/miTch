import { describe, it, expect } from 'vitest';
import { DataFlowService } from '../service';
import { eventLabel } from '../labels';
import type { AuditLogEntry } from '@askmi/shared-types';

function makeEntry(
  overrides: Partial<AuditLogEntry> & Pick<AuditLogEntry, 'action'>
): AuditLogEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    previousHash: '0'.repeat(64),
    currentHash: 'a'.repeat(64),
    ...overrides,
  };
}

const DEC_ID = 'decision-001';
const DEC_ID_2 = 'decision-002';

describe('DataFlowService', () => {
  const service = new DataFlowService();

  it('returns empty array for empty input', () => {
    expect(service.buildTransactions([])).toEqual([]);
  });

  it('ignores entries without decision_id', () => {
    const entries = [
      makeEntry({ action: 'POLICY_EVALUATED', metadata: { result: 'ok' } }),
    ];
    expect(service.buildTransactions(entries)).toEqual([]);
  });

  it('groups entries by decision_id', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID_2 } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns).toHaveLength(2);
  });

  it('extracts claimsShared from VP_GENERATED metadata', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age', 'birthDate'],
          verifier_did: 'did:askmi:verifier-test',
          credential_types: ['AgeCredential'],
          proven_claims: ['age >= 18'],
          used_zkp: true,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsShared).toEqual(['age', 'birthDate']);
  });

  it('extracts verifierId from VP_GENERATED metadata', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: [],
          credential_types: [],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].verifierId).toBe('did:askmi:verifier-liquor-store');
  });

  it('extracts provenClaims and usedZKP', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          proven_claims: ['age >= 18', 'age >= 21'],
          credential_types: ['AgeCredential'],
          verifier_did: 'did:askmi:verifier-test',
          used_zkp: true,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].provenClaims).toEqual(['age >= 18', 'age >= 21']);
    expect(txns[0].usedZKP).toBe(true);
  });

  it('extracts singleUseCredential from VP_GENERATED metadata', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: [],
          proven_claims: [],
          credential_types: [],
          used_zkp: false,
          single_use_credential: true,
        },
      }),
    ];
    expect(service.buildTransactions(entries)[0].singleUseCredential).toBe(true);
  });

  it('defaults singleUseCredential to false when missing', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: [],
          proven_claims: [],
          credential_types: [],
          used_zkp: false,
        },
      }),
    ];
    expect(service.buildTransactions(entries)[0].singleUseCredential).toBe(false);
  });

  it('computes lifecycle — keysCreated and keysDestroyed', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.keysCreated).toBe(2);
    expect(txns[0].lifecycle.keysDestroyed).toBe(1);
  });

  it('fullyShredded = true when all keys destroyed', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.fullyShredded).toBe(true);
  });

  it('fullyShredded = false when keys still open', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.fullyShredded).toBe(false);
  });

  it('fullyShredded = false when no keys created', () => {
    const entries = [
      makeEntry({ action: 'VP_GENERATED', metadata: { decision_id: DEC_ID, claims_shared: [], credential_types: [], proven_claims: [], used_zkp: false } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.fullyShredded).toBe(false);
  });

  it('computes shreddingLatencyMs correctly', () => {
    const t0 = new Date('2026-03-15T10:00:00Z');
    const t1 = new Date('2026-03-15T10:00:05Z');
    const entries = [
      makeEntry({ action: 'KEY_CREATED', timestamp: t0.toISOString(), metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', timestamp: t1.toISOString(), metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.shreddingLatencyMs).toBe(5000);
  });

  it('shreddingLatencyMs is null when no keys', () => {
    const entries = [
      makeEntry({ action: 'VP_GENERATED', metadata: { decision_id: DEC_ID, claims_shared: [], credential_types: [], proven_claims: [], used_zkp: false } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].lifecycle.shreddingLatencyMs).toBeNull();
  });

  it('extracts verifier label from DID', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          verifier_did: 'did:askmi:verifier-liquor-store',
          claims_shared: [],
          credential_types: [],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].verifierLabel).toBe('Liquor Store');
  });

  it('uses fallback label when no verifier', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].verifierLabel).toBe('Unbekannter Verifier');
  });

  it('sorts transactions newest first', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', timestamp: '2026-03-15T08:00:00Z', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_CREATED', timestamp: '2026-03-15T10:00:00Z', metadata: { decision_id: DEC_ID_2 } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].transactionId).toBe(DEC_ID_2);
    expect(txns[1].transactionId).toBe(DEC_ID);
  });

  it('builds single event transaction', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns).toHaveLength(1);
    expect(txns[0].events).toHaveLength(1);
  });

  it('graceful degradation — no VP_GENERATED → empty claimsShared', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsShared).toEqual([]);
    expect(txns[0].credentialTypes).toEqual([]);
    expect(txns[0].usedZKP).toBe(false);
  });

  it('computes claimsWithheld as set difference (requested - shared)', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          claims_requested: ['age', 'name', 'address'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsRequested).toEqual(['age', 'name', 'address']);
    expect(txns[0].claimsWithheld).toEqual(['name', 'address']);
  });

  it('claimsWithheld is empty when all requested claims shared', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age', 'name'],
          claims_requested: ['age', 'name'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsWithheld).toEqual([]);
  });

  it('claimsWithheld excludes proven predicates as well as shared claims', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: [],
          claims_requested: ['age >= 18'],
          proven_claims: ['age >= 18'],
          credential_types: ['AgeCredential'],
          used_zkp: true,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];

    const txns = service.buildTransactions(entries);

    expect(txns[0].claimsRequested).toEqual(['age >= 18']);
    expect(txns[0].provenClaims).toEqual(['age >= 18']);
    expect(txns[0].claimsWithheld).toEqual([]);
  });

  it('claimsWithheld is null when claims_requested missing (legacy)', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsRequested).toBeNull();
    expect(txns[0].claimsWithheld).toBeNull();
  });

  it('claimsRequested is null when no VP_GENERATED event', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsRequested).toBeNull();
    expect(txns[0].claimsWithheld).toBeNull();
  });

  it('claimsWithheld handles duplicates in requested', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          claims_requested: ['age', 'name', 'name'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsWithheld).toEqual(['name', 'name']);
  });

  it('claimsRequested carries full requested list', () => {
    const entries = [
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          claims_requested: ['age', 'birthDate', 'address'],
          credential_types: ['AgeCredential'],
          proven_claims: [],
          used_zkp: false,
          verifier_did: 'did:askmi:verifier-test',
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].claimsRequested).toEqual(['age', 'birthDate', 'address']);
  });

  it('sets startedAt and completedAt from event timestamps', () => {
    const t0 = '2026-03-15T10:00:00Z';
    const t1 = '2026-03-15T10:01:00Z';
    const entries = [
      makeEntry({ action: 'KEY_CREATED', timestamp: t0, metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'KEY_DESTROYED', timestamp: t1, metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].startedAt).toBe(t0);
    expect(txns[0].completedAt).toBe(t1);
  });

  it('extracts identity firewall accesses from audit metadata', () => {
    const entries = [
      makeEntry({
        action: 'IDENTITY_ACCESS_DETECTED',
        metadata: {
          decision_id: DEC_ID,
          verifier_did: 'did:askmi:verifier-test',
          access_type: 'browser_api',
          surface: 'navigator.userAgent',
          actor_label: 'Google Chrome',
          field_class: 'fingerprint',
          persistence: 'cloud',
          linkability: 'cross_context',
          severity: 'critical',
          blocked: false,
          source: 'privacy_audit_service',
        },
      }),
    ];

    const txns = service.buildTransactions(entries);
    expect(txns[0].identityAccessCount).toBe(1);
    expect(txns[0].identityAccesses[0].actor_label).toBe('Google Chrome');
    expect(txns[0].identityAccesses[0]).not.toHaveProperty('decision_id');
  });

  it('maps events with correct labels and categories', () => {
    const entries = [
      makeEntry({ action: 'KEY_CREATED', metadata: { decision_id: DEC_ID } }),
      makeEntry({ action: 'VP_GENERATED', metadata: { decision_id: DEC_ID, claims_shared: [], credential_types: [], proven_claims: [], used_zkp: false } }),
      makeEntry({ action: 'KEY_DESTROYED', metadata: { decision_id: DEC_ID } }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].events[0].label).toBe('Sitzungsschlüssel erzeugt');
    expect(txns[0].events[0].category).toBe('key');
    expect(txns[0].events[1].label).toBe('Präsentation erstellt');
    expect(txns[0].events[1].category).toBe('presentation');
    expect(txns[0].events[2].label).toBe('Schlüssel vernichtet');
    expect(txns[0].events[2].category).toBe('key');
  });
  it('returns correct label for IDENTITY_ACCESS_DETECTED', () => {
    const result = eventLabel('IDENTITY_ACCESS_DETECTED');
    expect(result.label).toBe('Identifier-Zugriff erkannt');
    expect(result.category).toBe('identity');
  });
});

describe('eventLabel', () => {
  it('returns correct label for KEY_CREATED', () => {
    const result = eventLabel('KEY_CREATED');
    expect(result.label).toBe('Sitzungsschlüssel erzeugt');
    expect(result.category).toBe('key');
  });

  it('returns correct label for VP_GENERATED', () => {
    expect(eventLabel('VP_GENERATED').label).toBe('Präsentation erstellt');
  });

  it('returns correct label for USER_CONSENT_GRANTED', () => {
    const result = eventLabel('USER_CONSENT_GRANTED');
    expect(result.label).toBe('Nutzer hat zugestimmt');
    expect(result.category).toBe('consent');
  });

  it('returns correct label for POLICY_BLOCKED', () => {
    const result = eventLabel('POLICY_BLOCKED');
    expect(result.label).toBe('Anfrage blockiert');
    expect(result.category).toBe('policy');
  });

  it('returns correct label for VC_IMPORTED', () => {
    const result = eventLabel('VC_IMPORTED');
    expect(result.label).toBe('Credential empfangen');
    expect(result.category).toBe('credential');
  });

  it('returns correct label for VC_DELETED', () => {
    expect(eventLabel('VC_DELETED').label).toBe('Credential gelöscht');
  });
});

describe('DataFlowService — Layer-2 visibility (G-140 PR2): read the disclosure event', () => {
  const service = new DataFlowService();

  function disclosureEvent(meta: Record<string, unknown>) {
    return makeEntry({
      action: 'POLICY_EVALUATED',
      metadata: { source: 'policy_engine', ...meta },
    });
  }

  it('builds a populated transaction for a DENY from the disclosure event alone (gap B: no VP_GENERATED)', () => {
    const entries = [
      disclosureEvent({
        decision_id: DEC_ID,
        verifier_did: 'did:askmi:verifier-deny',
        verdict: 'DENY',
        requested_claims: ['age', 'salary'],
        authorized_claims: [],
        denied_claims: ['age', 'salary'],
        reason_codes: ['NO_MATCHING_RULE'],
      }),
    ];
    const [txn] = service.buildTransactions(entries);
    expect(txn, 'a DENY must still produce a transaction').toBeDefined();
    expect(txn.verdict).toBe('DENY');
    expect(txn.claimsRequested).toEqual(['age', 'salary']);
    expect(txn.claimsWithheld).toEqual(['age', 'salary']); // nothing shared on a DENY
    expect(txn.verifierId).toBe('did:askmi:verifier-deny');
  });

  it('measures claimsWithheld against the raw verifier-requested claims (gap A: over-asking visible)', () => {
    const entries = [
      disclosureEvent({
        decision_id: DEC_ID,
        verifier_did: 'did:askmi:verifier-overask',
        verdict: 'ALLOW',
        requested_claims: ['age', 'salary'],
        authorized_claims: ['age'],
        denied_claims: ['salary'],
        reason_codes: [],
      }),
      makeEntry({
        action: 'VP_GENERATED',
        metadata: {
          decision_id: DEC_ID,
          claims_shared: ['age'],
          verifier_did: 'did:askmi:verifier-overask',
          credential_types: ['AgeCredential'],
        },
      }),
    ];
    const [txn] = service.buildTransactions(entries);
    // Raw requested set comes from the disclosure event, not the VP's own view:
    expect(txn.claimsRequested).toEqual(['age', 'salary']);
    expect(txn.claimsWithheld).toContain('salary'); // the over-asked claim is shown as withheld
    expect(txn.verdict).toBe('ALLOW');
  });
});
