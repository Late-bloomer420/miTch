import { describe, it, expect } from 'vitest';
import { DataFlowService } from '../service';
import { eventLabel } from '../labels';
import type { AuditLogEntry } from '@mitch/shared-types';

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
          verifier_did: 'did:mitch:verifier-test',
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
          verifier_did: 'did:mitch:verifier-liquor-store',
          claims_shared: [],
          credential_types: [],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].verifierId).toBe('did:mitch:verifier-liquor-store');
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
          verifier_did: 'did:mitch:verifier-test',
          used_zkp: true,
        },
      }),
    ];
    const txns = service.buildTransactions(entries);
    expect(txns[0].provenClaims).toEqual(['age >= 18', 'age >= 21']);
    expect(txns[0].usedZKP).toBe(true);
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
          verifier_did: 'did:mitch:verifier-liquor-store',
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
