import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LocalAuditLog } from '../src/index.js';
import type { AuditEvent } from '../src/index.js';

describe('LocalAuditLog', () => {
  let log: LocalAuditLog;

  beforeEach(async () => {
    log = new LocalAuditLog();
    await log.initialize();
  });

  afterEach(() => {
    log.close();
  });

  // -------------------------------------------------------------------------
  // Initialization
  // -------------------------------------------------------------------------
  describe('initialize', () => {
    it('initializes without throwing', async () => {
      const freshLog = new LocalAuditLog();
      await expect(freshLog.initialize()).resolves.toBeUndefined();
    });

    it('can be initialized multiple times safely', async () => {
      const freshLog = new LocalAuditLog();
      await freshLog.initialize();
      await expect(freshLog.initialize()).resolves.toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Append
  // -------------------------------------------------------------------------
  describe('append', () => {
    it('appends an event and increments count', async () => {
      const event: AuditEvent = {
        type: 'KEY_GENERATED',
        timestamp: Date.now(),
        details: { keyType: 'ECDSA-P256' },
      };

      await log.append(event);
      const count = await log.getCount();
      expect(count).toBe(1);
    });

    it('appends multiple events', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: {} });
      await log.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: {} });
      await log.append({ type: 'CREDENTIAL_PRESENTED', timestamp: 3000, details: {} });

      const count = await log.getCount();
      expect(count).toBe(3);
    });

    it('auto-sets timestamp if missing', async () => {
      const event: AuditEvent = {
        type: 'KEY_GENERATED',
        timestamp: 0, // falsy
        details: { info: 'auto-time' },
      };

      const before = Date.now();
      await log.append(event);
      const exported = await log.exportForUser();
      const entry = exported.entries[0];

      expect(entry.timestamp).toBeGreaterThanOrEqual(before);
    });

    it('throws if not initialized', async () => {
      const uninitLog = new LocalAuditLog();
      // Attempting append without init should either throw or auto-init.
      // The code throws: 'Audit-log not initialized'
      await expect(
        uninitLog.append({ type: 'KEY_GENERATED', timestamp: Date.now(), details: {} }),
      ).rejects.toThrow('Audit-log not initialized');
    });
  });

  // -------------------------------------------------------------------------
  // Hash chain integrity
  // -------------------------------------------------------------------------
  describe('verifyIntegrity', () => {
    it('returns true for empty log', async () => {
      const result = await log.verifyIntegrity();
      expect(result).toBe(true);
    });

    it('returns true for a single entry', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: Date.now(), details: {} });
      const result = await log.verifyIntegrity();
      expect(result).toBe(true);
    });

    it('returns true for a chain of entries', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: { step: 1 } });
      await log.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: { step: 2 } });
      await log.append({ type: 'POLICY_EVALUATED', timestamp: 3000, details: { step: 3 } });
      await log.append({ type: 'CREDENTIAL_PRESENTED', timestamp: 4000, details: { step: 4 } });

      const result = await log.verifyIntegrity();
      expect(result).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Export
  // -------------------------------------------------------------------------
  describe('exportForUser', () => {
    it('exports empty log with genesis hash', async () => {
      const exported = await log.exportForUser();
      expect(exported.entries).toHaveLength(0);
      expect(exported.integrityProof.totalEntries).toBe(0);
      expect(exported.integrityProof.rootHash).toBe('0'.repeat(64));
    });

    it('exports entries with integrity proof', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: { k: 'v' } });
      await log.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: { c: 'd' } });

      const exported = await log.exportForUser();
      expect(exported.entries).toHaveLength(2);
      expect(exported.integrityProof.totalEntries).toBe(2);
      expect(exported.integrityProof.rootHash).not.toBe('0'.repeat(64));
      expect(exported.integrityProof.firstTimestamp).toBe(1000);
      expect(exported.integrityProof.lastTimestamp).toBe(2000);
    });

    it('exported entries preserve event type and details', async () => {
      await log.append({
        type: 'CREDENTIAL_PRESENTED',
        timestamp: 5000,
        details: { verifier: 'did:mitch:liquor-store', claim: 'age_over_18' },
      });

      const exported = await log.exportForUser();
      const entry = exported.entries[0];
      expect(entry.type).toBe('CREDENTIAL_PRESENTED');
      expect(entry.details.verifier).toBe('did:mitch:liquor-store');
      expect(entry.details.claim).toBe('age_over_18');
    });

    it('throws if not initialized', async () => {
      const uninitLog = new LocalAuditLog();
      await expect(uninitLog.exportForUser()).rejects.toThrow('Audit-log not initialized');
    });
  });

  // -------------------------------------------------------------------------
  // Delete (GDPR Art. 17)
  // -------------------------------------------------------------------------
  describe('deleteAll', () => {
    it('clears all entries', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: {} });
      await log.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: {} });

      let count = await log.getCount();
      expect(count).toBe(2);

      await log.deleteAll();

      count = await log.getCount();
      expect(count).toBe(0);
    });

    it('resets hash chain after deletion', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: {} });
      await log.deleteAll();

      const exported = await log.exportForUser();
      expect(exported.integrityProof.rootHash).toBe('0'.repeat(64));
    });

    it('allows appending after deleteAll', async () => {
      await log.append({ type: 'KEY_GENERATED', timestamp: 1000, details: {} });
      await log.deleteAll();
      await log.append({ type: 'CREDENTIAL_ISSUED', timestamp: 2000, details: {} });

      const count = await log.getCount();
      expect(count).toBe(1);

      const result = await log.verifyIntegrity();
      expect(result).toBe(true);
    });

    it('throws if not initialized', async () => {
      const uninitLog = new LocalAuditLog();
      await expect(uninitLog.deleteAll()).rejects.toThrow('Audit-log not initialized');
    });
  });

  // -------------------------------------------------------------------------
  // getCount
  // -------------------------------------------------------------------------
  describe('getCount', () => {
    it('returns 0 for empty log', async () => {
      const count = await log.getCount();
      expect(count).toBe(0);
    });

    it('tracks count accurately', async () => {
      for (let i = 0; i < 5; i++) {
        await log.append({ type: 'POLICY_EVALUATED', timestamp: 1000 + i, details: { i } });
      }
      const count = await log.getCount();
      expect(count).toBe(5);
    });

    it('throws if not initialized', async () => {
      const uninitLog = new LocalAuditLog();
      await expect(uninitLog.getCount()).rejects.toThrow('Audit-log not initialized');
    });
  });

  // -------------------------------------------------------------------------
  // Encryption (entries are AES-GCM encrypted at rest)
  // -------------------------------------------------------------------------
  describe('encryption', () => {
    it('stores encrypted data that can be decrypted within the same session', async () => {
      const sensitiveDetails = {
        verifier: 'did:mitch:hospital',
        claim: 'blood_type',
        value: 'A+',
      };

      await log.append({
        type: 'CREDENTIAL_PRESENTED',
        timestamp: Date.now(),
        details: sensitiveDetails,
      });

      const exported = await log.exportForUser();
      expect(exported.entries).toHaveLength(1);
      expect(exported.entries[0].details.value).toBe('A+');
    });
  });

  // -------------------------------------------------------------------------
  // Event types coverage
  // -------------------------------------------------------------------------
  describe('event types', () => {
    const allTypes: AuditEvent['type'][] = [
      'CREDENTIAL_ISSUED',
      'CREDENTIAL_PRESENTED',
      'POLICY_EVALUATED',
      'KEY_GENERATED',
      'KEY_DESTROYED',
      'HUMAN_VERIFICATION',
      'AUTOMATION_BLOCKED',
    ];

    for (const eventType of allTypes) {
      it(`handles event type: ${eventType}`, async () => {
        await log.append({ type: eventType, timestamp: Date.now(), details: { test: true } });
        const exported = await log.exportForUser();
        expect(exported.entries[0].type).toBe(eventType);
      });
    }
  });
});
