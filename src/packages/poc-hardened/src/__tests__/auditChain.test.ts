import { describe, it, expect } from 'vitest';
import { AuditChain } from '../audit/auditChain';

describe('AuditChain', () => {
    it('starts empty with GENESIS hash', () => {
        const chain = new AuditChain();
        expect(chain.length).toBe(0);
        expect(chain.latest).toBeUndefined();
    });

    it('appends entries and increments length', () => {
        const chain = new AuditChain();
        chain.append('credential_issued', { credentialHash: 'abc' });
        chain.append('consent_given', { consentHash: 'def' });
        expect(chain.length).toBe(2);
    });

    it('first entry has previousHash = GENESIS', () => {
        const chain = new AuditChain();
        const entry = chain.append('credential_issued', {});
        expect(entry.previousHash).toBe('GENESIS');
        expect(entry.sequence).toBe(0);
    });

    it('second entry previousHash = first entry entryHash', () => {
        const chain = new AuditChain();
        const e1 = chain.append('credential_issued', {});
        const e2 = chain.append('consent_given', {});
        expect(e2.previousHash).toBe(e1.entryHash);
    });

    it('verify() returns valid for intact chain', () => {
        const chain = new AuditChain();
        chain.append('credential_issued', { credentialHash: 'h1' });
        chain.append('credential_presented', { disclosureHash: 'h2' });
        chain.append('consent_given', { consentHash: 'h3' });
        expect(chain.verify().valid).toBe(true);
    });

    it('verify() returns valid for empty chain', () => {
        const chain = new AuditChain();
        expect(chain.verify().valid).toBe(true);
    });

    it('tampering entry hash breaks verification', () => {
        const chain = new AuditChain();
        chain.append('credential_issued', {});
        chain.append('credential_presented', {});

        // getEntries() returns shallow copy — objects are same references
        // so mutating entryHash DOES affect the chain's internal state
        const entries = chain.getEntries();
        (entries[0] as any).entryHash = 'tampered';

        // verify() recomputes hash and detects mismatch
        expect(chain.verify().valid).toBe(false);
    });

    it('export() returns valid JSON with chainLength', () => {
        const chain = new AuditChain();
        chain.append('verification_allowed', { verifierIdHash: 'v1' });
        const exported = JSON.parse(chain.export());
        expect(exported.chainLength).toBe(1);
        expect(exported.verified).toBe(true);
        expect(Array.isArray(exported.entries)).toBe(true);
    });

    it('entry has ISO timestamp and coarse timestamp', () => {
        const chain = new AuditChain();
        const e = chain.append('crypto_shred', {
            shredProof: { keyId: 'k1', algorithm: 'AES-GCM', destroyedAt: new Date().toISOString(), method: 'key_zeroed' }
        });
        expect(e.timestamp).toMatch(/^\d{4}-/);
        expect(e.timestampCoarse).toMatch(/^\d{4}-\d{2}$/);
    });

    it('each entry has unique id', () => {
        const chain = new AuditChain();
        const ids = new Set<string>();
        for (let i = 0; i < 5; i++) {
            ids.add(chain.append('consent_given', {}).id);
        }
        expect(ids.size).toBe(5);
    });

    it('getEntries() returns a copy (not mutable reference)', () => {
        const chain = new AuditChain();
        chain.append('credential_issued', {});
        const entries = chain.getEntries();
        entries.pop();
        expect(chain.length).toBe(1); // original not affected
    });
});
