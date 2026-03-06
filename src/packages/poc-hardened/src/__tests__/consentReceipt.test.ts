import { describe, it, expect } from 'vitest';
import { createConsentReceipt, ConsentReceiptStore, type CreateReceiptInput } from '../audit/consentReceipt';

const BASE_INPUT: CreateReceiptInput = {
    action: 'approved',
    verifierId: 'verifier-shop',
    verifierName: 'Cool Shop',
    verifierPolicyHash: 'abc123',
    claims: [{ name: 'over_18', tier: 'legal', disclosed: true }],
    requestHash: 'req-hash',
    responseHash: 'resp-hash',
    nonce: 'nonce-001',
};

describe('createConsentReceipt', () => {
    it('creates a receipt with correct version and action', () => {
        const r = createConsentReceipt(BASE_INPUT);
        expect(r.version).toBe('v0');
        expect(r.action).toBe('approved');
    });

    it('includes verifier info', () => {
        const r = createConsentReceipt(BASE_INPUT);
        expect(r.verifier.id).toBe('verifier-shop');
        expect(r.verifier.name).toBe('Cool Shop');
    });

    it('includes evidence hashes', () => {
        const r = createConsentReceipt(BASE_INPUT);
        expect(r.evidence.requestHash).toBe('req-hash');
        expect(r.evidence.nonce).toBe('nonce-001');
    });

    it('generates unique IDs', () => {
        const r1 = createConsentReceipt(BASE_INPUT);
        const r2 = createConsentReceipt(BASE_INPUT);
        expect(r1.id).not.toBe(r2.id);
    });

    it('sets remembered=false by default', () => {
        const r = createConsentReceipt(BASE_INPUT);
        expect(r.consent.remembered).toBe(false);
    });

    it('sets expiresAt when rememberUntil provided', () => {
        const until = Date.now() + 86400000;
        const r = createConsentReceipt({ ...BASE_INPUT, remembered: true, rememberUntil: until });
        expect(r.consent.expiresAt).toBe(until);
        expect(r.consent.remembered).toBe(true);
    });
});

describe('ConsentReceiptStore', () => {
    it('starts empty', () => {
        const store = new ConsentReceiptStore();
        expect(store.getAll()).toHaveLength(0);
    });

    it('adds and retrieves receipts', () => {
        const store = new ConsentReceiptStore();
        store.add(createConsentReceipt(BASE_INPUT));
        store.add(createConsentReceipt({ ...BASE_INPUT, action: 'declined' }));
        expect(store.getAll()).toHaveLength(2);
    });

    it('filters by verifier', () => {
        const store = new ConsentReceiptStore();
        store.add(createConsentReceipt(BASE_INPUT));
        store.add(createConsentReceipt({ ...BASE_INPUT, verifierId: 'other-verifier' }));
        expect(store.getByVerifier('verifier-shop')).toHaveLength(1);
        expect(store.getByVerifier('other-verifier')).toHaveLength(1);
    });

    it('revoke sets revokedAt', () => {
        const store = new ConsentReceiptStore();
        const r = createConsentReceipt(BASE_INPUT);
        store.add(r);
        const ok = store.revoke(r.id);
        expect(ok).toBe(true);
        expect(store.getAll()[0].consent.revokedAt).toBeDefined();
    });

    it('revoke returns false for unknown id', () => {
        const store = new ConsentReceiptStore();
        expect(store.revoke('nonexistent')).toBe(false);
    });

    it('getSummary aggregates counts correctly', () => {
        const store = new ConsentReceiptStore();
        store.add(createConsentReceipt({ ...BASE_INPUT, action: 'approved' }));
        store.add(createConsentReceipt({ ...BASE_INPUT, action: 'approved' }));
        store.add(createConsentReceipt({ ...BASE_INPUT, action: 'declined' }));
        store.add(createConsentReceipt({ ...BASE_INPUT, action: 'partial', verifierId: 'v2' }));

        const s = store.getSummary();
        expect(s.total).toBe(4);
        expect(s.approved).toBe(2);
        expect(s.declined).toBe(1);
        expect(s.partial).toBe(1);
        expect(s.uniqueVerifiers).toBe(2);
    });

    it('export returns valid structure', () => {
        const store = new ConsentReceiptStore();
        store.add(createConsentReceipt(BASE_INPUT));
        const exported = store.export() as any;
        expect(exported.format).toBe('mitch-consent-receipts-v0');
        expect(Array.isArray(exported.receipts)).toBe(true);
    });
});
