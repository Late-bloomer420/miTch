/**
 * U-03 + U-04 — Unlinkability + Key Shredding Tests
 * Spec 111 Phase 1 + Phase 2
 */

import { describe, it, expect } from 'vitest';
import {
    generatePairwiseDID,
    generatePairwiseDIDFromMasterKey,
    resolveDidPeer0,
    verifyPairwiseDIDProof,
} from '../src/pairwise-did';
import { DIDResolver } from '../src/did';

// ─── Shared master key material (32 random bytes — fixed for determinism in tests) ──

const MASTER_KEY = new Uint8Array([
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
]);

// ─── U-01: HKDF Derivation Tests ──────────────────────────────────────────────

describe('U-01 — HKDF Pairwise DID from Master Key', () => {
    it('same master + same verifier + same nonce → same DID (deterministic)', async () => {
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.at', 'nonce-1');
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.at', 'nonce-1');
        expect(r1.did).toBe(r2.did);
        r1.destroy();
        r2.destroy();
    });

    it('same master + same verifier + different nonce → different DIDs', async () => {
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.at', 'nonce-A');
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.at', 'nonce-B');
        expect(r1.did).not.toBe(r2.did);
        r1.destroy();
        r2.destroy();
    });

    it('same master + different verifiers → different DIDs (cross-verifier unlinkability)', async () => {
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://liquor-store.at', 'nonce-x');
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://hospital.at', 'nonce-x');
        expect(r1.did).not.toBe(r2.did);
        r1.destroy();
        r2.destroy();
    });

    it('different master keys → different DIDs', async () => {
        const masterKey2 = new Uint8Array(32).fill(0xab);
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.at', 'nonce-1');
        const r2 = await generatePairwiseDIDFromMasterKey(masterKey2, 'https://shop.at', 'nonce-1');
        expect(r1.did).not.toBe(r2.did);
        r1.destroy();
        r2.destroy();
    });

    it('HKDF-derived DID has valid did:peer:0z format', async () => {
        const r = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://verifier.example', 'nonce-fmt');
        expect(r.did).toMatch(/^did:peer:0z[1-9A-HJ-NP-Za-km-z]+$/);
        r.destroy();
    });

    it('HKDF DID can sign and verify proof', async () => {
        const r = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://verifier.example', 'nonce-sign');
        const data = new TextEncoder().encode('decision-id-abc');
        const sig = await r.sign(data);
        const valid = await verifyPairwiseDIDProof(r.did, data, sig);
        expect(valid).toBe(true);
        r.destroy();
    });

    it('HKDF DID: different sessions produce different signatures for same data', async () => {
        const data = new TextEncoder().encode('test-data');
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://v.example', 'session-1');
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://v.example', 'session-2');
        const sig1 = await r1.sign(data);
        const sig2 = await r2.sign(data);
        // Different keys → different signatures
        expect(Buffer.from(sig1).toString('hex')).not.toBe(Buffer.from(sig2).toString('hex'));
        r1.destroy();
        r2.destroy();
    });

    it('50 HKDF-derived DIDs for different verifiers are all unique', async () => {
        const dids = new Set<string>();
        for (let i = 0; i < 50; i++) {
            const r = await generatePairwiseDIDFromMasterKey(
                MASTER_KEY,
                `https://verifier-${i}.example.com`,
                'shared-nonce'
            );
            dids.add(r.did);
            r.destroy();
        }
        expect(dids.size).toBe(50);
    });
});

// ─── U-02: did:peer Inline Resolution ─────────────────────────────────────────

describe('U-02 — did:peer:0 Inline Resolution', () => {
    it('resolveDidPeer0 returns valid DID Document', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v1', sessionNonce: 'n1' });
        const doc = await resolveDidPeer0(r.did);
        expect(doc.id).toBe(r.did);
        expect(doc.verificationMethod).toHaveLength(1);
        expect(doc.verificationMethod![0].type).toBe('JsonWebKey2020');
        expect(doc.authentication).toContain(`${r.did}#key-1`);
        r.destroy();
    });

    it('resolved DID Document contains P-256 JWK', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v2', sessionNonce: 'n2' });
        const doc = await resolveDidPeer0(r.did);
        const jwk = doc.verificationMethod![0].publicKeyJwk!;
        expect(jwk.kty).toBe('EC');
        expect(jwk.crv).toBe('P-256');
        expect(jwk.x).toBeTruthy();
        expect(jwk.y).toBeTruthy();
        r.destroy();
    });

    it('rejects non-did:peer:0 DIDs', async () => {
        await expect(resolveDidPeer0('did:web:example.com')).rejects.toThrow();
        await expect(resolveDidPeer0('did:peer:1somethingelse')).rejects.toThrow();
    });

    it('DIDResolver.resolve() handles did:peer:0 without network', async () => {
        const resolver = new DIDResolver({ allowMockFallback: false });
        const r = await generatePairwiseDID({ verifierOrigin: 'v3', sessionNonce: 'n3' });
        const doc = await resolver.resolve(r.did);
        expect(doc.id).toBe(r.did);
        expect(doc.verificationMethod!.length).toBeGreaterThan(0);
        r.destroy();
    });

    it('DIDResolver extracts verification key from did:peer:0', async () => {
        const resolver = new DIDResolver();
        const r = await generatePairwiseDID({ verifierOrigin: 'v4', sessionNonce: 'n4' });
        const key = await resolver.resolveAndExtractKey(r.did, 'authentication');
        expect(key).toBeTruthy();
        r.destroy();
    });

    it('resolved doc has assertionMethod and authentication set', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v5', sessionNonce: 'n5' });
        const doc = await resolveDidPeer0(r.did);
        expect(doc.assertionMethod).toBeDefined();
        expect(doc.assertionMethod!.length).toBeGreaterThan(0);
        r.destroy();
    });
});

// ─── U-04: Key Shredding Integration ──────────────────────────────────────────

describe('U-04 — Key Shredding after Interaction', () => {
    it('destroy() prevents further signing (random key path)', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v-shred', sessionNonce: 'ns1' });
        r.destroy();
        await expect(r.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow('shredded');
    });

    it('destroy() prevents further signing (HKDF path)', async () => {
        const r = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://v.example', 'shred-session');
        r.destroy();
        await expect(r.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow('shredded');
    });

    it('key is marked as shredded after destroy()', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v-mark', sessionNonce: 'ns2' });
        expect(r.signingKey.isShredded()).toBe(false);
        r.destroy();
        expect(r.signingKey.isShredded()).toBe(true);
        expect(r.encryptionKey.isShredded()).toBe(true);
    });

    it('proof is valid before destroy(), invalid attempt after', async () => {
        const r = await generatePairwiseDID({ verifierOrigin: 'v-proof', sessionNonce: 'ns3' });
        const data = new TextEncoder().encode('interaction-data');
        const sig = await r.sign(data);
        const valid = await verifyPairwiseDIDProof(r.did, data, sig);
        expect(valid).toBe(true);

        r.destroy();
        // Proof was computed before destroy — still verifiable via DID
        const stillValid = await verifyPairwiseDIDProof(r.did, data, sig);
        expect(stillValid).toBe(true); // DID is public — verification still works
    });

    it('50 concurrent interactions each get unique DID and are shredded', async () => {
        const dids = new Set<string>();
        const results = await Promise.all(
            Array.from({ length: 50 }, (_, i) =>
                generatePairwiseDID({ verifierOrigin: `v-${i}`, sessionNonce: `ns-${i}` })
            )
        );
        results.forEach(r => {
            dids.add(r.did);
            r.destroy();
        });
        expect(dids.size).toBe(50);
        expect(results.every(r => r.signingKey.isShredded())).toBe(true);
    });

    it('HKDF path: same session can be regenerated after destroy (recovery)', async () => {
        const verifierOrigin = 'https://recovery-test.example';
        const sessionNonce = 'recovery-nonce';

        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, verifierOrigin, sessionNonce);
        const did1 = r1.did;
        r1.destroy();

        // Regenerate with same master key → same DID
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, verifierOrigin, sessionNonce);
        expect(r2.did).toBe(did1);
        r2.destroy();
    });
});

// ─── U-03: Cross-Verifier Isolation ───────────────────────────────────────────

describe('U-03 — Cross-Verifier + Cross-Session Isolation', () => {
    it('proof signed for verifier A cannot be verified against verifier B DID', async () => {
        const dataA = new TextEncoder().encode('session-A-data');
        const rA = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://verifier-a.example', 'sess-1');
        const rB = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://verifier-b.example', 'sess-1');

        const sigA = await rA.sign(dataA);
        // Signature from A cannot verify against B's DID (different public key)
        const invalidCrossVerify = await verifyPairwiseDIDProof(rB.did, dataA, sigA);
        expect(invalidCrossVerify).toBe(false);

        rA.destroy();
        rB.destroy();
    });

    it('cross-session: same verifier different sessions → independent DIDs, proofs not interchangeable', async () => {
        const data = new TextEncoder().encode('common-data');
        const r1 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.example', 'session-1');
        const r2 = await generatePairwiseDIDFromMasterKey(MASTER_KEY, 'https://shop.example', 'session-2');

        const sig1 = await r1.sign(data);
        // sig1 should not verify against r2.did
        const cross = await verifyPairwiseDIDProof(r2.did, data, sig1);
        expect(cross).toBe(false);

        r1.destroy();
        r2.destroy();
    });

    it('random-key path: 100 verifiers cannot correlate any two DIDs', async () => {
        const dids = new Set<string>();
        for (let i = 0; i < 100; i++) {
            const r = await generatePairwiseDID({
                verifierOrigin: `https://verifier-${i}.example`,
                sessionNonce: 'fixed-nonce',
            });
            dids.add(r.did);
            r.destroy();
        }
        // All DIDs must be unique — no correlation possible
        expect(dids.size).toBe(100);
    }, 30_000);
});
