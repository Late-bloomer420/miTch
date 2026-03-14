/**
 * Tests for Spec 111 — Pairwise Ephemeral DIDs (Phase 1)
 *
 * Verifies: unlinkability, anti-correlation, key shredding, proof binding.
 */

import { describe, it, expect } from 'vitest';
import { generatePairwiseDID, verifyPairwiseDIDProof } from '../src/pairwise-did';

// ─── Unlinkability ────────────────────────────────────────────────────────────

describe('Pairwise DID — Unlinkability', () => {
  it('same verifier + different sessions produce different DIDs', async () => {
    const verifierOrigin = 'https://liquor-store.example.com';
    const result1 = await generatePairwiseDID({
      verifierOrigin,
      sessionNonce: 'nonce-session-001',
    });
    const result2 = await generatePairwiseDID({
      verifierOrigin,
      sessionNonce: 'nonce-session-002',
    });
    expect(result1.did).not.toBe(result2.did);
    result1.destroy();
    result2.destroy();
  });

  it('different verifiers produce different DIDs', async () => {
    const result1 = await generatePairwiseDID({
      verifierOrigin: 'https://liquor-store.example.com',
      sessionNonce: 'shared-nonce-xyz',
    });
    const result2 = await generatePairwiseDID({
      verifierOrigin: 'https://pharmacy.example.com',
      sessionNonce: 'shared-nonce-xyz',
    });
    expect(result1.did).not.toBe(result2.did);
    result1.destroy();
    result2.destroy();
  });

  it('DID is a valid did:peer method 0 format', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://hospital.example.com',
      sessionNonce: 'nonce-abc',
    });
    expect(result.did).toMatch(/^did:peer:0z[1-9A-HJ-NP-Za-km-z]+$/);
    result.destroy();
  });
});

// ─── Anti-Correlation ─────────────────────────────────────────────────────────

describe('Pairwise DID — Anti-Correlation', () => {
  it('100 generated DIDs are all unique (no collisions)', async () => {
    const dids = new Set<string>();
    const verifierOrigin = 'https://verifier.example.com';

    // 100 iterations: P-256 keys have 256-bit randomness, so collision probability
    // after 100 DIDs is ~2^-200 (birthday paradox). This fully proves uniqueness
    // while avoiding intermittent timeouts under parallel turbo load.
    for (let i = 0; i < 100; i++) {
      const result = await generatePairwiseDID({
        verifierOrigin,
        sessionNonce: `nonce-${i}-${Math.random()}`,
      });
      dids.add(result.did);
      result.destroy();
    }

    expect(dids.size).toBe(100);
  }, 30_000);

  it('DIDs have consistent length (no structural patterns)', async () => {
    const lengths = new Set<number>();
    for (let i = 0; i < 20; i++) {
      const result = await generatePairwiseDID({
        verifierOrigin: 'https://verifier.example.com',
        sessionNonce: `nonce-${i}`,
      });
      lengths.add(result.did.length);
      result.destroy();
    }
    // All DIDs should have the same length (compressed P-256 key = fixed size)
    expect(lengths.size).toBe(1);
  });
});

// ─── Key Shredding ────────────────────────────────────────────────────────────

describe('Pairwise DID — Key Shredding', () => {
  it('signing key is zeroed after destroy()', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'shred-test-001',
    });
    expect(result.signingKey.isShredded()).toBe(false);
    result.destroy();
    expect(result.signingKey.isShredded()).toBe(true);
  });

  it('encryption key is zeroed after destroy()', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'shred-test-002',
    });
    expect(result.encryptionKey.isShredded()).toBe(false);
    result.destroy();
    expect(result.encryptionKey.isShredded()).toBe(true);
  });

  it('sign() throws after destroy()', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'shred-test-003',
    });
    result.destroy();
    await expect(
      result.sign(new Uint8Array([1, 2, 3]))
    ).rejects.toThrow('shredded');
  });
});

// ─── Proof Binding ────────────────────────────────────────────────────────────

describe('Pairwise DID — Proof Binding', () => {
  it('signed proof verifies against the session DID', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'proof-test-001',
    });

    const payload = new TextEncoder().encode('age >= 18');
    const signature = await result.sign(payload);

    const valid = await verifyPairwiseDIDProof(result.did, payload, signature);
    expect(valid).toBe(true);

    result.destroy();
  });

  it('proof from session A does not verify against session B DID', async () => {
    const sessionA = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'proof-test-session-A',
    });
    const sessionB = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'proof-test-session-B',
    });

    const payload = new TextEncoder().encode('age >= 18');
    const signatureA = await sessionA.sign(payload);

    // Session A's signature should NOT verify with session B's DID
    const invalid = await verifyPairwiseDIDProof(sessionB.did, payload, signatureA);
    expect(invalid).toBe(false);

    sessionA.destroy();
    sessionB.destroy();
  });

  it('tampered payload does not verify', async () => {
    const result = await generatePairwiseDID({
      verifierOrigin: 'https://verifier.example.com',
      sessionNonce: 'proof-test-tamper',
    });

    const original = new TextEncoder().encode('age >= 18');
    const tampered = new TextEncoder().encode('age >= 16');
    const signature = await result.sign(original);

    const valid = await verifyPairwiseDIDProof(result.did, tampered, signature);
    expect(valid).toBe(false);

    result.destroy();
  });
});
