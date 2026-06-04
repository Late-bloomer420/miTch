import { describe, test, expect } from 'vitest';
import { sha256, sha256Bytes, hmac, verifyDigestMultibase } from '../src/hashing';
import { encodeBase58btc, wrapSha256Multihash } from '../src/multibase';

describe('Hashing utilities', () => {
    test('sha256 produces known vector', async () => {
        const hash = await sha256('abc');
        expect(hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    test('sha256Bytes produces raw bytes', async () => {
        const hash = await sha256Bytes('abc');
        expect(hash).toBeInstanceOf(Uint8Array);
        expect(hash.length).toBe(32);
        expect(hash[0]).toBe(0xba);
    });

    test('hmac produces deterministic output', async () => {
        // generate a temporary key for HMAC
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode('secret'),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const mac = await hmac(key, 'test-message');
        expect(mac).toBeDefined();
        expect(mac.length).toBe(64); // 256‑bit hex
    });

    test('verifyDigestMultibase validates correct hash', async () => {
        const content = 'Hello, AskMI!';
        const hashBytes = await sha256Bytes(content);
        const multihash = wrapSha256Multihash(hashBytes);
        const digest = encodeBase58btc(multihash);

        await expect(verifyDigestMultibase(content, digest)).resolves.not.toThrow();
    });

    test('verifyDigestMultibase fails on tampered content', async () => {
        const content = 'Hello, AskMI!';
        const hashBytes = await sha256Bytes(content);
        const multihash = wrapSha256Multihash(hashBytes);
        const digest = encodeBase58btc(multihash);

        await expect(verifyDigestMultibase('Tampered content', digest)).rejects.toThrow('DIGEST_VERIFICATION_FAILED');
    });

    test('verifyDigestMultibase fails on invalid multibase', async () => {
        await expect(verifyDigestMultibase('content', 'not-a-multibase')).rejects.toThrow('MULTIBASE_INVALID_ENCODING');
    });
});
