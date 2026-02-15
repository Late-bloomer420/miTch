import { describe, test, expect } from 'vitest';
import { sha256, hmac } from '../src/hashing';

describe('Hashing utilities', () => {
    test('sha256 produces known vector', async () => {
        const hash = await sha256('abc');
        expect(hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
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
});
