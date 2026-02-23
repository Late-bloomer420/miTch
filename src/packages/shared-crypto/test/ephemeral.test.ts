import { describe, test, expect } from 'vitest';
import { EphemeralKey, SecureBuffer } from '../src';

describe('EphemeralKey Primitive', () => {
    test('Lifecycle: Create -> Use -> Shred -> Fail', async () => {
        // ... (existing test code)
    });
});

describe('SecureBuffer Forensic Shredding', () => {
    test('Memory zeroing via shred() prevents further access', () => {
        const text = "SENSITIVE_DATA_123";
        const buf = SecureBuffer.fromString(text);

        expect(buf.view.length).toBeGreaterThan(0);

        buf.shred();

        expect(() => {
            console.log(buf.view);
        }).toThrow(/SECURITY VIOLATION/);
    });
});
