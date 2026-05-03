import { describe, it, expect } from 'vitest';
import { SecureBuffer } from '../src/secure-buffer';

describe('SecureBuffer — construction', () => {
    it('allocates zeroed buffer of given size', () => {
        const buf = new SecureBuffer(8);
        const view = buf.view;
        expect(view.byteLength).toBe(8);
        for (const byte of view) {
            expect(byte).toBe(0);
        }
    });

    it('copies data from Uint8Array (owns the buffer)', () => {
        const source = new Uint8Array([1, 2, 3, 4]);
        const buf = new SecureBuffer(source);
        expect(buf.view).toEqual(source);

        // Mutating source must not affect the SecureBuffer
        source[0] = 99;
        expect(buf.view[0]).toBe(1);
    });

    it('handles zero-length input', () => {
        const buf = new SecureBuffer(0);
        expect(buf.view.byteLength).toBe(0);
    });
});

describe('SecureBuffer.fromString()', () => {
    it('encodes a string to UTF-8 bytes', () => {
        const buf = SecureBuffer.fromString('hello');
        const expected = new TextEncoder().encode('hello');
        expect(buf.view).toEqual(expected);
    });

    it('creates an empty buffer from an empty string', () => {
        const buf = SecureBuffer.fromString('');
        expect(buf.view.byteLength).toBe(0);
    });

    it('handles multi-byte UTF-8 characters', () => {
        const text = 'Ä Ö Ü'; // multi-byte in UTF-8
        const buf = SecureBuffer.fromString(text);
        expect(buf.view).toEqual(new TextEncoder().encode(text));
    });
});

describe('SecureBuffer.view', () => {
    it('returns the data before shredding', () => {
        const buf = new SecureBuffer(new Uint8Array([5, 10, 15]));
        const view = buf.view;
        expect(view[0]).toBe(5);
        expect(view[1]).toBe(10);
        expect(view[2]).toBe(15);
    });

    it('throws SECURITY VIOLATION after shredding', () => {
        const buf = new SecureBuffer(4);
        buf.shred();
        expect(() => buf.view).toThrow('SECURITY VIOLATION');
    });
});

describe('SecureBuffer.shred()', () => {
    it('overwrites all bytes with 0x00 before releasing', () => {
        const source = new Uint8Array([1, 2, 3, 4, 5]);
        const buf = new SecureBuffer(source);

        // Capture reference before shred
        const viewBeforeShred = buf.view;
        buf.shred();

        // The underlying typed array should have been zeroed in-place
        for (const byte of viewBeforeShred) {
            expect(byte).toBe(0);
        }
    });

    it('calling shred() twice does not throw', () => {
        const buf = new SecureBuffer(4);
        buf.shred();
        expect(() => buf.shred()).not.toThrow();
    });

    it('view is inaccessible after second shred call', () => {
        const buf = new SecureBuffer(4);
        buf.shred();
        buf.shred();
        expect(() => buf.view).toThrow('SECURITY VIOLATION');
    });
});
