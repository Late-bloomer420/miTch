import { describe, it, expect } from 'vitest';
import { mapGet, toArrayBuffer } from '../util';

describe('mapGet()', () => {
    describe('Map input', () => {
        it('retrieves a value by string key', () => {
            const m = new Map<string, number>([['age', 27]]);
            expect(mapGet(m, 'age')).toBe(27);
        });

        it('retrieves a value by number key', () => {
            const m = new Map<number, string>([[1, 'one']]);
            expect(mapGet(m, 1)).toBe('one');
        });

        it('returns undefined for a missing key', () => {
            const m = new Map<string, number>([['age', 27]]);
            expect(mapGet(m, 'missing')).toBeUndefined();
        });
    });

    describe('plain object input', () => {
        it('retrieves a value by string key', () => {
            const obj = { name: 'Alice', age: 30 };
            expect(mapGet(obj, 'name')).toBe('Alice');
        });

        it('retrieves a value by numeric key from object', () => {
            const obj: Record<number, string> = { 0: 'zero', 1: 'one' };
            expect(mapGet(obj, 0)).toBe('zero');
        });

        it('returns undefined for a missing key in plain object', () => {
            const obj = { a: 1 };
            expect(mapGet(obj as any, 'b')).toBeUndefined();
        });
    });
});

describe('toArrayBuffer()', () => {
    it('produces an ArrayBuffer with the same bytes', () => {
        const source = new Uint8Array([10, 20, 30, 40]);
        const result = toArrayBuffer(source);
        expect(result).toBeInstanceOf(ArrayBuffer);
        expect(new Uint8Array(result)).toEqual(source);
    });

    it('returns a copy — mutating the original does not affect the result', () => {
        const source = new Uint8Array([1, 2, 3]);
        const result = toArrayBuffer(source);
        source[0] = 99;
        expect(new Uint8Array(result)[0]).toBe(1);
    });

    it('handles an empty Uint8Array', () => {
        const result = toArrayBuffer(new Uint8Array(0));
        expect(result.byteLength).toBe(0);
    });

    it('correct byteLength', () => {
        const source = new Uint8Array(16);
        expect(toArrayBuffer(source).byteLength).toBe(16);
    });
});
