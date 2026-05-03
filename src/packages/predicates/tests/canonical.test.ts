import { describe, it, expect } from 'vitest';
import { canonicalStringify } from '../src/canonical';

describe('canonicalStringify()', () => {
    describe('primitives', () => {
        it('serializes a string', () => {
            expect(canonicalStringify('hello')).toBe('"hello"');
        });

        it('serializes a number', () => {
            expect(canonicalStringify(42)).toBe('42');
        });

        it('serializes null', () => {
            expect(canonicalStringify(null)).toBe('null');
        });

        it('serializes a boolean', () => {
            expect(canonicalStringify(true)).toBe('true');
            expect(canonicalStringify(false)).toBe('false');
        });
    });

    describe('objects', () => {
        it('serializes an empty object', () => {
            expect(canonicalStringify({})).toBe('{}');
        });

        it('sorts keys alphabetically', () => {
            const result = canonicalStringify({ z: 1, a: 2, m: 3 });
            expect(result).toBe('{"a":2,"m":3,"z":1}');
        });

        it('omits undefined values in objects', () => {
            const result = canonicalStringify({ a: 1, b: undefined, c: 3 });
            expect(result).toBe('{"a":1,"c":3}');
        });

        it('omits function values in objects', () => {
            const result = canonicalStringify({ a: 1, fn: () => 'x' });
            expect(result).toBe('{"a":1}');
        });

        it('serializes nested objects with sorted keys', () => {
            const result = canonicalStringify({ b: { z: 1, a: 2 }, a: { y: 3, x: 4 } });
            expect(result).toBe('{"a":{"x":4,"y":3},"b":{"a":2,"z":1}}');
        });
    });

    describe('arrays', () => {
        it('serializes an empty array', () => {
            expect(canonicalStringify([])).toBe('[]');
        });

        it('preserves array order', () => {
            expect(canonicalStringify([3, 1, 2])).toBe('[3,1,2]');
        });

        it('serializes undefined in arrays as null', () => {
            const arr = [1, undefined, 3];
            expect(canonicalStringify(arr)).toBe('[1,null,3]');
        });

        it('serializes function in arrays as null', () => {
            const arr: unknown[] = [1, () => 'x', 3];
            expect(canonicalStringify(arr)).toBe('[1,null,3]');
        });
    });

    describe('Date', () => {
        it('serializes Date as a quoted ISO string', () => {
            const d = new Date('2025-01-15T12:00:00.000Z');
            const result = canonicalStringify(d);
            expect(result).toBe('"2025-01-15T12:00:00.000Z"');
        });
    });

    describe('BigInt — fail-closed', () => {
        it('throws CANONICAL_STRINGIFY_UNSUPPORTED for BigInt values', () => {
            expect(() => canonicalStringify(BigInt(42))).toThrow('CANONICAL_STRINGIFY_UNSUPPORTED');
        });

        it('throws when BigInt appears inside an object', () => {
            expect(() => canonicalStringify({ n: BigInt(1) })).toThrow('CANONICAL_STRINGIFY_UNSUPPORTED');
        });
    });

    describe('circular references — fail-closed', () => {
        it('throws CANONICAL_STRINGIFY_CYCLE for self-referencing objects', () => {
            const obj: Record<string, unknown> = {};
            obj.self = obj;
            expect(() => canonicalStringify(obj)).toThrow('CANONICAL_STRINGIFY_CYCLE');
        });

        it('throws CANONICAL_STRINGIFY_CYCLE for indirect cycles', () => {
            const a: Record<string, unknown> = {};
            const b: Record<string, unknown> = { a };
            a.b = b;
            expect(() => canonicalStringify(a)).toThrow('CANONICAL_STRINGIFY_CYCLE');
        });
    });

    describe('determinism', () => {
        it('produces identical output for the same input on multiple calls', () => {
            const obj = { c: [1, 2], b: { x: true }, a: 'hello' };
            expect(canonicalStringify(obj)).toBe(canonicalStringify(obj));
        });

        it('produces identical output regardless of key insertion order', () => {
            const obj1 = { a: 1, b: 2 };
            const obj2 = { b: 2, a: 1 };
            expect(canonicalStringify(obj1)).toBe(canonicalStringify(obj2));
        });
    });

    describe('top-level edge cases', () => {
        it('throws CANONICAL_STRINGIFY_TOPLEVEL_UNDEFINED for top-level undefined', () => {
            expect(() => canonicalStringify(undefined)).toThrow('CANONICAL_STRINGIFY_TOPLEVEL_UNDEFINED');
        });
    });
});
