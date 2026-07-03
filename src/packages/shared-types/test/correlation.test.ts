import { describe, it, expect } from 'vitest';
import {
    newCorrelationId,
    isCorrelationId,
    resolveCorrelationId,
    CORRELATION_ID_PREFIX,
} from '../src/correlation';

describe('correlation (G-100.4) — canonical per-transaction id', () => {
    it('mints a prefixed, non-empty id that validates', () => {
        const id = newCorrelationId();
        expect(id.startsWith(CORRELATION_ID_PREFIX)).toBe(true);
        expect(id.length).toBeGreaterThan(CORRELATION_ID_PREFIX.length);
        expect(isCorrelationId(id)).toBe(true);
    });

    it('mints unique ids', () => {
        expect(newCorrelationId()).not.toBe(newCorrelationId());
    });

    it('rejects non-correlation values', () => {
        expect(isCorrelationId(undefined)).toBe(false);
        expect(isCorrelationId(null)).toBe(false);
        expect(isCorrelationId(42)).toBe(false);
        expect(isCorrelationId('')).toBe(false);
        expect(isCorrelationId('abc123')).toBe(false);
        expect(isCorrelationId(CORRELATION_ID_PREFIX)).toBe(false); // prefix only, no body
    });

    it('prefers an explicit verifier-minted correlation id', () => {
        const minted = newCorrelationId();
        expect(resolveCorrelationId({ correlationId: minted, nonce: 'abc' })).toBe(minted);
    });

    it('derives a stable id from the nonce when none is supplied', () => {
        expect(resolveCorrelationId({ nonce: 'nonce-123' })).toBe(`${CORRELATION_ID_PREFIX}nonce-123`);
    });

    it('is deterministic per nonce so services agree on the same id', () => {
        const a = resolveCorrelationId({ nonce: 'shared-nonce' });
        const b = resolveCorrelationId({ nonce: 'shared-nonce' });
        expect(a).toBe(b);
    });

    it('ignores an invalid explicit id and falls back to the nonce', () => {
        expect(resolveCorrelationId({ correlationId: 'not-valid', nonce: 'n1' })).toBe(
            `${CORRELATION_ID_PREFIX}n1`,
        );
    });

    it('mints a fresh id when neither id nor nonce is available', () => {
        const id = resolveCorrelationId({});
        expect(isCorrelationId(id)).toBe(true);
    });
});
