import { describe, it, expect } from 'vitest';
import {
    createInitialState,
    calculateRemaining,
    recordImpression,
    mergeStates,
    needsReset,
    resetCounters,
} from '../src/sync/crdt-state';
import { InMemorySyncAdapter } from '../src/sync/storage-adapter';

const RESET_AT = '2026-03-12T00:00:00Z';

// ---------------------------------------------------------------------------
// createInitialState
// ---------------------------------------------------------------------------

describe('createInitialState', () => {
    it('creates state with empty counters', () => {
        const state = createInitialState(20, RESET_AT);
        expect(state.version).toBe('1.0');
        expect(state.counters).toEqual({});
        expect(state.dailyLimit).toBe(20);
        expect(state.resetAt).toBe(RESET_AT);
    });
});

// ---------------------------------------------------------------------------
// calculateRemaining
// ---------------------------------------------------------------------------

describe('calculateRemaining', () => {
    it('returns full limit when no impressions', () => {
        const state = createInitialState(20, RESET_AT);
        expect(calculateRemaining(state)).toBe(20);
    });

    it('subtracts total across all devices', () => {
        const state = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 3, 'device-B': 2 },
        };
        expect(calculateRemaining(state)).toBe(15);
    });

    it('never returns negative', () => {
        const state = {
            ...createInitialState(5, RESET_AT),
            counters: { 'device-A': 10 }, // over limit
        };
        expect(calculateRemaining(state)).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// recordImpression
// ---------------------------------------------------------------------------

describe('recordImpression', () => {
    it('increments own device counter', () => {
        const state = createInitialState(20, RESET_AT);
        const next = recordImpression(state, 'device-A');
        expect(next.counters['device-A']).toBe(1);
    });

    it('does not mutate original state (immutable)', () => {
        const state = createInitialState(20, RESET_AT);
        recordImpression(state, 'device-A');
        expect(state.counters['device-A']).toBeUndefined();
    });

    it('increments only the specified device', () => {
        const state = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 2, 'device-B': 1 },
        };
        const next = recordImpression(state, 'device-A');
        expect(next.counters['device-A']).toBe(3);
        expect(next.counters['device-B']).toBe(1); // unchanged
    });
});

// ---------------------------------------------------------------------------
// mergeStates
// ---------------------------------------------------------------------------

describe('mergeStates', () => {
    it('correctly merges concurrent updates (CRDT key property)', () => {
        const stateA = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 3, 'device-B': 1 },
        };
        const stateB = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 2, 'device-B': 2 },
        };

        const merged = mergeStates(stateA, stateB);

        // CRDT: take max per device
        expect(merged.counters['device-A']).toBe(3); // max(3, 2)
        expect(merged.counters['device-B']).toBe(2); // max(1, 2)
        expect(calculateRemaining(merged)).toBe(15); // 20 - 5
    });

    it('handles new device appearing in remote state', () => {
        const existing = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 5 },
        };
        const withNewDevice = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 5, 'device-C': 1 },
        };

        const merged = mergeStates(existing, withNewDevice);

        expect(Object.keys(merged.counters)).toContain('device-C');
        expect(merged.counters['device-C']).toBe(1);
        expect(calculateRemaining(merged)).toBe(14); // 20 - 6
    });

    it('is commutative: merge(A, B) == merge(B, A)', () => {
        const stateA = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 4, 'device-B': 1 },
        };
        const stateB = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 2, 'device-B': 3 },
        };

        const ab = mergeStates(stateA, stateB);
        const ba = mergeStates(stateB, stateA);

        expect(ab.counters).toEqual(ba.counters);
        expect(calculateRemaining(ab)).toBe(calculateRemaining(ba));
    });

    it('is idempotent: merge(A, A) == A', () => {
        const state = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 3 },
        };
        const merged = mergeStates(state, state);
        expect(merged.counters['device-A']).toBe(3);
    });

    it('takes larger dailyLimit across devices', () => {
        const stateA = { ...createInitialState(10, RESET_AT) };
        const stateB = { ...createInitialState(20, RESET_AT) };
        const merged = mergeStates(stateA, stateB);
        expect(merged.dailyLimit).toBe(20);
    });

    it('takes later resetAt timestamp', () => {
        const stateA = { ...createInitialState(10, '2026-03-12T00:00:00Z') };
        const stateB = { ...createInitialState(10, '2026-03-13T00:00:00Z') };
        const merged = mergeStates(stateA, stateB);
        expect(merged.resetAt).toBe('2026-03-13T00:00:00Z');
    });
});

// ---------------------------------------------------------------------------
// needsReset / resetCounters
// ---------------------------------------------------------------------------

describe('needsReset', () => {
    it('returns false before reset time', () => {
        const state = createInitialState(20, '2099-01-01T00:00:00Z');
        expect(needsReset(state, new Date('2026-03-11T23:59:59Z'))).toBe(false);
    });

    it('returns true after reset time', () => {
        const state = createInitialState(20, '2026-03-11T00:00:00Z');
        expect(needsReset(state, new Date('2026-03-12T00:00:01Z'))).toBe(true);
    });
});

describe('resetCounters', () => {
    it('clears all counters', () => {
        const state = {
            ...createInitialState(20, RESET_AT),
            counters: { 'device-A': 5, 'device-B': 3 },
        };
        const next = resetCounters(state, 'device-A', '2026-03-13T00:00:00Z');
        expect(next.counters).toEqual({});
        expect(next.dailyLimit).toBe(20);
        expect(next.resetAt).toBe('2026-03-13T00:00:00Z');
    });
});

// ---------------------------------------------------------------------------
// InMemorySyncAdapter
// ---------------------------------------------------------------------------

describe('InMemorySyncAdapter', () => {
    it('stores and retrieves blobs', async () => {
        const adapter = new InMemorySyncAdapter();
        const blob = new Uint8Array([1, 2, 3, 4]);
        await adapter.put('test-key', blob);
        const retrieved = await adapter.get('test-key');
        expect(retrieved).toEqual(blob);
    });

    it('returns null for missing keys', async () => {
        const adapter = new InMemorySyncAdapter();
        expect(await adapter.get('nonexistent')).toBeNull();
    });

    it('deletes keys', async () => {
        const adapter = new InMemorySyncAdapter();
        await adapter.put('key', new Uint8Array([1]));
        await adapter.delete('key');
        expect(await adapter.get('key')).toBeNull();
    });

    it('notifies watchers on put', async () => {
        const adapter = new InMemorySyncAdapter();
        const received: Uint8Array[] = [];
        adapter.watch('sync-key', (blob) => received.push(blob));

        const blob = new Uint8Array([9, 8, 7]);
        await adapter.put('sync-key', blob);

        expect(received).toHaveLength(1);
        expect(received[0]).toEqual(blob);
    });

    it('unsubscribe stops notifications', async () => {
        const adapter = new InMemorySyncAdapter();
        const received: Uint8Array[] = [];
        const unsubscribe = adapter.watch('key', (b) => received.push(b));

        await adapter.put('key', new Uint8Array([1]));
        unsubscribe();
        await adapter.put('key', new Uint8Array([2]));

        expect(received).toHaveLength(1); // only the first one
    });
});
