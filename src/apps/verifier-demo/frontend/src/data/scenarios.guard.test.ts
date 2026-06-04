import { describe, it, expect } from 'vitest';
import { ASKMI_SCENARIO_CLAIMS, type AskmiScenarioId } from '@askmi/shared-types';
import { SCENARIOS, SCENARIO_ORDER } from './scenarios';

/**
 * Drift guard for S2-04.
 *
 * `data/scenarios.ts` is deliberately kept as local presentation copy and is NOT
 * derived from `ASKMI_SCENARIO_CLAIMS`. This guard makes sure the two cannot
 * silently drift on real claim values (the bug class that left `doctor-login`
 * age at 24 here while the canonical/backend/wallet value was 35).
 *
 * It intentionally does NOT force the frontend to mirror the canonical structure:
 * - Redaction/placeholder copy may differ (e.g. canonical 'redacted' vs the
 *   frontend's '€ [redacted]'), so those keys are skipped.
 * - The frontend need not display every canonical claim, so we only compare keys
 *   that are actually shown.
 */
function isComparable(value: unknown): boolean {
  if (typeof value === 'number') return true;
  if (typeof value === 'string') return !/redacted|\[|\]/.test(value);
  return false;
}

describe('verifier-demo scenario fixtures stay consistent with canonical claims', () => {
  it('exposes the same scenario IDs as the canonical fixtures', () => {
    const canonicalIds = (Object.keys(ASKMI_SCENARIO_CLAIMS) as AskmiScenarioId[]).sort();
    expect([...SCENARIO_ORDER].sort()).toEqual(canonicalIds);
  });

  for (const id of SCENARIO_ORDER) {
    it(`displays canonical real claim values for "${id}" without drifting`, () => {
      const canonical = ASKMI_SCENARIO_CLAIMS[id as AskmiScenarioId];

      // Flatten the displayed wallet-credential fields into key -> displayed string.
      const displayed = new Map<string, string>();
      for (const cred of SCENARIOS[id].walletCredentials) {
        for (const field of cred.fields) displayed.set(field.key, field.value);
      }

      for (const [key, value] of Object.entries(canonical)) {
        if (!isComparable(value)) continue;
        if (!displayed.has(key)) continue;
        expect(displayed.get(key)).toBe(String(value));
      }
    });
  }
});
