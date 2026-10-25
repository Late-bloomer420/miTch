import { describe, it, expect } from 'vitest';
import { generateReport } from '../report';
import type { EvidenceResult } from '../types';

const ts = new Date('2026-07-14T00:00:00.000Z');
const results: EvidenceResult[] = [
  { id: 'A', claim: 'a', category: 'stride', status: 'PASS', detail: 'ok' },
  { id: 'G', claim: 'g', category: 'fail-closed', status: 'RESIDUAL', detail: 'deferred' },
];

describe('generateReport', () => {
  it('is deterministic for the same results + timestamp (identical hash)', async () => {
    const r1 = await generateReport(results, { timestamp: ts });
    const r2 = await generateReport(results, { timestamp: ts });
    expect(r1.hash).toBe(r2.hash);
    expect(r1.markdown).toBe(r2.markdown);
  });
  it('changes the hash when a result changes', async () => {
    const r1 = await generateReport(results, { timestamp: ts });
    const changed = [{ ...results[0], status: 'FAIL' as const }, results[1]];
    const r2 = await generateReport(changed, { timestamp: ts });
    expect(r1.hash).not.toBe(r2.hash);
  });
  it('reports residuals separately from proven in the markdown', async () => {
    const r = await generateReport(results, { timestamp: ts });
    expect(r.markdown).toMatch(/RESIDUAL/);
    expect(r.markdown).toMatch(/Proven:\s*1/);
    expect(r.markdown).toMatch(/Residual:\s*1/);
  });
  it('includes a signature only when a signer is provided', async () => {
    const none = await generateReport(results, { timestamp: ts });
    expect(none.signature).toBeUndefined();
    const signed = await generateReport(results, { timestamp: ts, sign: async () => 'SIG' });
    expect(signed.signature).toBe('SIG');
  });
});
