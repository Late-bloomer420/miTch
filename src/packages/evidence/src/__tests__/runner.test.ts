import { describe, it, expect, vi } from 'vitest';
import { runEvidence, vitestExecutor, type TestExecutor } from '../runner';
import type { EvidenceClaim } from '../types';

const claim = (over: Partial<EvidenceClaim> = {}): EvidenceClaim => ({
  id: 'C1', claim: 'c', category: 'stride',
  pnpmFilter: '@askmi/evidence', packageDir: 'src/packages/evidence',
  testFile: 'src/__tests__/fixtures/passing.fixture.test.ts', ...over,
});

describe('runEvidence (logic, injected executor)', () => {
  it('maps a residual claim to RESIDUAL without calling the executor', async () => {
    const exec = vi.fn();
    const res = await runEvidence([claim({ id: 'R', residual: { reason: 'deferred' } })], exec as unknown as TestExecutor);
    expect(res[0].status).toBe('RESIDUAL');
    expect(res[0].detail).toContain('deferred');
    expect(exec).not.toHaveBeenCalled();
  });
  it('delegates a non-residual claim to the executor and records its status', async () => {
    const exec: TestExecutor = async () => ({ status: 'PASS', detail: 'ok' });
    const res = await runEvidence([claim()], exec);
    expect(res[0].status).toBe('PASS');
  });
  it('never throws — an executor that throws yields ERROR', async () => {
    const exec: TestExecutor = async () => { throw new Error('boom'); };
    const res = await runEvidence([claim()], exec);
    expect(res[0].status).toBe('ERROR');
    expect(res[0].detail).toContain('boom');
  });
});

describe('vitestExecutor (integration, real spawn)', () => {
  it('FAILs fail-closed when the test file does not exist', async () => {
    const r = await vitestExecutor(claim({ testFile: 'src/__tests__/does-not-exist.test.ts' }));
    expect(r.status).toBe('FAIL');
    expect(r.detail).toMatch(/not found/i);
  });
  it('PASSes for a real passing fixture test', async () => {
    const r = await vitestExecutor(claim());
    expect(r.status).toBe('PASS');
  }, 60_000);
});
