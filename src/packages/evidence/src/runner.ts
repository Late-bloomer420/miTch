import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EvidenceClaim, EvidenceResult } from './types';

export type TestExecutor = (
  claim: EvidenceClaim
) => Promise<{ status: 'PASS' | 'FAIL' | 'ERROR'; detail: string }>;

export function repoRoot(): string {
  // src/packages/evidence/src/runner.ts → up 4 to repo root
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', '..', '..');
}

export async function runEvidence(
  claims: EvidenceClaim[],
  executor: TestExecutor
): Promise<EvidenceResult[]> {
  const out: EvidenceResult[] = [];
  for (const c of claims) {
    const base = { id: c.id, claim: c.claim, category: c.category };
    if (c.residual) {
      out.push({ ...base, status: 'RESIDUAL', detail: c.residual.reason });
      continue;
    }
    try {
      const r = await executor(c);
      out.push({ ...base, status: r.status, detail: r.detail });
    } catch (e) {
      out.push({ ...base, status: 'ERROR', detail: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

export const vitestExecutor: TestExecutor = async (claim) => {
  const root = repoRoot();
  const abs = join(root, claim.packageDir, claim.testFile);
  if (!existsSync(abs)) {
    return { status: 'FAIL', detail: `test file not found: ${claim.packageDir}/${claim.testFile}` };
  }
  const args = ['--filter', claim.pnpmFilter, 'exec', 'vitest', 'run', claim.testFile];
  if (claim.testNamePattern) args.push('-t', claim.testNamePattern);
  const cmd = ['pnpm', ...args].join(' ');
  const res = spawnSync(cmd, { cwd: root, encoding: 'utf8', shell: true });
  if (res.status === 0) return { status: 'PASS', detail: `${claim.pnpmFilter} ${claim.testFile}` };
  const tail = ((res.stdout || '') + (res.stderr || '')).split('\n').slice(-8).join('\n');
  return { status: 'FAIL', detail: `exit ${res.status}: ${tail}` };
};
