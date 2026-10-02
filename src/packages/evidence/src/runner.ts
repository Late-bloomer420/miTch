import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, extname, isAbsolute, join, resolve } from 'node:path';
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

const require = createRequire(import.meta.url);
const PNPM_VERSION = '9.15.9';

// npm_execpath is a hint, not an arbitrary executable override. Accept only the
// real JS bin declared by the pinned pnpm package (including symlinked installs).
function validatedPnpmJs(candidate: string): string {
  if (!isAbsolute(candidate)) throw new Error('pnpm entry point must be absolute');
  const entry = realpathSync(candidate);
  if (!['.js', '.cjs', '.mjs'].includes(extname(entry)) || !statSync(entry).isFile()) {
    throw new Error('pnpm entry point must be a JavaScript file');
  }
  const packageDir = resolve(dirname(entry), '..');
  const pkg = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
  if (
    pkg.name !== 'pnpm' ||
    pkg.version !== PNPM_VERSION ||
    typeof pkg.bin?.pnpm !== 'string' ||
    realpathSync(resolve(packageDir, pkg.bin.pnpm)) !== entry
  ) {
    throw new Error(`entry point is not the pnpm ${PNPM_VERSION} JavaScript bin`);
  }
  return entry;
}

function resolvePnpmJs(): string {
  if (process.env.npm_execpath) {
    try {
      return validatedPnpmJs(process.env.npm_execpath);
    } catch {
      // npm/Corepack wrappers, CMD shims and invalid hints use the pinned dependency.
    }
  }
  return validatedPnpmJs(resolve(dirname(require.resolve('pnpm')), 'bin/pnpm.cjs'));
}

export const vitestExecutor: TestExecutor = async (claim) => {
  const root = repoRoot();
  const abs = join(root, claim.packageDir, claim.testFile);
  if (!existsSync(abs)) {
    return { status: 'FAIL', detail: `test file not found: ${claim.packageDir}/${claim.testFile}` };
  }
  let pnpmJs: string;
  try {
    pnpmJs = resolvePnpmJs();
  } catch (e) {
    return {
      status: 'FAIL',
      detail: `failed to resolve pnpm: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  const args = ['--filter', claim.pnpmFilter, 'exec', 'vitest', 'run', claim.testFile];
  if (claim.testNamePattern) args.push('-t', claim.testNamePattern);
  const res = spawnSync(process.execPath, [pnpmJs, ...args], {
    cwd: root,
    encoding: 'utf8',
    shell: false,
  });
  if (res.error) {
    return {
      status: 'FAIL',
      detail: `failed to spawn pnpm: ${(res.error as NodeJS.ErrnoException).code || 'UNKNOWN'}: ${res.error.message}`,
    };
  }
  if (res.status === 0) return { status: 'PASS', detail: `${claim.pnpmFilter} ${claim.testFile}` };
  const tail = ((res.stdout || '') + (res.stderr || '')).split('\n').slice(-8).join('\n');
  return { status: 'FAIL', detail: `exit ${res.status}: ${tail}` };
};
