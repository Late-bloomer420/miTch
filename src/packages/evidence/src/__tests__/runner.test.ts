import { afterEach, describe, it, expect, vi } from 'vitest';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runEvidence, vitestExecutor, repoRoot, type TestExecutor } from '../runner';
import type { EvidenceClaim } from '../types';

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  return { ...actual, spawnSync: vi.fn(actual.spawnSync) };
});
const nativeSpawnSync = (
  await vi.importActual<typeof import('node:child_process')>('node:child_process')
).spawnSync;
const spawn = vi.mocked(spawnSync);
const packageDir = 'src/packages/evidence';
const tempDir = join(
  repoRoot(),
  packageDir,
  'src/__tests__/fixtures',
  `runner temp ${process.pid}`
);
const originalExecpath = process.env.npm_execpath;

const claim = (over: Partial<EvidenceClaim> = {}): EvidenceClaim => ({
  id: 'C1',
  claim: 'c',
  category: 'stride',
  pnpmFilter: '@askmi/evidence',
  packageDir,
  testFile: 'src/__tests__/fixtures/passing.fixture.test.ts',
  ...over,
});

function tempFile(name: string, content: string): string {
  mkdirSync(tempDir, { recursive: true });
  const path = join(tempDir, name);
  writeFileSync(path, content);
  return path;
}

function restoreExecpath(): void {
  if (originalExecpath === undefined) delete process.env.npm_execpath;
  else process.env.npm_execpath = originalExecpath;
}

afterEach(() => {
  spawn.mockReset();
  spawn.mockImplementation(nativeSpawnSync);
  restoreExecpath();
  delete process.env.EVIDENCE_FIXTURE_MARKER;
  delete process.env.EVIDENCE_ARGV_CAPTURE;
  rmSync(tempDir, { recursive: true, force: true });
});

describe('runEvidence (logic, injected executor)', () => {
  it('maps a residual claim to RESIDUAL without calling the executor', async () => {
    const exec = vi.fn();
    const res = await runEvidence(
      [claim({ id: 'R', residual: { reason: 'deferred' } })],
      exec as unknown as TestExecutor
    );
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
    const exec: TestExecutor = async () => {
      throw new Error('boom');
    };
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
    expect(spawn).not.toHaveBeenCalled();
  });

  it('executes a matching passing fixture with spaces in its file and pattern', async () => {
    mkdirSync(tempDir, { recursive: true });
    const marker = join(tempDir, 'fixture executed');
    process.env.EVIDENCE_FIXTURE_MARKER = marker;
    const r = await vitestExecutor(
      claim({
        testFile: 'src/__tests__/fixtures/passing with spaces.fixture.test.ts',
        testNamePattern: '^passes with spaces$',
      })
    );
    expect(r.status).toBe('PASS');
    expect(readFileSync(marker, 'utf8')).toBe('executed');
  }, 60_000);

  it('delivers metacharacters, quotes and spaces unchanged to a real Node child', async () => {
    const probe = join(repoRoot(), packageDir, 'src/__tests__/fixtures/argv-probe.cjs');
    mkdirSync(tempDir, { recursive: true });
    const capture = join(tempDir, 'argv.json');
    process.env.EVIDENCE_ARGV_CAPTURE = capture;
    const pattern = 'literal ; & $(echo injected) "double quotes" \'single quotes\' spaces';
    spawn.mockImplementationOnce((command, args, options) => {
      // Replace only the pnpm CLI with a probe; preserve the production command,
      // argument array and options, and observe argv across the OS process boundary.
      return nativeSpawnSync(command, [probe, ...args!.slice(1)], options!);
    });
    const r = await vitestExecutor(claim({ testNamePattern: pattern }));
    expect(r.status).toBe('PASS');
    expect(spawn).toHaveBeenCalledWith(
      process.execPath,
      [
        expect.stringMatching(/pnpm\.cjs$/),
        '--filter',
        '@askmi/evidence',
        'exec',
        'vitest',
        'run',
        claim().testFile,
        '-t',
        pattern,
      ],
      { cwd: repoRoot(), encoding: 'utf8', shell: false }
    );
    expect(JSON.parse(readFileSync(capture, 'utf8'))).toEqual([
      '--filter',
      '@askmi/evidence',
      'exec',
      'vitest',
      'run',
      claim().testFile,
      '-t',
      pattern,
    ]);
  });

  it('does not execute a marker-file payload through the real pnpm launch', async () => {
    mkdirSync(tempDir, { recursive: true });
    // Relative, space-free marker makes the old shell-joined launch exploitable
    // on either platform. This test and the argv test must reject that regression.
    const markerName = `evidence-injection-${process.pid}`;
    const marker = join(repoRoot(), markerName);
    const separator = process.platform === 'win32' ? '&' : ';';
    const payload = `fixture ${separator} node -e "require('node:fs').writeFileSync('${markerName}', 'injected')"`;
    try {
      const r = await vitestExecutor(claim({ testNamePattern: payload }));
      // A nonmatching pattern may skip the fixture; this is a security assertion,
      // never evidence that a claim's test ran. The matching test above proves that.
      expect(r.status).toBe('PASS');
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(marker, { force: true });
    }
  }, 60_000);

  it('reports a real failed spawn with ENOENT instead of exit null', async () => {
    spawn.mockImplementationOnce((_command, args, options) =>
      nativeSpawnSync(join(tempDir, 'nonexistent-node-executable'), args!, options!)
    );
    const r = await vitestExecutor(claim());
    expect(r.status).toBe('FAIL');
    expect(r.detail).toMatch(/failed to spawn pnpm: ENOENT/);
    expect(r.detail).not.toContain('exit null');
  });

  it('cannot report PASS for a nonzero child exit', async () => {
    tempFile(
      'failing.fixture.test.ts',
      `import { it, expect } from 'vitest';\nit('fails', () => expect(1).toBe(2));\n`
    );
    const r = await vitestExecutor(
      claim({
        testFile: `src/__tests__/fixtures/runner temp ${process.pid}/failing.fixture.test.ts`,
      })
    );
    expect(r.status).toBe('FAIL');
    expect(r.detail).toMatch(/exit 1:/);
  }, 60_000);

  it('falls back to the pinned pnpm dependency when npm_execpath is absent', async () => {
    delete process.env.npm_execpath;
    const r = await vitestExecutor(claim());
    expect(r.status).toBe('PASS');
    expect(spawn.mock.calls[0][0]).toBe(process.execPath);
    expect(spawn.mock.calls[0][1]![0]).toMatch(/pnpm\.cjs$/);
  }, 60_000);

  it.each(['untrusted.cjs', 'pnpm.cmd'])(
    'does not execute an invalid npm_execpath (%s)',
    async (name) => {
      const hint = tempFile(name, 'throw new Error("untrusted hint executed");');
      process.env.npm_execpath = hint;
      const r = await vitestExecutor(claim());
      expect(r.status).toBe('PASS');
      expect(spawn.mock.calls[0][1]![0]).not.toBe(hint);
    },
    60_000
  );

  it('prefers a validated pnpm npm_execpath', async () => {
    // Use the same installed package as a symlinked/global pnpm installation.
    const { createRequire } = await import('node:module');
    const { realpathSync } = await import('node:fs');
    const entry = join(dirname(createRequire(import.meta.url).resolve('pnpm')), 'bin/pnpm.cjs');
    process.env.npm_execpath = entry;
    const r = await vitestExecutor(claim());
    expect(r.status).toBe('PASS');
    expect(spawn.mock.calls[0][1]![0]).toBe(realpathSync(entry));
  }, 60_000);
});
