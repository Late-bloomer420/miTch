# SECURE-2 — Internal Evidence Pack + Runnable Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A private `@askmi/evidence` harness that proves each security claim maps to a passing test and emits a timestamped, hash-integrity evidence report, plus `SECURITY.md`, a security entry-point, and an honest residuals register.

**Architecture:** A new private workspace package `@askmi/evidence` with four focused units — `manifest` (claim→test data + schema validation), `runner` (executes mapped tests via an injectable executor, fail-closed), `report` (deterministic Markdown+JSON+SHA-256), `cli` (wires them, writes the report, exits non-zero on failure). Docs consolidate existing artifacts. TDD throughout; the runner uses dependency injection so its logic is unit-tested without shelling out.

**Tech Stack:** TypeScript ESM, Vitest (default config, no per-package config file), Node built-ins only (`node:crypto`, `node:fs`, `node:path`, `node:child_process`). No new third-party dependencies.

## Global Constraints

- **Fail-closed:** a missing/renamed test, a test error, a missing resolver, or a manifest schema violation must never count as "proven". Ambiguity → FAIL/ERROR/throw, never PASS. *(spec §5)*
- **`signaturesVerified`-style honesty:** `RESIDUAL` claims (GAP-1 TEE, GAP-4 external review, documented-residuals) are reported explicitly, never conflated with proven. *(spec §2, §5)*
- **No new third-party dependencies.** Node built-ins + Vitest only. Report signing is an **optional injected hook**, default off (hash-only). *(spec §2)*
- **Do not modify any existing security test** to fit the harness — map to tests as they are. *(spec §2)*
- **Package conventions (verbatim from the repo):** `"type": "module"`, `"private": true`, scope `@askmi/*`, `"build": "tsc -p tsconfig.build.json"`, `"test": "vitest run --passWithNoTests"`, tsconfigs `extends "../../../tsconfig.base.json"`, `exclude ["node_modules","dist","**/*.test.ts"]`, devDeps `rimraf ^5.0.0 typescript ^5.3.3 vitest ^4.1.8`.
- **Green bar for done:** `pnpm test` (47/47 turbo tasks — the new package adds one) + `pnpm lint` (0 errors; the 7 pre-existing wallet-pwa `no-explicit-any` warnings are unrelated and unchanged) + `pnpm guard:rebrand` all pass, and `pnpm evidence` exits 0 with every non-residual claim PASS.
- **TDD mandatory** for all harness code: RED → verify RED → GREEN → verify GREEN → REFACTOR. No production code without a failing test first. Docs (Task 6) are exempt but must cite real paths.

---

## File structure

```
src/packages/evidence/
  package.json               # private, @askmi/evidence
  tsconfig.json
  tsconfig.build.json
  src/
    types.ts                 # EvidenceClaim, EvidenceResult, EvidenceStatus, ReportOptions
    manifest.ts              # EVIDENCE_CLAIMS + validateManifest()
    runner.ts                # runEvidence(claims, executor) + vitestExecutor
    report.ts                # generateReport(results, opts)
    cli.ts                   # entry: run → report → write files → exit code
    index.ts                 # re-exports
    __tests__/
      manifest.test.ts
      runner.test.ts
      report.test.ts
      fixtures/
        passing.fixture.test.ts   # a trivially-passing test the runner integration test targets
docs/security/README.md      # pack entry-point + reproducible build/verify
docs/security/RESIDUALS.md   # honest open-items register
SECURITY.md                  # responsible-disclosure policy (repo root)
docs/qa/evidence-reports/    # generated report artifacts (baseline committed)
```

---

## Task 1: Scaffold the `@askmi/evidence` package

**Files:**
- Create: `src/packages/evidence/package.json`, `src/packages/evidence/tsconfig.json`, `src/packages/evidence/tsconfig.build.json`, `src/packages/evidence/src/index.ts`
- Create (test): `src/packages/evidence/src/__tests__/smoke.test.ts`

**Interfaces:**
- Produces: the package `@askmi/evidence` with working `build` + `test` scripts (adds one turbo `test` task, 46→47).

- [ ] **Step 1: Write the failing smoke test**

`src/packages/evidence/src/__tests__/smoke.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { PACKAGE_NAME } from '../index';

describe('@askmi/evidence package', () => {
  it('exposes its package name', () => {
    expect(PACKAGE_NAME).toBe('@askmi/evidence');
  });
});
```

- [ ] **Step 2: Run it — verify it fails**

Run: `pnpm --filter @askmi/evidence exec vitest run` (will fail: package not installed yet / `../index` missing).
Expected: FAIL (module or filter resolution error).

- [ ] **Step 3: Create the package files**

`src/packages/evidence/package.json`:
```json
{
  "name": "@askmi/evidence",
  "version": "0.1.0",
  "description": "Security evidence harness for AskMI — claim→test map, runner, report",
  "private": true,
  "type": "module",
  "main": "./dist/index.js",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "bin": { "askmi-evidence": "./dist/cli.js" },
  "files": ["dist", "src"],
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "dev": "tsc -p tsconfig.build.json --watch",
    "clean": "rimraf dist",
    "test": "vitest run --passWithNoTests",
    "typecheck": "tsc --noEmit",
    "evidence": "tsx src/cli.ts"
  },
  "keywords": ["AskMI", "security", "evidence", "audit"],
  "author": "Late-bloomer420 <jonas.f.meyer@googlemail.com>",
  "license": "MIT",
  "devDependencies": {
    "rimraf": "^5.0.0",
    "tsx": "^4.19.2",
    "typescript": "^5.3.3",
    "vitest": "^4.1.8"
  }
}
```
`src/packages/evidence/tsconfig.build.json`:
```json
{
  "extends": "../../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "target": "ES2020"
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```
`src/packages/evidence/tsconfig.json`:
```json
{
  "extends": "../../../tsconfig.base.json",
  "compilerOptions": { "outDir": "./dist", "rootDir": "./src" },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "**/*.test.ts"]
}
```
`src/packages/evidence/src/index.ts`:
```ts
export const PACKAGE_NAME = '@askmi/evidence';
```

- [ ] **Step 4: Install + run the smoke test**

Run: `pnpm install` (registers the new workspace package), then `pnpm --filter @askmi/evidence exec vitest run`.
Expected: PASS (1 test). Then `pnpm --filter @askmi/evidence build` → tsc exits 0.

- [ ] **Step 5: Commit**
```bash
git add src/packages/evidence pnpm-lock.yaml
git commit -m "feat(secure-2): scaffold @askmi/evidence harness package"
```

---

## Task 2: Types + manifest schema validation

**Files:**
- Create: `src/packages/evidence/src/types.ts`, `src/packages/evidence/src/manifest.ts`
- Create (test): `src/packages/evidence/src/__tests__/manifest.test.ts`

**Interfaces:**
- Produces:
  - `EvidenceStatus = 'PASS' | 'FAIL' | 'ERROR' | 'RESIDUAL'`
  - `EvidenceClaim { id: string; claim: string; category: EvidenceCategory; pnpmFilter: string; packageDir: string; testFile: string; testNamePattern?: string; residual?: { reason: string } }`
  - `EvidenceCategory = 'stride' | 'fail-closed' | 'gdpr' | 'eudi-cir' | 'unlinkability'`
  - `EvidenceResult { id: string; claim: string; category: EvidenceCategory; status: EvidenceStatus; detail: string }`
  - `validateManifest(claims: EvidenceClaim[]): void` — throws `Error` on any schema violation.
  - `EVIDENCE_CLAIMS: EvidenceClaim[]` (seeded minimally here; expanded in Task 5).

- [ ] **Step 1: Write the failing tests**

`src/packages/evidence/src/__tests__/manifest.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { validateManifest } from '../manifest';
import type { EvidenceClaim } from '../types';

const valid: EvidenceClaim = {
  id: 'T-1', claim: 'x', category: 'stride',
  pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine',
  testFile: 'src/__tests__/input-validation.test.ts',
};
const residual: EvidenceClaim = {
  id: 'GAP-1', claim: 'RAM wipe', category: 'fail-closed',
  pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'browser limit' },
};

describe('validateManifest', () => {
  it('accepts a valid non-residual claim', () => {
    expect(() => validateManifest([valid])).not.toThrow();
  });
  it('accepts a residual claim with empty test fields', () => {
    expect(() => validateManifest([residual])).not.toThrow();
  });
  it('throws when a non-residual claim is missing testFile', () => {
    expect(() => validateManifest([{ ...valid, testFile: '' }])).toThrow(/testFile/);
  });
  it('throws on an unknown category', () => {
    expect(() => validateManifest([{ ...valid, category: 'bogus' as never }])).toThrow(/category/);
  });
  it('throws on duplicate ids', () => {
    expect(() => validateManifest([valid, valid])).toThrow(/duplicate/i);
  });
});
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/manifest.test.ts`
Expected: FAIL (`validateManifest` not defined).

- [ ] **Step 3: Implement types + manifest**

`src/packages/evidence/src/types.ts`:
```ts
export type EvidenceStatus = 'PASS' | 'FAIL' | 'ERROR' | 'RESIDUAL';
export type EvidenceCategory = 'stride' | 'fail-closed' | 'gdpr' | 'eudi-cir' | 'unlinkability';

export interface EvidenceClaim {
  id: string;
  claim: string;
  category: EvidenceCategory;
  pnpmFilter: string;   // e.g. '@askmi/policy-engine' (empty for residual)
  packageDir: string;   // repo-relative, e.g. 'src/packages/policy-engine' (empty for residual)
  testFile: string;     // package-relative, e.g. 'src/__tests__/x.test.ts' (empty for residual)
  testNamePattern?: string;
  residual?: { reason: string };
}

export interface EvidenceResult {
  id: string;
  claim: string;
  category: EvidenceCategory;
  status: EvidenceStatus;
  detail: string;
}

export interface ReportOptions {
  timestamp: Date;
  toolVersions?: Record<string, string>;
  sign?: (bytes: Uint8Array) => Promise<string>;
}
```
`src/packages/evidence/src/manifest.ts`:
```ts
import type { EvidenceCategory, EvidenceClaim } from './types';

const CATEGORIES: EvidenceCategory[] = ['stride', 'fail-closed', 'gdpr', 'eudi-cir', 'unlinkability'];

export function validateManifest(claims: EvidenceClaim[]): void {
  const seen = new Set<string>();
  for (const c of claims) {
    if (!c.id) throw new Error('manifest: claim missing id');
    if (seen.has(c.id)) throw new Error(`manifest: duplicate id ${c.id}`);
    seen.add(c.id);
    if (!c.claim) throw new Error(`manifest: ${c.id} missing claim text`);
    if (!CATEGORIES.includes(c.category)) throw new Error(`manifest: ${c.id} unknown category ${c.category}`);
    if (c.residual) continue; // residual claims intentionally have empty test fields
    if (!c.pnpmFilter) throw new Error(`manifest: ${c.id} missing pnpmFilter`);
    if (!c.packageDir) throw new Error(`manifest: ${c.id} missing packageDir`);
    if (!c.testFile) throw new Error(`manifest: ${c.id} missing testFile`);
  }
}

// Seeded in Task 5 with the real SECURE-1 + STRIDE + residual claims.
export const EVIDENCE_CLAIMS: EvidenceClaim[] = [];
```

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/manifest.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**
```bash
git add src/packages/evidence/src/types.ts src/packages/evidence/src/manifest.ts src/packages/evidence/src/__tests__/manifest.test.ts
git commit -m "feat(secure-2): evidence claim types + fail-closed manifest validation"
```

---

## Task 3: Runner (injectable executor, fail-closed)

**Files:**
- Create: `src/packages/evidence/src/runner.ts`
- Create (test): `src/packages/evidence/src/__tests__/runner.test.ts`, `src/packages/evidence/src/__tests__/fixtures/passing.fixture.test.ts`

**Interfaces:**
- Consumes: `EvidenceClaim`, `EvidenceResult` (Task 2).
- Produces:
  - `TestExecutor = (claim: EvidenceClaim) => Promise<{ status: 'PASS' | 'FAIL' | 'ERROR'; detail: string }>`
  - `runEvidence(claims: EvidenceClaim[], executor: TestExecutor): Promise<EvidenceResult[]>` — residual claims → `RESIDUAL` without calling executor; non-residual → executor; never throws (executor throw → `ERROR`).
  - `vitestExecutor: TestExecutor` — resolves `<repoRoot>/<packageDir>/<testFile>`; missing file → `FAIL 'test file not found'`; else spawns vitest and maps exit code (0→PASS, else→FAIL).
  - `repoRoot(): string` — resolves the monorepo root from this file location.

- [ ] **Step 1: Write the failing tests**

`src/packages/evidence/src/__tests__/fixtures/passing.fixture.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
describe('fixture', () => { it('passes', () => { expect(1).toBe(1); }); });
```
`src/packages/evidence/src/__tests__/runner.test.ts`:
```ts
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
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/runner.test.ts`
Expected: FAIL (`runner` module missing).

- [ ] **Step 3: Implement the runner**

`src/packages/evidence/src/runner.ts`:
```ts
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
  const res = spawnSync('pnpm', args, { cwd: root, encoding: 'utf8', shell: true });
  if (res.status === 0) return { status: 'PASS', detail: `${claim.pnpmFilter} ${claim.testFile}` };
  const tail = (res.stdout || '').split('\n').slice(-8).join('\n');
  return { status: 'FAIL', detail: `exit ${res.status}: ${tail}` };
};
```

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/runner.test.ts`
Expected: PASS (5 tests; the real-spawn PASS test may take a few seconds).

- [ ] **Step 5: Commit**
```bash
git add src/packages/evidence/src/runner.ts src/packages/evidence/src/__tests__/runner.test.ts src/packages/evidence/src/__tests__/fixtures
git commit -m "feat(secure-2): fail-closed evidence runner with injectable executor"
```

---

## Task 4: Report generator (deterministic, hashed, optional signer)

**Files:**
- Create: `src/packages/evidence/src/report.ts`
- Create (test): `src/packages/evidence/src/__tests__/report.test.ts`

**Interfaces:**
- Consumes: `EvidenceResult`, `ReportOptions` (Task 2).
- Produces: `generateReport(results: EvidenceResult[], opts: ReportOptions): Promise<{ markdown: string; json: string; hash: string; signature?: string }>`. `hash` = SHA-256 hex over the canonical JSON of `{ generatedAt, toolVersions, results }`. Deterministic for fixed inputs. `signature` present iff `opts.sign` provided.

- [ ] **Step 1: Write the failing tests**

`src/packages/evidence/src/__tests__/report.test.ts`:
```ts
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
```

- [ ] **Step 2: Run — verify it fails**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/report.test.ts`
Expected: FAIL (`report` module missing).

- [ ] **Step 3: Implement the report generator**

`src/packages/evidence/src/report.ts`:
```ts
import { createHash } from 'node:crypto';
import type { EvidenceResult, ReportOptions } from './types';

function count(results: EvidenceResult[], status: string): number {
  return results.filter((r) => r.status === status).length;
}

export async function generateReport(
  results: EvidenceResult[],
  opts: ReportOptions
): Promise<{ markdown: string; json: string; hash: string; signature?: string }> {
  const payload = {
    generatedAt: opts.timestamp.toISOString(),
    toolVersions: opts.toolVersions ?? {},
    results,
  };
  const json = JSON.stringify(payload, null, 2);
  const hash = createHash('sha256').update(json).digest('hex');

  const proven = count(results, 'PASS');
  const failed = count(results, 'FAIL');
  const errored = count(results, 'ERROR');
  const residual = count(results, 'RESIDUAL');

  const rows = results
    .map((r) => `| ${r.id} | ${r.category} | ${r.status} | ${r.claim.replace(/\|/g, '\\|')} |`)
    .join('\n');

  const markdown = `# AskMI Security Evidence Report

**Generated:** ${payload.generatedAt}
**Integrity (SHA-256):** \`${hash}\`

## Totals
- Proven: ${proven}
- Failed: ${failed}
- Error: ${errored}
- Residual: ${residual}

> Residual = intentionally NOT proven by a test (documented open item), never counted as proven.

## Claims
| ID | Category | Status | Claim |
|----|----------|--------|-------|
${rows}
`;

  const signature = opts.sign ? await opts.sign(new TextEncoder().encode(json)) : undefined;
  return { markdown, json, hash, signature };
}
```

- [ ] **Step 4: Run — verify pass**

Run: `pnpm --filter @askmi/evidence exec vitest run src/__tests__/report.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**
```bash
git add src/packages/evidence/src/report.ts src/packages/evidence/src/__tests__/report.test.ts
git commit -m "feat(secure-2): deterministic hashed evidence report generator"
```

---

## Task 5: CLI + real manifest + baseline report

**Files:**
- Create: `src/packages/evidence/src/cli.ts`
- Modify: `src/packages/evidence/src/manifest.ts` (seed `EVIDENCE_CLAIMS`), `src/packages/evidence/src/index.ts` (re-exports)
- Modify: `package.json` (root — add `"evidence"` script)
- Create: `docs/qa/evidence-reports/` (baseline report written by the CLI)

**Interfaces:**
- Consumes: `EVIDENCE_CLAIMS`, `validateManifest`, `runEvidence`, `vitestExecutor`, `generateReport` (Tasks 2–4).
- Produces: `pnpm evidence` → writes `docs/qa/evidence-reports/EVIDENCE_<UTC-ISO>.{md,json}`, prints a summary, exits non-zero if any `FAIL`/`ERROR`.

- [ ] **Step 1: Seed the real manifest**

Replace `EVIDENCE_CLAIMS` in `manifest.ts` with the real claims (every `testFile` below is a real path verified in SECURE-1 / the STRIDE table; a wrong path makes `pnpm evidence` FAIL by design):
```ts
export const EVIDENCE_CLAIMS: EvidenceClaim[] = [
  // — SECURE-1 fail-closed fixes —
  { id: 'SECURE1-F03', claim: 'WebAuthn verifyPresence stub fails closed (no false presence proof)', category: 'fail-closed',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/webauthn-fail-closed.test.ts' },
  { id: 'SECURE1-F04', claim: 'Geo-scope denies on undetermined country / unknown scope (fail-closed)', category: 'fail-closed',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/ehds-geo-scope.test.ts' },
  { id: 'SECURE1-F16-18', claim: 'Passkey/identity-key metadata save failures fail closed (rethrow)', category: 'fail-closed',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/webauthn-save-failclosed.test.ts' },
  { id: 'SECURE1-F14', claim: 'OID4VP verifier cryptographically verifies SD-JWT VC + KB-JWT (fail-closed)', category: 'fail-closed',
    pnpmFilter: '@askmi/oid4vp-verifier', packageDir: 'src/packages/oid4vp-verifier', testFile: 'src/__tests__/response-verifier.crypto.test.ts' },
  { id: 'SECURE1-GAP3', claim: 'Anti-oracle DENY-path timing variance bounded (no secret-dependent branch)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/anti-oracle.test.ts' },
  // — Core STRIDE controls (ADR-009, existing tests) —
  { id: 'STRIDE-T1', claim: 'Claim-name injection rejected (whitelist input validation)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/input-validation.test.ts' },
  { id: 'STRIDE-T2', claim: 'Unsafe capability downgrade denied', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/capability-negotiation.test.ts' },
  { id: 'STRIDE-T5', claim: 'Audit-chain tampering detected (hash chain + signatures)', category: 'stride',
    pnpmFilter: '@askmi/audit-log', packageDir: 'src/packages/audit-log', testFile: 'test/adversarial_audit.test.ts' },
  { id: 'STRIDE-I2', claim: 'Cross-verifier correlation prevented (pairwise-ephemeral DIDs)', category: 'unlinkability',
    pnpmFilter: '@askmi/shared-crypto', packageDir: 'src/packages/shared-crypto', testFile: 'test/unlinkability.test.ts' },
  { id: 'STRIDE-I1', claim: 'Anti-oracle: verifier cannot distinguish deny reasons (≤4 buckets)', category: 'stride',
    pnpmFilter: '@askmi/policy-engine', packageDir: 'src/packages/policy-engine', testFile: 'src/__tests__/anti-oracle.test.ts' },
  // — Residuals (intentionally NOT proven by a test) —
  { id: 'GAP-1', claim: 'Physical RAM wipe unattainable in browser JS/V8 (TEE deferred)', category: 'fail-closed',
    pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'Browser runtime limit; TEE integration deferred (ADR-010).' } },
  { id: 'GAP-4', claim: 'External security review not yet performed', category: 'fail-closed',
    pnpmFilter: '', packageDir: '', testFile: '', residual: { reason: 'Human precondition; this pack prepares for it (SECURE-2), not the review itself.' } },
];
```
> If the implementer finds any of these test paths has moved, correct the path — do NOT delete the claim and do NOT point it at a different test. A wrong path failing the run is the feature working.

- [ ] **Step 2: Update `index.ts` re-exports**

`src/packages/evidence/src/index.ts`:
```ts
export const PACKAGE_NAME = '@askmi/evidence';
export * from './types';
export { EVIDENCE_CLAIMS, validateManifest } from './manifest';
export { runEvidence, vitestExecutor, repoRoot, type TestExecutor } from './runner';
export { generateReport } from './report';
```

- [ ] **Step 3: Write the CLI**

`src/packages/evidence/src/cli.ts`:
```ts
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { EVIDENCE_CLAIMS, validateManifest } from './manifest';
import { runEvidence, vitestExecutor, repoRoot } from './runner';
import { generateReport } from './report';

async function main(): Promise<void> {
  validateManifest(EVIDENCE_CLAIMS);
  const results = await runEvidence(EVIDENCE_CLAIMS, vitestExecutor);
  const now = new Date();
  const { markdown, json, hash } = await generateReport(results, {
    timestamp: now,
    toolVersions: { node: process.version },
  });

  const dir = join(repoRoot(), 'docs', 'qa', 'evidence-reports');
  mkdirSync(dir, { recursive: true });
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  writeFileSync(join(dir, `EVIDENCE_${stamp}.md`), markdown);
  writeFileSync(join(dir, `EVIDENCE_${stamp}.json`), json);

  const failed = results.filter((r) => r.status === 'FAIL' || r.status === 'ERROR');
  const proven = results.filter((r) => r.status === 'PASS').length;
  const residual = results.filter((r) => r.status === 'RESIDUAL').length;
  console.log(`Evidence: ${proven} proven, ${residual} residual, ${failed.length} failed. hash=${hash}`);
  for (const f of failed) console.error(`  FAIL ${f.id}: ${f.detail}`);
  process.exit(failed.length > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('evidence run crashed:', e);
  process.exit(1);
});
```

- [ ] **Step 4: Add the root `evidence` script**

In the root `package.json` `scripts`, add:
```json
"evidence": "pnpm --filter @askmi/evidence exec tsx src/cli.ts",
```

- [ ] **Step 5: Run the harness end-to-end**

Run: `pnpm evidence`
Expected: console `Evidence: 10 proven, 2 residual, 0 failed. hash=…`, exit 0, and a report pair written under `docs/qa/evidence-reports/`. If any claim FAILs with "test file not found", fix that claim's path (Step 1 note) and re-run until 0 failed.

- [ ] **Step 6: Commit (incl. the baseline report)**
```bash
git add src/packages/evidence/src/manifest.ts src/packages/evidence/src/index.ts src/packages/evidence/src/cli.ts package.json docs/qa/evidence-reports
git commit -m "feat(secure-2): evidence CLI + real claim manifest + baseline report"
```

---

## Task 6: Docs — SECURITY.md, entry-point, residuals register

**Files:**
- Create: `SECURITY.md` (repo root), `docs/security/README.md`, `docs/security/RESIDUALS.md`

**Interfaces:** none (documentation). Every path/link cited must resolve.

- [ ] **Step 1: Write `SECURITY.md`**

Create `SECURITY.md` at the repo root with: a **Reporting a Vulnerability** section (report channel = the maintainer email `jonas.f.meyer@googlemail.com`; ask reporters not to open public issues for security bugs; state a good-faith safe-harbor intent and a target acknowledgement window, e.g. 7 days), a **Scope** section (the wallet/policy/crypto surface; explicitly note this is a research/pilot project, not a production service), and a **Supported Versions** note pointing at `master`.

- [ ] **Step 2: Write `docs/security/README.md` (pack entry-point)**

Create the entry-point that links, with working relative paths:
- Security Target — `../compliance/SECURITY_TARGET_CC_READY.md`
- Threat model — `../03-architecture/mvp/ADR-009_Threat_Model.md`
- EUDI-CIR matrix — `../compliance/EUDI_CIR_MATRIX.md`
- P0 evidence — `../ops/EVIDENCE_PACK_P0.md`
- Runbooks — `../ops/RUNBOOKS_V1.md`
- Claim→test harness — `../../src/packages/evidence/` + the latest report under `../qa/evidence-reports/`
- Residuals — `./RESIDUALS.md`
- SECURITY.md — `../../SECURITY.md`

Include a **Reproduce the evidence** section with the exact commands and expected output:
```
pnpm install
pnpm build      # 29/29
pnpm test       # 47/47 turbo tasks
pnpm evidence   # N proven, 2 residual, 0 failed → report in docs/qa/evidence-reports/
```

- [ ] **Step 3: Write `docs/security/RESIDUALS.md`**

Create the honest open-items register with a row per residual: **GAP-1** (browser RAM / TEE deferred — ADR-010), **GAP-4** (external security review — human precondition), and the SECURE-1 `documented-residual` findings from `docs/qa/SECURE_1_FINDINGS_REGISTER.md` (F-05/F-06 L2-anchor stubs, F-14-adjacent notes, F-15 break-glass, F-19/F-20/F-22). Each row: what it is, why it is not closed, and what would close it. State plainly that the pack does not claim these are covered.

- [ ] **Step 4: Verify links resolve**

Run: `node -e "const fs=require('fs');const p=require('path');const root='docs/security';for(const f of ['README.md','RESIDUALS.md']){const t=fs.readFileSync(p.join(root,f),'utf8');for(const m of t.matchAll(/\]\(([^)]+\.md)\)/g)){const target=p.resolve(root,m[1]);if(!fs.existsSync(target))console.error('BROKEN',f,'->',m[1]);}}console.log('link check done');"`
Expected: `link check done` with no `BROKEN` lines.

- [ ] **Step 5: Commit**
```bash
git add SECURITY.md docs/security/README.md docs/security/RESIDUALS.md
git commit -m "docs(secure-2): SECURITY.md + security evidence entry-point + residuals register"
```

---

## Task 7: Final verification + PR

- [ ] **Step 1: Full green bar**

Run: `pnpm test` then `pnpm lint` then `pnpm guard:rebrand` then `pnpm evidence`
Expected: `pnpm test` 47/47 turbo tasks (the new `@askmi/evidence` test task included); lint 0 errors (7 pre-existing wallet-pwa warnings unchanged); guard passed; `pnpm evidence` exit 0, 0 failed.

- [ ] **Step 2: Push + PR**
```bash
git push -u origin feat/secure-2-evidence-pack
gh pr create --title "SECURE-2: internal evidence pack + runnable harness" --body "Adds a private @askmi/evidence harness (manifest→runner→report, fail-closed) that proves each security claim maps to a passing test and emits a timestamped SHA-256-hashed evidence report, plus SECURITY.md, a docs/security entry-point, and an honest residuals register. Preps GAP-4 (external review); GAP-1/GAP-4 remain openly unresolved. Verified: pnpm test 47/47, lint 0 errors, guard green, pnpm evidence 0 failed."
```

---

## Self-Review (completed by author)

**1. Spec coverage:**
- §3.1a Manifest → Task 2 (types + schema) + Task 5 (real seed). ✓
- §3.1b Runner (fail-closed, missing-test→FAIL) → Task 3. ✓
- §3.1c Report (deterministic, SHA-256, optional signer) → Task 4. ✓
- §3.1d CLI (`pnpm evidence`, writes report, exit code) → Task 5. ✓
- §3.2 Docs (entry-point, SECURITY.md, RESIDUALS) + reproducible steps → Task 6. ✓
- §5 fail-closed error handling → Global Constraints + Tasks 2/3. ✓
- §6 TDD tests → every harness task. ✓
- §7 Definition of Done (47/47, baseline report, links resolve) → Task 7 + Task 5. ✓
- Non-goal "no new deps": only `tsx` (dev, already used across the repo) + Node built-ins. ✓ Signing is an injected hook, default off. ✓

**2. Placeholder scan:** No TBD/TODO. The `EVIDENCE_CLAIMS = []` in Task 2 is explicitly seeded in Task 5 (not a placeholder — a staged build with the real data provided). All code steps show complete code.

**3. Type consistency:** `EvidenceClaim`/`EvidenceResult`/`EvidenceStatus`/`ReportOptions`/`TestExecutor` names and fields (`pnpmFilter`, `packageDir`, `testFile`, `testNamePattern`, `residual.reason`) are identical across Tasks 2–5. `generateReport`/`runEvidence`/`vitestExecutor`/`validateManifest`/`repoRoot` signatures match their definitions and call sites. `RESIDUAL` status handled consistently in runner, report, and CLI.
