import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./check-security-audit.mjs', import.meta.url));
const report = (overrides = {}) => ({ metadata: { vulnerabilities: {
  info: 0, low: 0, moderate: 0, high: 0, critical: 0, ...overrides,
} } });

function run(body, auditStatus) {
  const dir = mkdtempSync(path.join(tmpdir(), 'askmi-audit-'));
  try {
    const file = path.join(dir, 'audit.json');
    writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body));
    return spawnSync(process.execPath, [script, file, String(auditStatus)], { encoding: 'utf8' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

for (const [name, body, status, expected] of [
  ['clean audit', report(), 0, 0],
  ['moderate and low stay visible but pass', report({ moderate: 17, low: 2 }), 1, 0],
  ['one high blocks', report({ high: 1 }), 1, 1],
  ['one critical blocks', report({ critical: 1, high: 51 }), 1, 1],
  ['registry error blocks', { error: { code: 'ERR_PNPM_AUDIT_BAD_RESPONSE' } }, 1, 1],
  ['error with fabricated clean metadata blocks', { ...report(), error: {} }, 1, 1],
  ['malformed JSON blocks', 'not JSON', 1, 1],
  ['missing metadata blocks', {}, 0, 1],
  ['missing critical count blocks', report({ critical: undefined }), 0, 1],
  ['string count blocks', report({ critical: '0' }), 0, 1],
  ['negative count blocks', report({ high: -1 }), 0, 1],
  ['fractional count blocks', report({ high: 0.5 }), 0, 1],
  ['failed command with clean counts blocks', report(), 1, 1],
  ['unexpected command exit blocks', report({ high: 1 }), 2, 1],
  ['successful command with advisories contradicts report', report({ high: 1 }), 0, 1],
]) {
  test(name, () => {
    const res = run(body, status);
    assert.equal(res.status, expected, res.stdout + res.stderr);
    if (expected === 0) assert.match(res.stdout, /critical=0/);
    else assert.match(res.stderr, /Security audit denied/);
  });
}

test('missing report file blocks', () => {
  const res = spawnSync(process.execPath, [script, '/nonexistent/askmi-audit.json', '0'], { encoding: 'utf8' });
  assert.equal(res.status, 1);
});

for (const file of ['ci.yml', 'ci-security.yml']) {
  test(`${file} runs the regression and enforced gate without swallowing failure`, () => {
    const workflow = readFileSync(new URL(`../.github/workflows/${file}`, import.meta.url), 'utf8');
    assert.match(workflow, /node --test scripts\/check-security-audit.test.mjs/);
    assert.match(workflow, /node scripts\/check-security-audit.mjs/);
    assert.match(workflow, /pnpm audit --prod --json/);
    assert.doesNotMatch(workflow, /continue-on-error|except: pass|No critical vulnerabilities found/);
  });
}

// --- Expiring, dev-only exception for a single HIGH advisory -----------------

const GHSA = 'GHSA-fc5q-39xc-vjpf';
const day = 24 * 60 * 60 * 1000;
const isoDay = (offsetDays) => new Date(Date.now() + offsetDays * day).toISOString().slice(0, 10);
const advisory = (id, module, severity, findings) => ({
  github_advisory_id: id,
  module_name: module,
  severity,
  findings: Array.from({ length: findings }, (_, i) => ({ version: `1.0.${i}`, paths: [`x>${module}`] })),
});
const withAdvisories = (list) => {
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const a of list) counts[a.severity] += a.findings.length;
  return {
    metadata: { vulnerabilities: counts },
    advisories: Object.fromEntries(list.map((a, i) => [String(i + 1), a])),
  };
};
const exception = (overrides = {}) => ({
  id: GHSA,
  module: 'picomatch',
  expires: isoDay(30),
  reason: 'No patched release; dev tooling only, repository-controlled patterns.',
  tracking: '#257',
  ...overrides,
});

function runGate({ full, fullStatus = 1, prod, prodStatus = 0, exceptions }) {
  const dir = mkdtempSync(path.join(tmpdir(), 'askmi-audit-'));
  try {
    const write = (name, body) => {
      const file = path.join(dir, name);
      writeFileSync(file, typeof body === 'string' ? body : JSON.stringify(body));
      return file;
    };
    const args = [script, write('full.json', full), String(fullStatus)];
    args.push(prod === undefined ? '/nonexistent/prod.json' : write('prod.json', prod), String(prodStatus));
    args.push(write('exceptions.json', exceptions));
    return spawnSync(process.execPath, args, { encoding: 'utf8' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const picomatchHigh = advisory(GHSA, 'picomatch', 'high', 3);

test('active exception excuses a dev-only high advisory', () => {
  const res = runGate({ full: withAdvisories([picomatchHigh]), prod: report(), exceptions: [exception()] });
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Excepted: GHSA-fc5q-39xc-vjpf/);
  assert.match(res.stdout, /high=0 \(raw high=3\)/);
});

test('exception does not apply when the advisory reaches production dependencies', () => {
  const res = runGate({
    full: withAdvisories([picomatchHigh]),
    prod: withAdvisories([advisory(GHSA, 'picomatch', 'high', 1)]),
    prodStatus: 1,
    exceptions: [exception()],
  });
  assert.equal(res.status, 1);
  assert.match(res.stderr, /Security audit denied/);
});

for (const [name, prod] of [
  [
    'an unrelated critical advisory',
    withAdvisories([advisory('GHSA-2222-3333-4444', 'undici', 'critical', 1)]),
  ],
  ['a high count without an advisory list', report({ high: 1 })],
  ['a high advisory without an id', withAdvisories([advisory(undefined, 'undici', 'high', 1)])],
]) {
  test(`exception does not apply when the production report shows ${name}`, () => {
    const res = runGate({
      full: withAdvisories([picomatchHigh]),
      prod,
      prodStatus: 1,
      exceptions: [exception()],
    });
    assert.equal(res.status, 1, res.stdout + res.stderr);
    assert.match(res.stderr, /Security audit denied/);
  });
}

test('a moderate production finding does not cancel the exception', () => {
  const res = runGate({
    full: withAdvisories([picomatchHigh]),
    prod: report({ moderate: 1 }),
    prodStatus: 1,
    exceptions: [exception()],
  });
  assert.equal(res.status, 0, res.stdout + res.stderr);
});

test('exception without a production-only report denies', () => {
  const res = runGate({ full: withAdvisories([picomatchHigh]), exceptions: [exception()] });
  assert.equal(res.status, 1);
});

test('expired exception no longer excuses', () => {
  const res = runGate({
    full: withAdvisories([picomatchHigh]),
    prod: report(),
    exceptions: [exception({ expires: isoDay(-1) })],
  });
  assert.equal(res.status, 1);
  assert.match(res.stdout, /Expired exception ignored/);
});

test('exception never excuses a critical advisory', () => {
  const res = runGate({
    full: withAdvisories([advisory(GHSA, 'picomatch', 'critical', 1)]),
    prod: report(),
    exceptions: [exception()],
  });
  assert.equal(res.status, 1);
});

test('exception for one advisory does not excuse another high advisory', () => {
  const res = runGate({
    full: withAdvisories([picomatchHigh, advisory('GHSA-2222-3333-4444', 'undici', 'high', 1)]),
    prod: report(),
    exceptions: [exception()],
  });
  assert.equal(res.status, 1);
  assert.match(res.stdout, /high=1 \(raw high=4\)/);
});

test('exception must match the module as well as the id', () => {
  const res = runGate({
    full: withAdvisories([advisory(GHSA, 'micromatch', 'high', 1)]),
    prod: report(),
    exceptions: [exception()],
  });
  assert.equal(res.status, 1);
});

for (const [name, entry] of [
  ['expiry beyond 90 days', exception({ expires: isoDay(120) })],
  ['missing reason', exception({ reason: '' })],
  ['missing tracking reference', exception({ tracking: '' })],
  ['malformed id', exception({ id: 'CVE-2026-0001' })],
  ['malformed date', exception({ expires: '18.12.2026' })],
]) {
  test(`malformed exception file denies: ${name}`, () => {
    const res = runGate({ full: withAdvisories([picomatchHigh]), prod: report(), exceptions: [entry] });
    assert.equal(res.status, 1);
    assert.match(res.stderr, /could not be verified/);
  });
}

test('advisory list that does not explain the high count denies', () => {
  const full = withAdvisories([picomatchHigh]);
  full.metadata.vulnerabilities.high = 5;
  const res = runGate({ full, prod: report(), exceptions: [exception()] });
  assert.equal(res.status, 1);
});

test('committed exceptions file is valid and time-boxed', async () => {
  const { parseExceptions, DEFAULT_EXCEPTIONS_FILE } = await import('./check-security-audit.mjs');
  const entries = parseExceptions(readFileSync(DEFAULT_EXCEPTIONS_FILE, 'utf8'), Date.now());
  for (const e of entries) assert.ok(e.expiresAt >= Date.now(), `${e.id} has expired; remove it`);
});
