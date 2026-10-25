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
  ['high only stays visible under the minimum critical policy', report({ high: 51 }), 1, 0],
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
    assert.doesNotMatch(workflow, /continue-on-error|except: pass|No critical vulnerabilities found/);
  });
}
