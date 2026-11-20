// Keeps the build toolchain reproducible: every place that installs pnpm uses the
// version from package.json "packageManager", app images use a supported Node
// major, and CI installs never re-resolve the lockfile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { URL, fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
// Node.js majors that still receive security releases. Update when a line reaches end of life.
const SUPPORTED_NODE_MAJORS = new Set([22, 24]);

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const match = /^pnpm@(\d+\.\d+\.\d+)$/.exec(pkg.packageManager ?? '');
const PNPM = match?.[1];

function walk(dir, pick, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name.startsWith('.')) {
      continue;
    }
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, pick, out);
    else if (pick(entry.name)) out.push(path);
  }
  return out;
}

const dockerfiles = walk(join(ROOT, 'src'), (name) => /^Dockerfile(\..+)?$/.test(name));
const workflowDir = join(ROOT, '.github', 'workflows');
const workflows = readdirSync(workflowDir)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => join(workflowDir, name));
const rel = (path) => relative(ROOT, path);

test('packageManager pins an exact pnpm version', () => {
  assert.ok(PNPM, `package.json packageManager must be pnpm@x.y.z, got ${pkg.packageManager}`);
});

test('app images pin pnpm to packageManager', () => {
  assert.ok(dockerfiles.length > 0, 'no Dockerfiles found');
  for (const file of dockerfiles) {
    const text = readFileSync(file, 'utf8');
    assert.doesNotMatch(
      text,
      /npm (i|install) -g pnpm(?!@)/,
      `${rel(file)} installs unpinned pnpm`
    );
    for (const [, version] of text.matchAll(/pnpm@(\d+\.\d+\.\d+)/g)) {
      assert.equal(version, PNPM, `${rel(file)} pins pnpm@${version}, expected ${PNPM}`);
    }
    if (/\bpnpm install\b/.test(text)) {
      assert.match(text, /pnpm@\d+\.\d+\.\d+/, `${rel(file)} runs pnpm without a pinned version`);
    }
  }
});

test('app images use a supported Node.js major', () => {
  for (const file of dockerfiles) {
    const text = readFileSync(file, 'utf8');
    for (const [, major] of text.matchAll(/^FROM\s+node:(\d+)/gim)) {
      assert.ok(
        SUPPORTED_NODE_MAJORS.has(Number(major)),
        `${rel(file)} uses node:${major}, which is not in the supported set`
      );
    }
  }
});

test('workflows pin pnpm to packageManager and install from the lockfile', () => {
  for (const file of workflows) {
    const text = readFileSync(file, 'utf8');
    for (const block of text.matchAll(
      /pnpm\/action-setup@[^\n]*\n(?:\s+with:\s*\n)?\s+version:\s*([^\s#]+)/g
    )) {
      assert.equal(block[1], PNPM, `${rel(file)} sets up pnpm ${block[1]}, expected ${PNPM}`);
    }
    for (const line of text.split('\n')) {
      if (/\bpnpm install\b/.test(line)) {
        assert.match(
          line,
          /--frozen-lockfile/,
          `${rel(file)}: "${line.trim()}" lacks --frozen-lockfile`
        );
      }
    }
  }
});
