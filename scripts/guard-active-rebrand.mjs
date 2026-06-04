import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const ROOT = process.cwd();
const SCAN_TARGETS = [
  'src',
  '.github',
  'package.json',
  'pnpm-workspace.yaml',
  'turbo.json',
];
const SKIP_DIRS = new Set(['node_modules', 'dist', 'coverage', '.turbo', '.git']);
const SCAN_EXTENSIONS = new Set([
  '.cjs',
  '.js',
  '.json',
  '.jsx',
  '.mjs',
  '.ts',
  '.tsx',
  '.yaml',
  '.yml',
]);
const STALE_PATTERNS = [
  /@mitch\//,
  /did:mitch/,
  /mitch\.demo/,
  /MitchPolicyEvaluator/,
];

async function listFiles(target) {
  const absolute = path.join(ROOT, target);
  const info = await stat(absolute).catch(() => null);
  if (!info) return [];
  if (info.isFile()) return [absolute];
  if (!info.isDirectory()) return [];

  const entries = await readdir(absolute, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
    const child = path.join(absolute, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(path.relative(ROOT, child))));
    } else if (entry.isFile() && SCAN_EXTENSIONS.has(path.extname(child))) {
      files.push(child);
    }
  }
  return files;
}

function findMatches(file, content) {
  const matches = [];
  const lines = content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    for (const pattern of STALE_PATTERNS) {
      if (pattern.test(line)) {
        matches.push(`${path.relative(ROOT, file)}:${index + 1}: ${line.trim()}`);
      }
    }
  }
  return matches;
}

const files = (await Promise.all(SCAN_TARGETS.map(listFiles))).flat();
const findings = [];

for (const file of files) {
  const content = await readFile(file, 'utf8').catch(() => null);
  if (content === null) continue;
  findings.push(...findMatches(file, content));
}

if (findings.length > 0) {
  console.error('Active AskMI rebrand guard failed. Stale miTch identifiers found:');
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

console.log('Active AskMI rebrand guard passed.');
