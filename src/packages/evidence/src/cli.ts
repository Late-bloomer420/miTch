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
  writeFileSync(join(dir, `EVIDENCE_${stamp}.json`), json + '\n');

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
