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
