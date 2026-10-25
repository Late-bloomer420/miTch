import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// Minimum enforced policy: no critical findings. High findings stay visible
// and tracked in #185; audit transport/format errors must never look clean.
export function evaluateAudit(text, auditExitCode) {
  const report = JSON.parse(text);
  if (!report || typeof report !== 'object' || report.error) {
    throw new Error('Audit reported an error.');
  }
  const counts = report.metadata?.vulnerabilities;
  const levels = ['info', 'low', 'moderate', 'high', 'critical'];
  if (!counts || levels.some((level) => !Number.isSafeInteger(counts[level]) || counts[level] < 0)) {
    throw new Error('Missing or invalid audit vulnerability counts.');
  }
  const total = levels.reduce((sum, level) => sum + counts[level], 0);
  if (auditExitCode !== 0 && !(auditExitCode === 1 && total > 0)) {
    throw new Error('Audit command failed without a valid advisory result.');
  }
  if (auditExitCode === 0 && total > 0) {
    throw new Error('Audit exit status contradicts its advisory counts.');
  }
  return { critical: counts.critical, high: counts.high, total };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const counts = evaluateAudit(readFileSync(process.argv[2], 'utf8'), Number(process.argv[3]));
    console.log(`Audit: ${counts.total} findings; critical=${counts.critical}, high=${counts.high}. Gate: critical=0 required.`);
    if (counts.critical > 0) {
      console.error('Security audit denied: critical advisories require remediation.');
      process.exitCode = 1;
    }
  } catch {
    // Do not print raw registry/proxy diagnostics or misreport them as zero CVEs.
    console.error('Security audit denied: audit execution or report could not be verified.');
    process.exitCode = 1;
  }
}
