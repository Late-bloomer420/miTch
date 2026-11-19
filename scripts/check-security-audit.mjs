import { readFileSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';

// Enforced policy: no critical and no high findings. Moderate and lower stay
// visible in the log; audit transport/format errors must never look clean.
//
// The only relief is a narrow, expiring exception for a single HIGH advisory
// (scripts/security-audit-exceptions.json). It applies only when a separate
// production-only audit report has no high or critical findings and does not
// list the advisory. Critical findings are never excused. Anything that cannot be
// verified (missing/invalid prod report, malformed exception file, counts that
// do not add up) denies.

const LEVELS = ['info', 'low', 'moderate', 'high', 'critical'];
const GHSA_PATTERN =
  /^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const MAX_EXCEPTION_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_EXCEPTIONS_FILE = fileURLToPath(
  new URL('./security-audit-exceptions.json', import.meta.url)
);

function parseReport(text) {
  const report = JSON.parse(text);
  if (!report || typeof report !== 'object' || report.error) {
    throw new Error('Audit reported an error.');
  }
  return report;
}

export function evaluateAudit(text, auditExitCode) {
  const report = parseReport(text);
  const counts = report.metadata?.vulnerabilities;
  if (
    !counts ||
    LEVELS.some((level) => !Number.isSafeInteger(counts[level]) || counts[level] < 0)
  ) {
    throw new Error('Missing or invalid audit vulnerability counts.');
  }
  const total = LEVELS.reduce((sum, level) => sum + counts[level], 0);
  if (auditExitCode !== 0 && !(auditExitCode === 1 && total > 0)) {
    throw new Error('Audit command failed without a valid advisory result.');
  }
  if (auditExitCode === 0 && total > 0) {
    throw new Error('Audit exit status contradicts its advisory counts.');
  }
  return { critical: counts.critical, high: counts.high, total, report };
}

export function parseExceptions(text, now) {
  const entries = JSON.parse(text);
  if (!Array.isArray(entries)) throw new Error('Exceptions file must be a JSON array.');
  const latest = now + MAX_EXCEPTION_DAYS * DAY_MS;
  return entries.map((entry) => {
    if (!entry || typeof entry !== 'object') throw new Error('Invalid exception entry.');
    const { id, module, expires, reason, tracking } = entry;
    if (typeof id !== 'string' || !GHSA_PATTERN.test(id))
      throw new Error('Exception needs a GHSA id.');
    if (typeof module !== 'string' || module.length === 0)
      throw new Error('Exception needs a module.');
    if (typeof reason !== 'string' || reason.trim().length < 20) {
      throw new Error('Exception needs a written reason.');
    }
    if (typeof tracking !== 'string' || tracking.trim().length === 0) {
      throw new Error('Exception needs a tracking reference.');
    }
    if (typeof expires !== 'string' || !DATE_PATTERN.test(expires)) {
      throw new Error('Exception needs an expires date (YYYY-MM-DD).');
    }
    // Valid through the end of the expiry day (UTC).
    const expiresAt = Date.parse(`${expires}T23:59:59.999Z`);
    if (!Number.isFinite(expiresAt)) throw new Error('Exception expires date is invalid.');
    if (expiresAt > latest) {
      throw new Error(`Exception ${id} expires more than ${MAX_EXCEPTION_DAYS} days ahead.`);
    }
    return { id, module, expires, expiresAt, reason, tracking };
  });
}

function advisoryList(report) {
  const advisories = report.advisories;
  if (advisories === undefined) return [];
  if (!advisories || typeof advisories !== 'object') throw new Error('Invalid advisories section.');
  return Object.values(advisories);
}

function findingCount(advisory) {
  if (!Array.isArray(advisory.findings) || advisory.findings.length === 0) {
    throw new Error('Advisory without findings.');
  }
  return advisory.findings.length;
}

export function evaluateGate({ fullText, fullStatus, prodText, prodStatus, exceptionsText, now }) {
  const full = evaluateAudit(fullText, fullStatus);
  const advisories = advisoryList(full.report);

  // The per-level counts must be explained by the advisory list; otherwise the
  // excused amount cannot be trusted.
  for (const level of ['high', 'critical']) {
    const sum = advisories
      .filter((a) => a.severity === level)
      .reduce((n, a) => n + findingCount(a), 0);
    if (sum !== full[level]) throw new Error(`Advisory list does not match ${level} count.`);
  }

  const exceptions = exceptionsText === undefined ? [] : parseExceptions(exceptionsText, now);
  const excused = [];
  const expired = exceptions.filter((e) => e.expiresAt < now);
  const active = exceptions.filter((e) => e.expiresAt >= now);

  const highAdvisories = advisories.filter((a) => a.severity === 'high');
  if (active.length > 0 && highAdvisories.length > 0) {
    if (prodText === undefined) throw new Error('Exceptions need a production-only audit report.');
    const prod = evaluateAudit(prodText, prodStatus);
    const prodIds = new Set(advisoryList(prod.report).map((a) => a.github_advisory_id));
    // The counts decide: an advisory list can be missing, incomplete or unlabelled.
    const prodClean = prod.high === 0 && prod.critical === 0;
    for (const advisory of prodClean ? highAdvisories : []) {
      const match = active.find(
        (e) => e.id === advisory.github_advisory_id && e.module === advisory.module_name
      );
      if (match && !prodIds.has(advisory.github_advisory_id)) {
        excused.push({ ...match, findings: findingCount(advisory) });
      }
    }
  }

  const excusedFindings = excused.reduce((n, e) => n + e.findings, 0);
  return {
    critical: full.critical,
    high: full.high - excusedFindings,
    rawHigh: full.high,
    total: full.total,
    excused,
    expired,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [fullFile, fullStatus, prodFile, prodStatus, exceptionsFile] = process.argv.slice(2);
    let exceptionsText;
    try {
      exceptionsText = readFileSync(exceptionsFile ?? DEFAULT_EXCEPTIONS_FILE, 'utf8');
    } catch (error) {
      if (exceptionsFile !== undefined || error?.code !== 'ENOENT') throw error;
    }
    const result = evaluateGate({
      fullText: readFileSync(fullFile, 'utf8'),
      fullStatus: Number(fullStatus),
      prodText: prodFile === undefined ? undefined : readFileSync(prodFile, 'utf8'),
      prodStatus: prodStatus === undefined ? undefined : Number(prodStatus),
      exceptionsText,
      now: Date.now(),
    });
    for (const e of result.excused) {
      console.log(
        `Excepted: ${e.id} (${e.module}, ${e.findings} dev-only finding(s)) until ${e.expires} — ${e.tracking}`
      );
    }
    for (const e of result.expired) {
      console.log(`Expired exception ignored: ${e.id} (${e.module}) expired ${e.expires}`);
    }
    console.log(
      `Audit: ${result.total} findings; critical=${result.critical}, high=${result.high}` +
        (result.rawHigh !== result.high ? ` (raw high=${result.rawHigh})` : '') +
        '. Gate: critical=0 and high=0 required.'
    );
    if (result.critical > 0 || result.high > 0) {
      console.error('Security audit denied: critical or high advisories require remediation.');
      process.exitCode = 1;
    }
  } catch {
    // Do not print raw registry/proxy diagnostics or misreport them as zero CVEs.
    console.error('Security audit denied: audit execution or report could not be verified.');
    process.exitCode = 1;
  }
}
