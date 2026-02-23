# 59 — Supply-Chain Hardening v1

Stand: 2026-02-11

## Why
External findings highlight dependency compromise as a high-probability/high-impact risk.

## Baseline controls (now)
1. Dependency audit script present:
   - `npm run security:deps` (`npm audit --audit-level=high`)
2. Lockfile discipline and version pinning policy (no loose production deps)
3. Security review requirement before dependency upgrades

## Required next controls (short-term)
1. CI gate for `security:deps` (merge-blocking for high/critical)
2. SBOM generation and artifact retention per release
3. Dependency allowlist policy for critical cryptographic/runtime libraries
4. Incident procedure for dependency compromise (rollback + key rotation check)

## Acceptance criteria for v1.1
- Every release has:
  - successful dependency audit report,
  - SBOM artifact,
  - documented exceptions (if any) approved by human reviewer.
