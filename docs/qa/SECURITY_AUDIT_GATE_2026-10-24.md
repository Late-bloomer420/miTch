# Minimum critical audit gate — 2026-10-24

Scope: separate #185 gate slice based on master
`a21ac24e2e7f091b3652f91dfd26162f5a822914`. No dependency resolution change.
Node v24.19.0, pnpm 9.15.9 via Corepack, Linux.

`node --test scripts/check-security-audit.test.mjs`: **17/17 passed**.
Tests run the CLI in child processes and assert real exit codes. Critical=1,
registry/command errors, invalid JSON, invalid/missing counts, inconsistent exit
status and a missing report file all fail. The two integrated workflow files
must call the regression suite and enforced gate without failure suppression.

A live `pnpm audit --json` against the unchanged master lockfile reported
**146 findings, 52 high and 1 critical**. Feeding this result and its real audit
exit status to `check-security-audit.mjs` exited **1**, as required. The #193
lockfile produced the same live counts. The older 23 October Actions result
(140, 51 high, 1 critical) is dated registry evidence, not contradicted or erased.

Both `.github/workflows/ci.yml` and `ci-security.yml` now propose one common
policy: fail on any critical, or on an unverifiable audit execution/report.
A valid high-only report is visible but does not fail this **minimum critical**
policy. High-severity enforcement and dependency-family remediation remain open
under #185. This patch is not a clean-audit or production-readiness claim.

Owner: @Late-bloomer420. Target: **2026-10-26** for human gate review and critical
runtime dependency triage. The current live critical must make the proposed CI
red until remediation. No merged/integrated workflow run is claimed by this local
record; the PR's workflow results are the next evidence. Do not close #185 on the
strength of its synthetic gate tests.
