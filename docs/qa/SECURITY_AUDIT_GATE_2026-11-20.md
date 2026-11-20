# High/critical audit gate without exceptions — 2026-11-20

Base revision `8dd7f3e` (master after #309), branch
`docs/cleanup-roadmap-mapping-2026-11-20`. Linux cloud container, Node `v22.22.0`,
pnpm `10.34.9`. Observed 2026-11-20 around 06:20 UTC. The earlier records
([2026-10-24](SECURITY_AUDIT_GATE_2026-10-24.md), [2026-10-25](SECURITY_AUDIT_GATE_2026-10-25.md))
are preserved unchanged.

This is the first `docs/qa/` record for the high/critical gate introduced in PR #257.
STATE and BACKLOG previously cited only dated registry output for it.

## Change under test

- `scripts/security-audit-exceptions.json` is set to `[]`. It previously held one
  time-boxed entry: GHSA-fc5q-39xc-vjpf, `picomatch`, expiring 2026-12-18, tracked in #257.
- The stale npm lockfiles `package-lock.json` and
  `src/packages/poc-hardened/package-lock.json` are removed. Both last changed in #92
  (2026-06-09). They described only `@types/node` and `typescript` under the old package name.
  No workflow, Dockerfile or script runs `npm ci`; all installs use `pnpm --frozen-lockfile`.

## Observations

| Step                               | Command                                                                                               | Result                                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Install                            | `pnpm install --frozen-lockfile`                                                                      | exit 0                                                                |
| Full audit                         | `pnpm audit --json`                                                                                   | exit 0; info/low/moderate/high/critical = 0/0/0/0/0; 566 dependencies |
| Production audit                   | `pnpm audit --prod --json`                                                                            | exit 0; 0 findings                                                    |
| Gate                               | `node scripts/check-security-audit.mjs full.json 0 prod.json 0`                                       | `Audit: 0 findings; critical=0, high=0`; exit 0                       |
| Gate tests                         | `node --test scripts/check-security-audit.test.mjs`                                                   | 36/36 passed                                                          |
| Negative, empty exception file     | Synthetic full report with one high `picomatch` finding (GHSA-fc5q-39xc-vjpf), real clean prod report | `Security audit denied`; exit **1**                                   |
| Control, previous exception file   | Same synthetic report with the master version of the exception file                                   | excepted until 2026-12-18; exit 0                                     |
| Rebrand guard                      | `pnpm guard:rebrand`                                                                                  | exit 0                                                                |
| PoC package after lockfile removal | `pnpm --filter @askmi/poc-hardened build && … test`                                                   | build ok; 132/132 tests                                               |

The negative and control rows isolate the effect of this change. The same high finding
that the old entry excused now blocks the gate.

## Interpretation

- **Fact.** GHSA-fc5q-39xc-vjpf no longer appears in the registry response. The exception
  therefore had no effect at this revision; the gate passed without it.
- **Fact.** After 2026-12-18 the committed-file test ("committed exceptions file is valid and
  time-boxed") would have failed in both audit workflows. Removing the entry now avoids that
  and leaves no unused relief in the policy.
- **Unknown.** Why the advisory disappeared: it may have been withdrawn, re-scored or
  temporarily dropped. If it returns, the gate denies again. Remedy: pin a fixed release, or
  add a new reviewed entry (at most 90 days, high only, clean production audit).
- **Limit.** Audit counts are dated registry output, not a fixed property of the commit.
  The full `pnpm test` / `pnpm lint` suites were not re-run for this change; CI on the PR
  head is the authoritative re-run.

## Follow-up findings (not fixed here)

1. **Unpinned pnpm in app images.** `src/apps/issuer-mock/Dockerfile`,
   `src/apps/verifier-demo/backend/Dockerfile` and `src/apps/wallet-pwa/Dockerfile` run
   `npm install -g pnpm` without a version. An image build therefore picks whatever pnpm is
   current. That bypasses the 10.34.9 pin and is a supply-chain drift risk. Proposed fix: pin
   `pnpm@10.34.9` or use `corepack` with `packageManager`.
2. **Non-frozen install in the security workflow.** `.github/workflows/ci-security.yml` runs
   `pnpm install` without `--frozen-lockfile`. The audit could then evaluate a resolution that
   differs from the committed lockfile. `ci.yml` uses `--frozen-lockfile`.

#185 stays OPEN for evidence provenance, SBOM/signed provenance, conformance and independent
validation. This record does not establish release readiness or a clean audit beyond its date.

## Addendum — follow-up fixes (same day)

Both follow-up findings above are fixed in the same PR (#310). One more was found while doing so.
The observations above are left as recorded.

| Change                                                                                                                                                                                                                                    | Files                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| pnpm pinned through `corepack prepare pnpm@10.34.9 --activate`, as in the verifier-demo frontend image                                                                                                                                    | `src/apps/issuer-mock/Dockerfile`, `src/apps/verifier-demo/backend/Dockerfile`, `src/apps/wallet-pwa/Dockerfile` |
| Base image `node:20-alpine` → `node:22-alpine`. Node.js 20 reached end of life on 2026-04-30 and gets no security releases; CI already tests on Node 22                                                                                   | same three files                                                                                                 |
| Header comment "Based on AskMI 100% Compliance Architecture" replaced; the images make no compliance claim                                                                                                                                | same three files                                                                                                 |
| `pnpm install` → `pnpm install --frozen-lockfile`                                                                                                                                                                                         | `.github/workflows/ci-security.yml`                                                                              |
| New guard `scripts/check-toolchain-pins.test.mjs`, run in `ci-security.yml`. It checks pnpm against `packageManager` in images and workflows, supported Node majors in images (22, 24), and `--frozen-lockfile` on every workflow install | `scripts/`, workflow                                                                                             |

Verification (Linux, Node `v22.22.0`):

- The guard fails on base `8dd7f3e`: unpinned pnpm, `node:20`, non-frozen install (3 of 4 tests). It passes on the branch (4/4).
- `corepack prepare pnpm@10.34.9 --activate` on Node 22 (corepack 0.34.0) activates pnpm 10.34.9.
- **Not run:** a Docker image build. No Docker daemon is available in this environment. The images run the same Node 22 that CI tests on, but a first image build must confirm them.
- **Residual:** base images (`node`, `nginx`, `caddy`) are referenced by tag, not by digest.

### EU regulatory reference (orientation, not a compliance statement)

- **Fact.** The Cyber Resilience Act (Regulation (EU) 2024/2847) entered into force on
  2024-12-10. Its reporting duties (Art. 14) apply from 2026-09-11 and its main obligations from
  2027-12-11.
- **Fact.** Annex I Part I asks products to be placed on the market without known exploitable
  vulnerabilities and to allow vulnerabilities to be addressed through security updates.
  Part II asks manufacturers to identify and document components, including an SBOM.
- **Assessment.** Pinned build tools, a lockfile-exact install and a runtime that still gets
  security releases support these aims: reproducible builds make an SBOM accurate, and an EOL
  runtime cannot receive fixes.
- **Open.** Whether and when the CRA applies to AskMI depends on whether and how it is placed on
  the market. Today it is development/evaluation software. This change does not establish CRA
  conformity, and SBOM/provenance work stays under #185.
