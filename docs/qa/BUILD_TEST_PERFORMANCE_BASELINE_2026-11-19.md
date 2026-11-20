# Build/Test Runtime Baseline

**Date:** 2026-11-19
**Revision:** `70c7aef` (merge-base of branch `docs/qa-perf-baseline-2026-11-19` with master), verified clean checkout in a separate worktree
**Environment:** Windows 11, 12 logical cores, Node v24.16.0, pnpm 9.15.9, Turbo local cache
**Status:** Observation with exact commands and numbers. Not a security or performance PASS. All runs succeeded (exit 0). CI (= ubuntu-latest, Node 22) is NOT measured here; see Limits.

## Question

Why do `pnpm build` / `pnpm test` feel long? No documented runtime baseline existed.

## Method

All measurement runs were performed on a clean checkout of `70c7aef` (verified `git status --porcelain` empty before the runs) after `pnpm install --frozen-lockfile`. Commands and exact durations below.

## Measurements

| Run | Turbo task time | Wall clock (`time`) | Tasks / cache state |
|---|---|---|---|
| `pnpm exec turbo run test --force` (full cold: all test tasks AND their `^build` dependencies executed; **includes `@askmi/poc-hardened`**, see note) | 3 m 7.506 s | **3 m 11.115 s** | 50 tasks, 0 cached |
| `pnpm test` (immediately after, warm test cache) | 1.653 s | 3.275 s | 49 tasks, 49 cached ("FULL TURBO") |
| `pnpm build` (immediately after the forced test run; mixed cache state) | 28.632 s | 30.284 s | 31 tasks, 19 cached |

**Scope note (added after review):** the cold run called `turbo run test` directly, so it did not apply the root `test` script's `--filter=!@askmi/poc-hardened` (`package.json`). It therefore ran 50 tasks including `@askmi/poc-hardened`, while the warm `pnpm test` ran 49 without it. The cold and warm rows are not like-for-like, and the cold figure slightly overstates a cold `pnpm test`. A like-for-like cold number would come from `pnpm test -- --force`; it was not measured at `70c7aef`.

Per-suite wall-clock durations inside the full cold run (30 packages report duration numbers; suites ran under full parallel load, so per-suite wall clocks are inflated by CPU contention):

| Package | Wall clock | Top warnings |
|---|---|---|
| @askmi/evidence | 83.3 s | 78.1 s aggregated test time; real `spawnSync` subprocess tests |
| @askmi/wallet-pwa | 78.2 s | aggregated import time 62.3 s across workers; environment startup 6 ms |
| @askmi/phase0-security | 22.6 s | — |
| @askmi/shared-crypto | 19.4 s | aggregated test time 61.2 s (PQC keygen/signing is real work) |
| @askmi/policy-engine | 18.5 s | aggregated import time 73.9 s; transform 35.3 s |
| @askmi/issuer-mock | 14.6 s | — |
| @askmi/shared-types | 13.1 s | — |
| @askmi/consent-ui | 12.4 s | — |

Isolated control run for the top suite: `npx vitest run` in `src/packages/evidence` alone (no parallel package load): **13.58 s** wall clock (tests 12.58 s), 24 passed / 1 skipped — the same suite takes 83.3 s inside the cold full run (~6x), so most of its cold-run cost is CPU contention, not intrinsic work.

**Note on vitest sub-metrics:** per-suite "Duration" is wall clock, but the breakdown fields (transform/setup/import/tests) are summed across parallel workers and can exceed wall clock. They must not be compared with wall-clock rankings. The table above labels them explicitly as aggregated.

## Retracted preliminary measurement (provenance)

An earlier preliminary timing was taken in the main working tree at locally-unpushed revision `551a09d` **plus uncommitted local modifications** (among others `package.json` and `src/apps/wallet-pwa/package.json` were locally modified). It cannot be reproduced or checked out by anyone else. Its numbers (cold graph 3 m 58.6 s; wallet-pwa 120.5 s with 67.9 s jsdom environment startup) did NOT reproduce at the committed revision (wallet-pwa environment startup measured 6 ms). That preliminary measurement is therefore **retracted and superseded** by the `70c7aef` numbers in this report. Lesson recorded: a baseline intended for later comparison must be measured at a committed revision on a clean tree — which is what this report does.

## Analysis (committed revision `70c7aef`)

1. **Warm state is fast (seconds); the felt cost is the cold/invalidated state.** `pnpm test` warm: 1.7 s turbo / 3.3 s wall. Full cold graph: ~3 m 11 s wall locally.
2. **evidence is the top suite under full load, by design, and mostly contention.** Isolated it takes 13.6 s; under full parallel load 83.3 s (~6x). Its tests deliberately spawn real pnpm/vitest subprocesses (`runner.test.ts`, "vitestExecutor (integration, real spawn)", 0.5–5.5 s per test) — this is the purpose of the package. No change recommended.
3. **wallet-pwa is the second suite (78.2 s); the driver is module resolution, not jsdom startup at this revision.** The aggregated import time across workers is 62.3 s while environment startup measured 6 ms. (The preliminary dirty-tree observation of 68 s jsdom boot does not reproduce and is retracted.) A module-graph/import-cost investigation is the plausible follow-up, evidence pending.
4. **shared-crypto is real work but not a top driver by wall clock.** 19.4 s wall; the 61.2 s figure is the worker-aggregated test time (PQC keygen/signing), not wall clock.
5. **Cache invalidate is broad:** `turbo.json` defines no `inputs` for any task, so any file change in a package (including `README.md`) invalidates that package's build+test cache and everything downstream of it.
6. **CI is always cold for Turbo:** `.github/workflows/ci.yml` caches only the pnpm store; every CI run pays the cold graph, `build → test → lint` run sequentially, and the `layer-validation` job executes a second full `pnpm build`.

## Limits (what this report does NOT establish)

- CI (ubuntu-latest, Node 22) durations are not measured; local Node v24 vs CI Node 22 differences are not quantified.
- Run-to-run variance was not determined (single cold run, single warm run, one isolated control run).
- Install time (`pnpm install --frozen-lockfile`) was not timed.
- The wallet-pwa import-cost attribution is a hypothesis from aggregated vitest metrics; no module-graph analysis was done.

## Proposed follow-ups (NOT implemented)

1. Define turbo `inputs` per task to narrow cache invalidation.
2. CI: Turbo cache (`actions/cache` for the Turbo cache directory) or Turborepo remote cache (needs repo-owner decision: account + secrets).
3. Investigate wallet-pwa module-resolution/import cost (NOT jsdom: that hypothesis did not reproduce).
4. Evidence suite: leave as is; do not add parallelism work for its own sake.
5. Demo/pilot environment hosting: separate owner decision; would not change test runtime.
