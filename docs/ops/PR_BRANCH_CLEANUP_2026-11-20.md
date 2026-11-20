# PR and branch cleanup — 2026-10-23 to 2026-11-20

**Owner:** Late-bloomer420 · **Executed by:** Claude Code agent, with owner decisions recorded below
**master at close:** `8dd7f3e` (after #309) · **Open pull requests at close:** 0

## Purpose

Clear the pull-request backlog with privacy and security as the first criterion. Each open PR was
handled oldest first. A PR was merged only after its change was ported onto current `master` and
checked. Stale or mixed-scope PRs were closed with a written reason on the PR. Useful code from
closed PRs was carried over in a new, focused PR. This record shows what happened and which roadmap
item each step serves. It does not close any gate; see [Gate effect](#gate-effect).

## Timeline

| Date       | Step                                                                                                                                                                          | Pull requests                            |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| 2026-10-23 | Closed the public-preview tunnel PR: exposure work must not travel with security remediation ([working rule](../security/SECURITY_AUDIT_ROADMAP_2026-10-01.md#working-rules)) | #105                                     |
| 2026-10-23 | Closed the stacked weekly EUDI upstream chain as superseded; its content is on `master` at `624cf9a` via #174                                                                 | #144, #145, #146, #156, #157, #168, #169 |
| 2026-10-23 | Closed two bot PRs whose diffs were mostly reformatting in `verifier-sdk` and `policy-engine/engine.ts`                                                                       | #163, #164                               |
| 2026-10-25 | Ported the #141 code hardening (fail-closed recovery, verifier CORS/session isolation) and closed #141                                                                        | #195 merged, #141 closed                 |
| 2026-10-25 | Secure `decisionId` randomness landed as a focused fix; #151 closed                                                                                                           | #203 merged, #151 closed                 |
| 2026-11-13 | Superseded high-advisory PR closed; the dependency waves cleared all Dependabot alerts                                                                                        | #248 closed; #269, #272 merged           |
| 2026-11-13 | Architecture decoupling audit split (owner decision) and merged; canon follow-up merged 2026-11-19                                                                            | #188, #246                               |
| 2026-11-19 | pnpm 10.34.9 pinned everywhere; audit gate denies high and critical; time-boxed picomatch exception (owner decision)                                                          | #257                                     |
| 2026-11-20 | Build/test baseline corrected for two review findings, then merged                                                                                                            | #304                                     |
| 2026-11-20 | Functional parts of #163/#164 ported with tests                                                                                                                               | #308                                     |
| 2026-11-20 | Dormant picomatch exception removed, stale npm lockfiles removed, this record                                                                                                 | this PR                                  |

The owner merged further PRs in the same window (for example #265, #266, #297, #301, #302, #309).
They are listed in [CHANGELOG.md](../../CHANGELOG.md) and are not part of this record's decisions.

## Roadmap mapping

| Step                                                                                                                                                                                                                                         | Roadmap item                                                     | Tracker                                                                     |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------- |
| #141 → #195                                                                                                                                                                                                                                  | Wave 0: reconcile #141 security changes against current master   | #142                                                                        |
| #105, EUDI chain, #163/#164, #141, #248 closed with reasons                                                                                                                                                                                  | Wave 0: close or re-scope stale PRs                              | #142                                                                        |
| #257 (pnpm 10.34.9 in `packageManager`, CI and the verifier-demo frontend image); stale npm lockfiles removed here; three app images still unpinned ([finding 1](../qa/SECURITY_AUDIT_GATE_2026-11-20.md#follow-up-findings-not-fixed-here)) | Wave 0: pin Node/pnpm, remove stale npm lockfiles                | #142                                                                        |
| #194 (critical, 2026-10-25) and #257 (high, 2026-11-19); exceptions empty since #310                                                                                                                                                         | EV-05 / SEC-AUDIT-1: audit threshold fails closed                | #185                                                                        |
| #203, #195                                                                                                                                                                                                                                   | SEC-AUDIT-1: small code security fixes                           | [Security audit roadmap](../security/SECURITY_AUDIT_ROADMAP_2026-10-01.md)  |
| #206, #227, #229, #269, #272, #257                                                                                                                                                                                                           | SEC-AUDIT-2: dependency advisories (now 0 at every level, dated) | [Security audit roadmap](../security/SECURITY_AUDIT_ROADMAP_2026-10-01.md)  |
| #188, #246                                                                                                                                                                                                                                   | Canonical architecture boundaries                                | [ARCHITECTURE_DECOUPLING.md](../03-architecture/ARCHITECTURE_DECOUPLING.md) |
| #304, #308                                                                                                                                                                                                                                   | Evidence hygiene and code health; no gate                        | —                                                                           |

## Gate effect

- **Proposed for the owner, not recorded here:** two Wave 0 checklist items in #142 now have
  linked evidence: the #141 reconciliation and the stale-PR disposition. The pnpm/lockfile item is
  partly evidenced; it needs the three app images pinned (finding 1) before it can be ticked.
  [Update discipline](../RELEASE_READINESS_ROADMAP.md#update-discipline) leaves the gate change
  to the roadmap owner.
- **Not assessed in this record:** the other Wave 0 items (CIR traceability fields, frozen pilot
  profile, ARF/source lock). Node is pinned to major 22 in CI only; there is no `engines` field
  or `.nvmrc`.
- **EV-05:** the narrow gate criterion is implemented on master with dated evidence in
  [SECURITY_AUDIT_GATE_2026-11-20.md](../qa/SECURITY_AUDIT_GATE_2026-11-20.md). #185 stays open
  for its broader scope.
- No G0–G6 market gate, release gate or pilot date moves.

## Branches

On 2026-11-20 the remote had 64 heads. Sixty belong to a merged or closed PR and can be deleted.
Four stay: `master` and three branches without a PR that carry unique commits
(`docs/architecture-decoupling-audit-2026-08-20`, `fix/phase0-forensics-review`,
`wip/g100.4-correlation-id-trace`). Those three need an owner decision; none is deleted here.

The agent's `git push --delete` was refused with HTTP 403 for every branch. Deletion is left to
the owner. Nothing was worked around.

**Recovery.** GitHub keeps `refs/pull/<number>/head` for every PR after its branch is deleted.
Commits of closed, unmerged PRs therefore stay reachable:

```sh
git fetch origin pull/<number>/head:<local-branch>
```

Squash-merged branches show "unique" commits against `master` only because squashing changes
commit IDs; their content is on `master`.

| Branch                                                       | Tip            | PR                |
| ------------------------------------------------------------ | -------------- | ----------------- |
| `chore/pnpm-10-audit-gate`                                   | `0aa7b526ff48` | #257 merged       |
| `chore/port-jules-perf-163-164`                              | `9f4118b344dd` | #308 merged       |
| `chore/wallet-public-preview-flow`                           | `35385bb76caa` | #105 closed       |
| `claude/docs-archive-inventory`                              | `883ce1e8e46f` | #266 merged       |
| `claude/hopeful-ritchie-ZDGZe`                               | `4a321584b3d6` | #265 merged       |
| `claude/nifty-planck-ogbng4`                                 | `516084273747` | #290, #309 merged |
| `codex/Testapp`                                              | `9b1bdc3b750e` | #139 closed       |
| `demo/claims-cleanup`                                        | `f718a73277bb` | #155 merged       |
| `demo/live-demo-fixes`                                       | `d94bf69972f3` | #154 merged       |
| `docs/api-audit-review-299`                                  | `6e97438bfbee` | #302 merged       |
| `docs/api-protocol-audit-2026-11-03-reland`                  | `e6ba65496ed9` | #281 closed       |
| `docs/architecture-canon-backlog-2026-11-01`                 | `ac42f3fbca2d` | #246 merged       |
| `docs/changelog-discrete-core`                               | `baef28e15cc2` | #249 merged       |
| `docs/claude-md-ruleset-guard`                               | `f7a2dbba3216` | #268 merged       |
| `docs/deniable-ecdsa-presentations`                          | `a02621723a19` | #259 merged       |
| `docs/eudi-upstream-2026-08-31`                              | `4ce88b5e3e8d` | #144 closed       |
| `docs/eudi-upstream-2026-09-07`                              | `35e0a15db3f2` | #145 closed       |
| `docs/eudi-upstream-2026-09-14`                              | `32733e992aeb` | #146 closed       |
| `docs/eudi-upstream-2026-09-21`                              | `ffdf64abf7ef` | #156 closed       |
| `docs/eudi-upstream-2026-09-28`                              | `e9b7f6840705` | #157 closed       |
| `docs/eudi-upstream-2026-10-05`                              | `a094ecbc938e` | #168 closed       |
| `docs/eudi-upstream-2026-10-12`                              | `4d4cc604337a` | #169 closed       |
| `docs/eudi-upstream-2026-10-19`                              | `eaacac1cc4ad` | #179 closed       |
| `docs/evidence-truth-2026-10-14`                             | `d897fa5054f4` | #174 merged       |
| `docs/fallback-mode-inventory-242`                           | `03ad83fece7c` | #279 merged       |
| `docs/observable-trust-milestones`                           | `2d6169f30f04` | #178 merged       |
| `docs/pilot-delivery-structure`                              | `0513b31a83bf` | #306 merged       |
| `docs/qa-perf-baseline-2026-11-19`                           | `6b70103baf0a` | #304 merged       |
| `docs/security-threat-model-roadmap-20261023`                | `481e82f4a2b3` | #187 merged       |
| `docs/session-23-split-decision`                             | `67634721a47d` | #300 merged       |
| `feat/age-over-18-profile-c`                                 | `031157522f1e` | #291 merged       |
| `feat/discrete-core`                                         | `33c4486e1a7d` | #189 merged       |
| `feat/g140-surfacing-pr-b`                                   | `c4075a3aa840` | #120 merged       |
| `feat/isolated-demo-wallet`                                  | `76cc6f752245` | #277 merged       |
| `feat/issuer-kid-selection`                                  | `347835192ce9` | #292 merged       |
| `fix-decisionid-randomness-15758000728439267073`             | `d6617cf659c3` | #151 closed       |
| `fix-oid4vp-test-improvement-8485348132468725333`            | `e2c9a7464911` | #147 closed       |
| `fix/age-demo-evidence-honesty-97`                           | `cd0dcf92b124` | #287 merged       |
| `fix/audit-log-l2-anchor-honest-status`                      | `3e6eabba5cd9` | #297 merged       |
| `fix/dependabot-vitest-mocker-131636668113`                  | `924c1ef8bd9e` | #273 merged       |
| `fix/deps-high-advisories`                                   | `997d6c9c1bc2` | #248 closed       |
| `fix/entire-pr-247-scope-split`                              | `360d71640c8a` | #280 closed       |
| `fix/l2-mock-receipt-296`                                    | `bdd4bb80ea5e` | #301 merged       |
| `fix/strict-disclosure-264`                                  | `039400acf74b` | #288 merged       |
| `fix/strict-verifier-binding-238`                            | `edbb0692d154` | #275 merged       |
| `fix/trust-list-fail-closed-240`                             | `fdc41a39dd05` | #276 merged       |
| `fix/wallet-postmessage-origin-239`                          | `d82c3d61c6d6` | #278 merged       |
| `hardening/truth-readiness-rc`                               | `6f9e00569c3c` | #141 closed       |
| `jules-11783091063423459126-2958762a`                        | `e4d78c7a7493` | #165 merged       |
| `jules-18113794777574904008-ef724a83`                        | `85640a93d605` | #149 closed       |
| `jules-2265594072091173460-fda715c3`                         | `bb59d9d4e785` | #150 closed       |
| `jules-nonce-opt-6605583879866276969`                        | `ec63e3b86819` | #163 closed       |
| `perf-optimize-policy-engine-claim-set-16687172106700550250` | `e437b011a55a` | #164 closed       |
| `perf-optimize-predicate-hashing-14452747958728949187`       | `146b2d02f94e` | #148 closed       |
| `research/age-session-formal-model`                          | `cccd79a9cf4b` | #289 merged       |
| `test/age-over-18-expiry`                                    | `e210aee59605` | #298 merged       |
| `test/evidence-manifest-validation`                          | `25c56867a76a` | #307 merged       |
| `vibe/carrier-revenue-doc-8fe002`                            | `f40cf64bbb5c` | #258 merged       |
| `vibe/competitive-positioning-doc-dfbae9`                    | `f6500806785a` | #250 merged       |
| `vibe/remove-gemini-bot-499b47`                              | `091df1d5f9d8` | #303 merged       |

### Delete command (owner, from a clone with push rights)

```sh
git push origin --delete \
  chore/pnpm-10-audit-gate \
  chore/port-jules-perf-163-164 \
  chore/wallet-public-preview-flow \
  claude/docs-archive-inventory \
  claude/hopeful-ritchie-ZDGZe \
  claude/nifty-planck-ogbng4 \
  codex/Testapp \
  demo/claims-cleanup \
  demo/live-demo-fixes \
  docs/api-audit-review-299 \
  docs/api-protocol-audit-2026-11-03-reland \
  docs/architecture-canon-backlog-2026-11-01 \
  docs/changelog-discrete-core \
  docs/claude-md-ruleset-guard \
  docs/deniable-ecdsa-presentations \
  docs/eudi-upstream-2026-08-31 \
  docs/eudi-upstream-2026-09-07 \
  docs/eudi-upstream-2026-09-14 \
  docs/eudi-upstream-2026-09-21 \
  docs/eudi-upstream-2026-09-28 \
  docs/eudi-upstream-2026-10-05 \
  docs/eudi-upstream-2026-10-12 \
  docs/eudi-upstream-2026-10-19 \
  docs/evidence-truth-2026-10-14 \
  docs/fallback-mode-inventory-242 \
  docs/observable-trust-milestones \
  docs/pilot-delivery-structure \
  docs/qa-perf-baseline-2026-11-19 \
  docs/security-threat-model-roadmap-20261023 \
  docs/session-23-split-decision \
  feat/age-over-18-profile-c \
  feat/discrete-core \
  feat/g140-surfacing-pr-b \
  feat/isolated-demo-wallet \
  feat/issuer-kid-selection \
  fix-decisionid-randomness-15758000728439267073 \
  fix-oid4vp-test-improvement-8485348132468725333 \
  fix/age-demo-evidence-honesty-97 \
  fix/audit-log-l2-anchor-honest-status \
  fix/dependabot-vitest-mocker-131636668113 \
  fix/deps-high-advisories \
  fix/entire-pr-247-scope-split \
  fix/l2-mock-receipt-296 \
  fix/strict-disclosure-264 \
  fix/strict-verifier-binding-238 \
  fix/trust-list-fail-closed-240 \
  fix/wallet-postmessage-origin-239 \
  hardening/truth-readiness-rc \
  jules-11783091063423459126-2958762a \
  jules-18113794777574904008-ef724a83 \
  jules-2265594072091173460-fda715c3 \
  jules-nonce-opt-6605583879866276969 \
  perf-optimize-policy-engine-claim-set-16687172106700550250 \
  perf-optimize-predicate-hashing-14452747958728949187 \
  research/age-session-formal-model \
  test/age-over-18-expiry \
  test/evidence-manifest-validation \
  vibe/carrier-revenue-doc-8fe002 \
  vibe/competitive-positioning-doc-dfbae9 \
  vibe/remove-gemini-bot-499b47
```
