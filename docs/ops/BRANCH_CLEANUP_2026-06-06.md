# Branch Cleanup — 2026-06-06

**Owner:** Late-bloomer420 · **Executed by:** OpenClaw/Lumen agent
**master HEAD at cleanup:** `16f61bb` (PR #72 merged)

## Purpose

Close stale branches permanently to remove confusion, **without losing any work**.
Every closed branch was verified to be either (a) fully contained in `master`
(`ahead=0`, mathematically guaranteed) or (b) content-superseded by `master`
(verified file-by-file / via `git cherry`). Branches with their own commits were
preserved as annotated `archive/*` tags before deletion, so every commit remains
recoverable forever.

## Verification method

- `git rev-list --count master..<branch>` → `ahead=0` means master already
  contains every commit (deletion loses nothing).
- `git cherry master <branch>` → `+` = patch not in master (checked individually);
  all `+` here were verified as docs/state text-drift or superseded code.
- Strategic/business/compliance docs were content-diffed: `master >= branch`
  everywhere (market/positioning docs exist **only** in master under
  `docs/05-business/`).

## Recovery

Any archived branch can be restored:

```sh
git fetch origin --tags
git checkout -b <branch> archive/<branch-with-slashes-as-dashes>
```

The realized release point is tagged `v1.0-rc`.

## Closed branches — `ahead=0` (guaranteed in master, no tag needed)

| Branch | Tip SHA |
|---|---|
| chore/full-askmi-rebrand | 182f04e |
| chore/s2-04-scenario-fixtures | 8fa238c |
| chore/s2-05-statuslist-test-helpers | f81d109 |
| docs/sovereignty-vrn-revival | 16f61bb |
| docs/v1-rc-finalization | 4a19176 |
| feat/phase-1-stabilization | b72017b |
| feat/phase-2-decoupling | 86edbf0 |
| feat/phase-3-integration | e7a0845 |
| feat/phase-4-compliance | 662b2b9 |
| feat/phase-5-security | b903fb9 |
| master-sync | f3e91a5 |
| qa/pilot-flow-rerun-2026-06-04 | 9d1c3e9 |
| recovery/wallet-pre-phase6 | b802ebc |
| release/v1.0-rc-final | 856913e (→ tag `v1.0-rc`) |
| test/pilot-flow-smoke | 2d14ae0 |
| claude/relaxed-pike | d02b9e5 |

## Closed branches — `ahead>0` superseded (preserved as `archive/*` tags)

| Branch | Tip SHA | ahead | Why superseded | Archive tag |
|---|---|---|---|---|
| rescue/review-mit21-2026-06-04 | 1f8e4d9 | 13 | Deploy-infra, MIT-21 ConsentModal fix, TSL/StatusList/Batch all in master; unique = docs/state text-drift | archive/rescue-review-mit21-2026-06-04 |
| codex/mit21-sovereign-deployment | dde1427 | 3 | All files present in master | archive/codex-mit21-sovereign-deployment |
| feat/wallet-dynamic-credentials-sync | 5b1c7e2 | 6 | CredentialRenderer/Card + process.env browser-fix in master | archive/feat-wallet-dynamic-credentials-sync |
| codex/verifier-privacy-fail-closed | 3a94c6c | 1 | master verifier-demo fails closed (403, @askmi/predicates) | archive/codex-verifier-privacy-fail-closed |
| backup/pre-sync-2026-05-28 | 4aede75 | 7 | WalletService decompose in master; ADR-013 rescued separately (PR #73) | archive/backup-pre-sync-2026-05-28 |
| codex/repo-local-skills-20260525 | 35a8a53 | 1 | All 8 `.agent/skills/` files present in master | archive/codex-repo-local-skills-20260525 |
| recovery/wallet-v1-rc-final | 5821d36 | 3 | Anti-fingerprinting U-22/23 in master (0b7073f); cherry=0 | archive/recovery-wallet-v1-rc-final |
| final-ai-guardian-vision | 416566a | 1 | cherry=0 (vision/pitch consolidated in master) | archive/final-ai-guardian-vision |
| rescue/second-pc-2026-06-04 | 1c40a2a | 2 | 2nd-PC safety snapshot (already rescued 2026-06-04) | archive/rescue-second-pc-2026-06-04 |

## NOT closed (intentionally kept)

| Branch | Reason |
|---|---|
| master | trunk |
| feat/controlled-insight | source for Epic 2/3 port (Sovereignty Center + VRN); closed after port lands |
| analysis/sovereignty-center-ui-only | Epic-2 prep notes; kept until port complete |
| docs/adr-013-decomposition | open PR #73 (ADR-013) |

## Separately rescued to master

- **ADR-013 WalletService Decomposition Strategy** → PR #73 (`docs/adr-013-decomposition`),
  recovered from `backup/pre-sync`, namespace `@mitch`→`@askmi`.
