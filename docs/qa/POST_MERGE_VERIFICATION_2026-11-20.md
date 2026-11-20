# Post-merge verification — 2026-11-20 (master after the 10-PR merge session)

> **Role:** dated evidence record for the operational state after merging #165, #178,
> #249, #265, #266, #301, #302, #304, #308, #309, #311. Supplements, does not replace,
> per-PR CI evidence (all green except `Entire Gates`, which fails because Entire has
> no credits and does not block merges).

| Field | Value |
|---|---|
| Date | 2026-11-20 |
| Base revision | `ab72eb7fbdad080506b259e774abfdd03ee43d40` (master after #311) |
| Runtime | Node v24.16.0, pnpm 10.x (sandbox `pnpm.CMD`), Windows, ASKMI_TEST_MODE=1 |
| Scope | local full-graph runs on this machine; CI remains the authoritative cross-platform signal |

## Results

| Run | Result |
|---|---|
| `pnpm lint` | 13/13 turbo tasks successful, 0 errors, 7 pre-existing `no-explicit-any` warnings, 26.6 s |
| `ASKMI_TEST_MODE=1 pnpm test` (warm) | 49/49 tasks, FULL TURBO (cached) |
| `ASKMI_TEST_MODE=1 pnpm --filter @askmi/audit-log exec vitest run` | 6 files, 34/34 passed (verifies #301 / L2A-04: fallback receipts `network: 'mock'`, `status: 'mocked'`) |
| `turbo run test --force` (cold) | fails only in `@askmi/evidence#test`: 8 runner tests spawn real `pnpm` via `npm_execpath` and fail in this sandbox because pnpm resolves to `C:\Users\Lenovo\Desktop\pnpm\pnpm.CMD`; the same package's CI jobs are green on ubuntu-latest and windows-latest at this revision, so this is environmental, not a regression |

## Notes / limits

- The cold-run `@askmi/evidence` failure is recorded as environmental (sandbox pnpm path),
  not a code defect; CI at `ab72eb7` is green for `Evidence (ubuntu-latest)` and
  `Evidence (windows-latest)`.
- `Entire Gates` check: `failure` on every PR since Entire ran out of credits; non-blocking
  (all 11 merges in this session succeeded with it red). Re-check once credits are restored.
- #296 close was proposed in issue comment `7032389824` (owner confirmation pending).
- No release or pilot gate moves.
