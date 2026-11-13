# @askmi/poc-hardened — Reference / NOT production

> **Status: reference implementation. Kept intentionally. Not part of the
> production system, not part of the evidence chain, excluded from CI.**

This package is the original **self-contained, "hardened" proof-of-concept** of
the miTch verifier flow — the "proof box" in which the security properties
(anti-replay, fail-closed, rate-limiting, audit integrity, crypto-shredding)
were exercised end-to-end and **under simulated attack** before the production
system was split into the composable packages we ship today.

## Why it is kept

- **Attack simulator:** `swarm:test` floods the verifier and proves that
  rate-limiting + fail-closed hold. This harness is worth keeping as a
  benchmark / regression reference — it is not trivial to rebuild.
- **Security KPI tooling:** `kpi:check`, `evidence`.
- Historical reference for how the flow looked before decomposition
  (note the older `…V0` type world: `VerificationRequestV0`, `PolicyManifestV0`).

## What it is NOT

- **Not imported by any app or package.** Nothing depends on
  `@askmi/poc-hardened`. Its useful logic (proof-fatigue, rate-limiter,
  nonce-store, audit-log, RoPA) was **re-implemented** in the production
  packages — see `// Mirrors poc-hardened …` comments there.
- **Not an evidence source.** All threat-model / compliance / claim-evidence
  references point at the **live** packages (`shared-crypto`, `audit-log`,
  `policy-engine`), never at this PoC. "Green in poc-hardened" ≠ "production is
  secure" — it tests the older `V0` code.
- **Not in CI.** Excluded from `pnpm build` / `pnpm test` / `pnpm lint`
  (turbo `--filter=!@askmi/poc-hardened`) so it does not burn CI time or get
  confused with production coverage.

## Production equivalents (where the logic actually lives now)

| PoC area (`src/…`)             | Production home                                  |
| ------------------------------ | ------------------------------------------------ |
| `binding/` nonce/anti-replay   | `@askmi/shared-crypto` (`nonce-store.ts`, `validateBinding`) |
| `audit/` log + verify          | `@askmi/audit-log` (`index.ts`, `verify.ts`)     |
| `audit/ropa.ts` (Art. 30 RoPA) | `@askmi/policy-engine` (`audit-export-schema.ts`) |
| `api/` proof-fatigue, rate-limit | `@askmi/policy-engine`                          |

## Running it on demand

Everything still works when invoked explicitly (it is only excluded from the
aggregate pipelines, its own scripts are intact):

```bash
pnpm --filter @askmi/poc-hardened test        # PoC vitest suite
pnpm --filter @askmi/poc-hardened swarm:test  # attack simulator
pnpm --filter @askmi/poc-hardened kpi:check   # security KPIs
```

> The former `src/poc-web/standalone.html` (the published GitHub Pages landing
> page) was decoupled out of this package into the repo-root `site/` directory;
> Pages no longer builds from here.
