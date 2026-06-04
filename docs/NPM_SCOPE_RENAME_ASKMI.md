# AskMI Rebrand and npm Scope Alignment

**Date:** 2026-06-04
**Branch:** `chore/full-askmi-rebrand`
**Status:** in progress

## Decision

The repository now uses **AskMI** as the active product/package brand and
`@askmi/*` as the single workspace package scope.

Earlier work intentionally limited `@askmi/*` to the three packages that were
already published on npm. That partial state is retired: all internal workspace
packages, imports, aliases, pnpm lock entries, demo scripts, and app-level
runtime identifiers now align on `@askmi/*`.

## Runtime Naming

The active demo identifiers use AskMI names:

- Local trust/demo domains: `*.askmi.demo`
- Demo DIDs: `did:askmi:*`
- Primary environment variables: `ASKMI_*`
- Browser bridge messages: `ASKMI_*`

Where practical, runtime code still accepts legacy `MITCH_*` environment
variables or popup messages as compatibility fallbacks. New code should use
`ASKMI_*`.

## Historical References

Archived migration logs, old evidence, and historical context may still mention
`miTch`, `@mitch/*`, or old domains when they are recording what happened at the
time. Active source, package metadata, test fixtures, and current agent-facing
instructions should use AskMI.

## Verification Checklist

- `rg '@mitch/' . --glob '!node_modules/**' --glob '!dist/**'`
- `pnpm install --lockfile-only`
- `pnpm --filter @askmi/oid4vp test`
- `pnpm --filter verifier-backend test`
- `pnpm --filter @askmi/wallet-pwa test`
- `pnpm --filter @askmi/issuer-mock test`
- `pnpm --filter @askmi/oid4vp build`
- `pnpm --filter verifier-backend build`
- `pnpm --filter @askmi/wallet-pwa build`
