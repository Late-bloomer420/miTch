# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

AskMI is a privacy-preserving proof mediation middleware ("The Forgetting Layer") — development/evaluation policy and selective-disclosure components. Use component documentation and dated QA for the affected path. docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md indexes additional scoped findings; it does not replace those sources. TypeScript monorepo with pnpm workspaces.

## Commands

```bash
# Install dependencies
pnpm install

# Build all packages (respects dependency graph)
pnpm build

# Run all tests; record exact revision/runtime/scope instead of assuming historical totals

pnpm test

# Run tests for a single package
pnpm --filter @askmi/policy-engine test

# Run a single test file
cd src/packages/policy-engine && npx vitest run src/__tests__/engine.test.ts

# Lint; do not assume the result without running and recording it
pnpm lint

# Format
pnpm format
```

**Turbo v2** is used — config uses `tasks` in `turbo.json`.

## Architecture

**Monorepo layout:** `src/packages/` (29 packages) + `src/apps/` (3 apps)

### Core packages

- **policy-engine** — The central "Privacy Firewall" / ZKQF. Evaluates disclosure requests → ALLOW/DENY/PROMPT verdicts. Contains: engine.ts (main evaluator), kpi.ts, rate-limiter.ts, proof-fatigue.ts, jurisdiction.ts, config-profiles.ts, allow-assertion.ts
- **shared-crypto** — `@askmi/shared-crypto`. All crypto primitives: key generation, signing (Ed25519/P-256), encryption (AES-256-GCM), JWE, WebAuthn, PQC (ML-DSA, ML-KEM via @noble/post-quantum), crypto-agility negotiation, pairwise DIDs, DID quorum resolution
- **shared-types** — `@askmi/shared-types`. Central type definitions shared across all packages
- **layer-resolver** — Resolves protection layers (WELT/GRUNDVERSORGUNG/VULNERABLE) and the neutral per-claim sensitivity view. Two maps: enforcement `LAYER_MAP` (`getMinimumLayerForData`) and a visibility-only `VISIBILITY_LAYER_MAP` superset (`resolveLayerForData`/`sensitivityForData`); extending the enforcement map changes policy verdicts, so visibility vocabulary stays in the superset only

### Protocol packages

- **oid4vci** — OpenID for Verifiable Credential Issuance (wallet-side)
- **oid4vp** — repository OID4VP subset; current 1.0/DCQL parity unproven; wallet-side (presentation-request, vp-token, response-builder)
- **oid4vp-verifier** — OID4VP verifier-side (request-builder, response-verifier)
- **mdoc** — ISO 18013-5 mDL/mdoc: CBOR codec, COSE Sign1, mdoc types
- **verifier-sdk** — integration helpers with explicit configuration limits; verifier-browser is an archived prototype, not an active integration

### Infrastructure packages

- **anchor-service** — Merkle batch anchoring + L2 provider stubs
- **revocation-statuslist** — `@askmi/revocation-statuslist`. StatusList2021, multi-source resolver
- **secure-storage** — IndexedDB-backed encrypted storage (uses fake-indexeddb in tests)
- **secure-memory** — owned-buffer lifecycle wrapper; runtime copies/timeout cancellation remain open
- **audit-log** — tamper-evident local helper; durable storage/sink enforcement has open findings
- **webauthn-verifier** — WebAuthn + step-up authentication
- **predicates** — Predicate proof definitions (age-over, range, set-membership)
- **wallet-core** — Core wallet logic (~700 LOC WalletService, planned for decomposition)

### Apps

- **wallet-pwa** — React 18 + Vite PWA on port 5174 (jsdom test env, needs IndexedDB + elementFromPoint mocks)
- **issuer-mock** — Mock credential issuer on port 3005
- **verifier-demo** — Demo verifier on port 3004 + frontend

## Key Conventions

- **Fail-closed requirement:** ambiguous policy should DENY. This is not proof that every active HTTP path enforces it; #170/EV-05 and documented break-glass/residual exceptions remain open.
- **DecisionCapsule fields:** `verdict`, `decision_id`, `policy_hash` (NOT `policy_manifest_id`)
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- **Code style:** Prettier (single quotes, 2-space indent, trailing commas es5, 100 print width). ESLint with `@typescript-eslint/no-explicit-any: warn`, unused vars prefixed with `_`.
- **Test framework:** Vitest. Some packages use `environment: 'node'`, wallet-pwa uses `environment: 'jsdom'` with setup files for IndexedDB mocking.
- **No breaking changes** to public package APIs without explicit approval.
- **policy-engine index.ts** has many exports — check for naming conflicts when adding new modules.
- **npm scope reality:** AskMI is the active project/package brand. All workspace packages use the `@askmi/*` scope; new packages must stay on that scope.
- **Repo truth sources:** Read `docs/DOCS_CANON.md` before updating status, backlog, QA evidence, session history, or agent-facing instructions.

## Testing Notes

- Tests include `src/__tests__/` directories within each package
- wallet-pwa tests require setup mocks: `fake-indexeddb/auto`, `document.elementFromPoint` stub, `getAll`/`getAllKeys`/`clear` for SecureStorage
- secure-storage tests use `fake-indexeddb/auto` via setup file
- Run `ASKMI_TEST_MODE=1` for test-mode-specific behavior

## CI

GitHub Actions (`.github/workflows/ci.yml`): build → test → lint on Node 22 + pnpm 9. Separate security audit job runs `pnpm audit`. Layer validation job tests policy-engine E2E scenario.

## Evidence and update discipline

Use docs/DOCS_CANON.md to locate the affected topic and its evidence before declaring implementation or closure. Specs/design acceptance are not working code. Keep dated observations with exact SHA/runtime/profile. Characterization acceptance tests reproduce findings; they are not security PASS. Refresh evidence for affected paths/profiles/dependencies; docs-only edits do not require a full repository re-audit. Broader release gates need their own broader checks. No gate moves without its linked evidence. Do not duplicate #170–#173.
