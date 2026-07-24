# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

miTch is a privacy-preserving proof mediation middleware ("The Forgetting Layer") — ZK-style credential verification with crypto-shredding, fail-closed policy engine, GDPR Art. 25 + eIDAS 2.0 / EUDI compatible. TypeScript monorepo with pnpm workspaces.

## Commands

```bash
# Install dependencies
pnpm install

# Build all packages (respects dependency graph)
pnpm build

# Run all tests (1664 individual tests across 44 turbo tasks)

pnpm test

# Run tests for a single package
pnpm --filter @mitch/policy-engine test

# Run a single test file
cd src/packages/policy-engine && npx vitest run src/__tests__/engine.test.ts

# Lint (0 errors, 0 warnings)
pnpm lint

# Format
pnpm format
```

**Turbo v2** is used — config uses `tasks` in `turbo.json`.

## Architecture

**Monorepo layout:** `src/packages/` (28 packages) + `src/apps/` (3 apps)

### Core packages

- **policy-engine** — The central "Privacy Firewall" / ZKQF. Evaluates disclosure requests → ALLOW/DENY/PROMPT verdicts. Contains: engine.ts (main evaluator), kpi.ts, rate-limiter.ts, proof-fatigue.ts, jurisdiction.ts, config-profiles.ts, allow-assertion.ts
- **shared-crypto** — All crypto primitives: key generation, signing (Ed25519/P-256), encryption (AES-256-GCM), JWE, WebAuthn, PQC (ML-DSA, ML-KEM via @noble/post-quantum), crypto-agility negotiation, pairwise DIDs, DID quorum resolution
- **shared-types** — Central type definitions shared across all packages
- **layer-resolver** — Resolves trust layers and credential schemas

### Protocol packages

- **oid4vci** — OpenID for Verifiable Credential Issuance (wallet-side)
- **oid4vp** — OID4VP 1.0 wallet-side (presentation-request, vp-token, response-builder)
- **oid4vp-verifier** — OID4VP verifier-side (request-builder, response-verifier)
- **mdoc** — ISO 18013-5 mDL/mdoc: CBOR codec, COSE Sign1, mdoc types
- **verifier-sdk** / **verifier-browser** — Verifier integration libraries

### Infrastructure packages

- **anchor-service** — Merkle batch anchoring + L2 provider stubs
- **revocation-statuslist** — StatusList2021, multi-source resolver
- **secure-storage** — IndexedDB-backed encrypted storage (uses fake-indexeddb in tests)
- **secure-memory** — Memory-safe credential handling
- **audit-log** — Immutable audit trail
- **webauthn-verifier** — WebAuthn + step-up authentication
- **predicates** — Predicate proof definitions (age-over, range, set-membership)
- **wallet-core** — Core wallet logic (~700 LOC WalletService, planned for decomposition)

### Apps

- **wallet-pwa** — React 18 + Vite PWA on port 5174 (jsdom test env, needs IndexedDB + elementFromPoint mocks)
- **issuer-mock** — Mock credential issuer on port 3005
- **verifier-demo** — Demo verifier on port 3004 + frontend

## Key Conventions

- **Fail-closed principle:** Ambiguous policy evaluations → DENY. Never default to ALLOW.
- **DecisionCapsule fields:** `verdict`, `decision_id`, `policy_hash` (NOT `policy_manifest_id`)
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `test:`, `chore:`
- **Code style:** Prettier (single quotes, 2-space indent, trailing commas es5, 100 print width). ESLint with `@typescript-eslint/no-explicit-any: warn`, unused vars prefixed with `_`.
- **Test framework:** Vitest. Some packages use `environment: 'node'`, wallet-pwa uses `environment: 'jsdom'` with setup files for IndexedDB mocking.
- **No breaking changes** to public package APIs without explicit approval.
- **policy-engine index.ts** has many exports — check for naming conflicts when adding new modules.

## Testing Notes

- Tests include `src/__tests__/` directories within each package
- wallet-pwa tests require setup mocks: `fake-indexeddb/auto`, `document.elementFromPoint` stub, `getAll`/`getAllKeys`/`clear` for SecureStorage
- secure-storage tests use `fake-indexeddb/auto` via setup file
- Run `MITCH_TEST_MODE=1` for test-mode-specific behavior

## CI

GitHub Actions (`.github/workflows/ci.yml`): build → test → lint on Node 22 + pnpm 9. Separate security audit job runs `pnpm audit`. Layer validation job tests policy-engine E2E scenario.

## Imported Claude Cowork project instructions

# Claude Co-Work Richtlinien für miTch

[cite_start]Du bist der dedizierte Entwicklungs-Assistent für "miTch — The Forgetting Layer"[cite: 26]. [cite_start]Das Projekt ist ein pnpm/Turborepo Monorepo mit 26 Packages und 3 Apps[cite: 34]. 

## 🚨 Kernprinzipien (Nicht verhandelbar)
1. [cite_start]Fail-Closed & Deny-Biased: Jeder unklare oder ambivalente Zustand MUSS zu einem `DENY` führen (kein stillschweigendes Erlauben)[cite: 31, 52].
2. [cite_start]Zero Identity Custody: Es werden niemals PII (personenbezogene Daten) oder rohe Attribute im Klartext auf Servern gespeichert oder übertragen[cite: 27, 53, 56].
3. [cite_start]Krypto-Sicherheit: Nutze ausschließlich die in `@mitch/shared-crypto` und `@mitch/secure-memory` definierten Primitiven (AES-256-GCM, HKDF, ECDSA)[cite: 36, 43, 58].

## 🔄 Arbeitsmodus: Der /loop Befehl
Wenn der Nutzer den Befehl `/loop` startet (oder eine Aufgabe erteilt, die mehrere iterative Schritte erfordert), folge diesem strikten Ablauf:

1. [cite_start]ANALYSE: Lies die relevanten Dateien im Monorepo (nutze die bestehende Struktur in `src/`, `docs/` oder `data/`)[cite: 14, 15, 16].
2. IMPLEMENTIERUNG: Schreibe Code modular, TypeScript-strikt und fehlerfrei.
3. [cite_start]VALIDIERUNG: Führe die Tests aus (z. B. via `pnpm test` oder spezifische Paket-Tests)[cite: 24].
4. ITERATION: Wenn Fehler auftreten, korrigiere sie selbstständig im nächsten Loop-Durchlauf, bis die Aufgabe zu 100% gelöst ist und alle Tests bestehen.

## 📁 Projekt-Architektur-Referenz für Code-Änderungen
- [cite_start]Richtlinien/Validierung: Evaluator-Regeln gehören in `@mitch/policy-engine`. [cite_start]ZK-Style Predicates in `@mitch/predicates`.
- [cite_start]Protokolle: OID4VP/VCI-Änderungen gehören in die entsprechenden `@mitch/oid4vp` oder `@mitch/oid4vci` Packages[cite: 38, 39].
- [cite_start]Storage: Sichere Lagerung erfolgt ausschließlich über `@mitch/secure-storage` (IndexedDB)[cite: 42].

## 📝 Commit- & Dokumentations-Standard
- [cite_start]Nutze Conventional Commits (z.b. `feat(security): ...`, `fix(verifier-backend): ...`, `docs(security): ...`)[cite: 15, 23].
- [cite_start]Aktualisiere nach relevanten Änderungen die `CLAUDE_TASKS.md`, `STATE.md` oder die entsprechende `ADR` in `docs/03-architecture/mvp/`[cite: 21, 63].
