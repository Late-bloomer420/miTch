# miTch — The Forgetting Layer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

miTch is **privacy-preserving compliance middleware** — a proof mediation layer where verifiers receive minimal cryptographic proofs instead of raw PII. Data is encrypted with ephemeral keys that are destroyed after each transaction (crypto-shredding), so forgetting is structural, not optional. The system is fail-closed and deny-biased: if anything is ambiguous, access is denied.

---

## Architecture

miTch is a **pnpm monorepo** (Turborepo) with **22 packages + 3 apps = 25 workspaces**.

```
miTch/
├── docs/                          # Specifications & design docs
│   ├── 00-welt/                  # Layer 0: Universal principles
│   ├── 01-grundversorgung/       # Layer 1: Children + essential services
│   ├── 02-erwachsene-vulnerable/ # Layer 2: Health, elderly, finance
│   ├── 03-architecture/          # Technical architecture & ADRs
│   ├── 04-legal/                 # GDPR, compliance
│   └── 05-business/              # Business model
├── src/
│   ├── apps/                     # 3 applications
│   │   ├── wallet-pwa/          # Holder wallet (Vite PWA)
│   │   ├── issuer-mock/         # Mock credential issuer
│   │   └── verifier-demo/       # Demo verifier service
│   └── packages/                 # 22 library packages
└── archive/                      # Historical repos & prototypes
```

### Protection Layers

Higher layers inherit all protections from lower layers:

| Layer | Name | Scope |
|-------|------|-------|
| 0 | WELT | Universal principles, non-linkability, data minimization |
| 1 | GRUNDVERSORGUNG | Children + essential services, mandatory crypto-shredding |
| 2 | ERWACHSENE-VULNERABLE | Health, finance, elderly — GDPR Art. 9 |

### Packages

**Core (depended on by most other packages):**
| Package | Purpose |
|---------|---------|
| `@mitch/shared-types` | Shared TypeScript types (12 dependents) |
| `@mitch/shared-crypto` | Cryptographic primitives, ephemeral keys |

**Mid-level:**
| Package | Purpose |
|---------|---------|
| `@mitch/policy-engine` | Rule-based policy evaluation, layer enforcement |
| `@mitch/audit-log` | Immutable hash-chain audit log |
| `@mitch/predicates` | Predicate evaluation (e.g., age >= 18) |
| `@mitch/secure-storage` | Encrypted credential storage |
| `@mitch/layer-resolver` | Protection layer resolution |
| `@mitch/mock-issuer` | Mock credential issuer library |
| `@mitch/verifier-sdk` | Server-side verifier library |
| `@mitch/verifier-browser` | Client-side verifier (zero-backend) |
| `@mitch/oid4vci` | OpenID for Verifiable Credential Issuance |
| `@mitch/anchor-service` | Merkle/blockchain anchor (stubs) |

**Standalone / experimental:**
| Package | Purpose |
|---------|---------|
| `@mitch/eid-issuer-connector` | eID/eIDAS issuer integration (stub) |
| `@mitch/revocation-statuslist` | StatusList2021 revocation (early) |
| `@mitch/webauthn-verifier` | WebAuthn step-up authentication |
| `@mitch/secure-memory` | Secure memory handling |
| `@mitch/phase0-security` | Security hardening experiments |
| `@mitch/poc-hardened` | Hardened proof-of-concept server |

**Test & tooling:**
| Package | Purpose |
|---------|---------|
| `@mitch/integration-tests` | Cross-package integration tests |
| `@mitch/benchmarks` | Performance benchmarks |
| `@mitch/demo-liquor-store` | E2E demo: age-gated purchase |
| `@mitch/secure-ui-test` | UI security testing |

---

## Getting Started

**Prerequisites:** Node.js 18+, pnpm 9.0.0+

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install
pnpm build
pnpm test
```

Other commands:
```bash
pnpm dev:wallet    # Run wallet PWA in dev mode
pnpm lint          # Lint all packages
pnpm format        # Format with Prettier
pnpm clean         # Clean build artifacts
```

---

## Fail-Closed Golden Tests (Merge-Blocking)

The `test:golden` script runs fail-closed regression tests that enforce three invariants:

1. **Unknown verifier / DID resolution fails → DENY**
2. **Revocation status unknown/unreachable → DENY** (for configured risk layers)
3. **Policy ambiguity / purpose mismatch → DENY or PROMPT, never ALLOW**

These tests are **merge-blocking** in CI. A refactor that reintroduces an "ALLOW on failure" bug will fail the build immediately.

```bash
pnpm test:golden
```

Includes a specific regression test for the 2026-03-03 bug where StatusList fetch failure returned ALLOW instead of DENY.

---

## Current Status (2026-03-04)

**Single source of truth:**
- P0 evidence and closure status: [`docs/ops/EVIDENCE_PACK_P0.md`](docs/ops/EVIDENCE_PACK_P0.md)
- Latest pilot dry run record: [`docs/pilot/PILOT_DRY_RUN_01.md`](docs/pilot/PILOT_DRY_RUN_01.md)

**Pilot path (fixed minimal scenario):**
- **Altersverifikation (18+)** as the single validation use-case for current pilot execution.

See docs canon map: [`docs/DOCS_CANON.md`](docs/DOCS_CANON.md).

---

## Key Design Principles

1. **Fail-closed** — ambiguity → deny
2. **Rule over authority** — trust from rules, not central power
3. **Data minimization by construction** — built-in, not bolted-on
4. **User sovereignty** — user controls all data releases
5. **No central identity custody** — ever

---

## License

[MIT](LICENSE)

---

**Maintainer:** [@Late-bloomer420](https://github.com/Late-bloomer420)
