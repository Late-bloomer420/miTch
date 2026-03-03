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

## Current Status (2026-03-04)

**Phase: Post-consolidation, closing P0 gaps**

This repo was consolidated from 7 separate locations on 2026-02-15. Original git histories are preserved in `archive/git-bundles/`.

### What works
- Monorepo builds and tests pass (`pnpm build && pnpm test` — run it to see current count)
- Policy engine with layer-aware rule evaluation
- SD-JWT VC credential stack
- Audit log with hash-chain integrity
- Predicate proofs (e.g., `age >= 18` without revealing DOB) — note: these are **hash-based predicate proofs**, not full zero-knowledge proofs (no snark/stark library yet)
- Crypto-shredding primitives (ephemeral key generation + destruction)
- E2E demo flow (liquor store age verification)
- Wallet PWA shell

### What's in progress (P0 gaps)
- DID resolution + signature verification (stubs only)
- Credential revocation runtime enforcement (basic deny list exists, no StatusList2021)
- Policy engine deterministic conflict resolution + deny reason codes
- Presentation binding & anti-replay (nonce TTL, canonicalization)
- eID issuer connector (stub)
- Wallet credential persistence (TODO)

### What's not done
- TEE integration
- Multi-device sync
- Quantum-ready signatures
- Production deployment / CI pipeline
- External GDPR legal opinion
- RP integration SDK

See [`docs/`](docs/) for detailed specifications and [consolidated-gaps](https://github.com/Late-bloomer420/miTch/blob/consolidation/docs/consolidated-gaps.md) for the full gap tracker (31 items, prioritized P0–P3).

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
