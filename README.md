# AskMI — The Forgetting Layer

> **Privacy-preserving proof mediation for digital identity.**
> Verifiers get cryptographic proofs. Never raw data. Never PII.

[![Tests](https://img.shields.io/badge/tests-1820%20passing-brightgreen)](https://github.com/Late-bloomer420/miTch/actions)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GDPR Art. 25](https://img.shields.io/badge/GDPR-Art.%2025%20by%20Design-blue)](docs/ops/EVIDENCE_PACK_P0.md)
[![eIDAS 2.0](https://img.shields.io/badge/eIDAS%202.0-certified--ready-blue)](docs/compliance)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

**[🔴 Live Demo](https://late-bloomer420.github.io/miTch/)** — no server, no data collection, runs entirely in your browser.

---

## What is AskMI?

AskMI sits between identity wallets and verifiers. When a website asks "Are you 18+?", AskMI ensures they get a **yes/no proof** — not your name, birthday, or address.

- **Not a wallet** — works *with* EUDI wallets, not instead of them
- **Not a blockchain** — ephemeral keys, crypto-shredding, no on-chain PII
- **Not an identity provider** — AskMI never sees or stores your identity

**Core principle:** Fail-closed, deny-biased. If anything is ambiguous → **DENY**.

---

## Quick Start

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install
pnpm dev        # wallet-pwa (5174), verifier-demo (3004), issuer-mock (3005)
```

```bash
pnpm test       # 1820+ tests across 29 packages

pnpm lint       # 0 errors
pnpm build      # compile all packages
```

---

## npm Packages

AskMI is the active product/package brand. All workspace packages use the
`@askmi/*` scope.

Currently published on npm:

- `@askmi/shared-types`
- `@askmi/shared-crypto`
- `@askmi/revocation-statuslist`

See [docs/NPM_SCOPE_RENAME_ASKMI.md](docs/NPM_SCOPE_RENAME_ASKMI.md) for the
rename scope and verification notes.

---

## How It Works

```
Issuer (eID/gov)  →  Wallet (Edge)  →  AskMI Policy Engine  →  Verifier (shop/hospital)
                                            ↓
                                     Minimal Proof Only
                                     (no PII leaves device)
```

1. **Issuance** — Government issues credential (SD-JWT VC via OID4VCI)
2. **Storage** — Credential stored locally, AES-256-GCM encrypted
3. **Request** — Verifier asks for attributes via OID4VP
4. **Mediation** — Policy Engine evaluates: what's asked vs. what's allowed
5. **Proof** — Only proven claims leave the device, ECDSA-signed, AAD-bound
6. **Shredding** — Ephemeral keys destroyed. Verifier has proof, nothing else.

---

## Architecture

pnpm monorepo (Turborepo) — **29 packages, 3 apps**.


### Core

| Package | Purpose |
|---|---|
| `@askmi/policy-engine` | Fail-closed rule evaluator · 31+ deny codes |
| `@askmi/shared-crypto` | ECDSA · AES-256-GCM · HKDF · SD-JWT · pairwise DIDs · PQC (ML-DSA, ML-KEM) |
| `@askmi/predicates` | ZK-style predicates (`isOver18`, `isStudent`, …) |
| `@askmi/shared-types` | Shared TypeScript types across all packages |
| `@askmi/data-flow` | Transaction transparency · grouped audit views |

### Protocol

| Package | Purpose |
|---|---|
| `@askmi/oid4vci` | OpenID for Verifiable Credential Issuance |
| `@askmi/oid4vp` | OpenID for Verifiable Presentations + SIOPv2 |
| `@askmi/oid4vp-verifier` | Verifier-side OID4VP request handling |
| `@askmi/mdoc` | ISO 18013-5 mDL/mdoc: CBOR codec, COSE Sign1 |
| `@askmi/verifier-sdk` | Server SDK: decrypt · verify · replay-check |
| `@askmi/verifier-browser` | Browser-side verifier integration |
| `@askmi/mcp-server` | MCP interface for LLM agents (Claude Desktop) |

### Storage & Security

| Package | Purpose |
|---|---|
| `@askmi/secure-storage` | AES-256-GCM credential store (Pluggable Adapters) |
| `@askmi/secure-memory` | Secure in-memory key handling |
| `@askmi/wallet-core` | Wallet logic + CRDT multi-device sync |
| `@askmi/webauthn-verifier` | WebAuthn step-up authentication |
| `@askmi/audit-log` | WORM append-only audit log (GDPR Art. 32) |
| `@askmi/revocation-statuslist` | StatusList2021 — fail-closed revocation |
| `@askmi/anchor-service` | Merkle batch anchoring + L2 stubs |

### Identity & Compliance

| Package | Purpose |
|---|---|
| `@askmi/eid-issuer-connector` | eID/ID Austria bridge for credential issuance |
| `@askmi/layer-resolver` | DID + layer resolution |
| `@askmi/phase0-security` | Security hardening patterns |

### Demos & Testing

| Package | Purpose |
|---|---|
| `@askmi/poc-hardened` | Hardened proof-of-concept (standalone demo) |
| `@askmi/demo-liquor-store` | Age verification demo scenario |
| `@askmi/benchmarks` | Performance benchmarks |
| `@askmi/integration-tests` | Cross-package integration tests |
| `@askmi/mock-issuer` | Mock credential issuer for testing |
| `@askmi/secure-ui-test` | UI security testing |
| `@askmi/consent-ui` | Reusable consent components and flows |

**Apps:** `wallet-pwa` (React PWA) · `verifier-demo` (Express + frontend) · `issuer-mock` (OID4VCI server)

---

## Key Properties

| Property | How |
|---|---|
| **Fail-Closed** | Every ambiguous state → DENY (no silent allow) |
| **Unlinkability** | HKDF pairwise DIDs per verifier session |
| **Data Minimization** | Only proven claims leave device — never raw attributes |
| **Crypto-Shredding** | Ephemeral keys destroyed after each transaction |
| **WORM Audit** | Append-only log, integrity-chained, user-readable |
| **Passkey-First** | Biometric device binding for all identity operations |
| **Zero Identity Custody** | No PII on any server — infrastructure is blind |

---

## Compliance

| Standard | Status |
|---|---|
| **GDPR Art. 25** | Privacy by Design — data minimization by construction |
| **GDPR Art. 32** | WORM audit log, AES-256-GCM at rest |
| **eIDAS 2.0 / EUDI** | OID4VP + OID4VCI + SIOPv2 + DPoP + HAIP |
| **CIR (Implementing Regulation)** | 100% Technical ([matrix](docs/compliance/EUDI_CIR_MATRIX.md)) |
| **EHDS** | Break-glass WebAuthn step-up for health data |

---

## Use Cases

- **🍺 Age Verification** — Prove 18+ without revealing birthday
- **🎓 Student Discount** — Prove enrollment without sharing student ID
- **🏥 Health Data (EHDS)** — Emergency access with WebAuthn step-up + audit trail
- **📺 Ad-Tech Blind Provider** — Demographic verification without tracking (nullifier-based sybil protection)

---

## Docs

| Document | Link |
|---|---|
| Architecture | [docs/presentation/ARCHITECTURE.md](docs/presentation/ARCHITECTURE.md) |
| Demo Script | [docs/presentation/DEMO_SCRIPT.md](docs/presentation/DEMO_SCRIPT.md) |
| Specs (114) | [docs/specs/](docs/specs/) |
| ADRs (12) | [docs/03-architecture/mvp/](docs/03-architecture/mvp/) |
| P0 Evidence Pack | [docs/ops/EVIDENCE_PACK_P0.md](docs/ops/EVIDENCE_PACK_P0.md) |
| Compliance Matrix | [docs/compliance/EUDI_CIR_MATRIX.md](docs/compliance/EUDI_CIR_MATRIX.md) |
| Refactoring Roadmap | [docs/REFACTORING_ROADMAP.md](docs/REFACTORING_ROADMAP.md) |
| Backlog | [docs/BACKLOG.md](docs/BACKLOG.md) |

---

## License

[Apache 2.0](LICENSE) — **Maintainer:** [@Late-bloomer420](https://github.com/Late-bloomer420)
