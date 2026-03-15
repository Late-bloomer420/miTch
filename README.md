# miTch — The Forgetting Layer

> **Privacy-preserving proof mediation for digital identity.**
> Verifiers get cryptographic proofs. Never raw data. Never PII.

[![Tests](https://img.shields.io/badge/tests-1411%20passing-brightgreen)](https://github.com/Late-bloomer420/miTch/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GDPR Art. 25](https://img.shields.io/badge/GDPR-Art.%2025%20by%20Design-blue)](docs/ops/EVIDENCE_PACK_P0.md)
[![eIDAS 2.0](https://img.shields.io/badge/eIDAS%202.0-compatible-blue)](docs/compliance)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

**[🔴 Live Demo](https://late-bloomer420.github.io/miTch/)** — no server, no data collection, runs entirely in your browser.

---

## What is miTch?

miTch sits between identity wallets and verifiers. When a website asks "Are you 18+?", miTch ensures they get a **yes/no proof** — not your name, birthday, or address.

- **Not a wallet** — works *with* EUDI wallets, not instead of them
- **Not a blockchain** — ephemeral keys, crypto-shredding, no on-chain PII
- **Not an identity provider** — miTch never sees or stores your identity

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
pnpm test       # 1411+ tests across 26 packages
pnpm lint       # 0 errors
pnpm build      # compile all packages
```

---

## How It Works

```
Issuer (eID/gov)  →  Wallet (Edge)  →  miTch Policy Engine  →  Verifier (shop/hospital)
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

pnpm monorepo (Turborepo) — **26 packages, 3 apps**.

### Core

| Package | Purpose |
|---|---|
| `@mitch/policy-engine` | Fail-closed rule evaluator · 31+ deny codes |
| `@mitch/shared-crypto` | ECDSA · AES-256-GCM · HKDF · SD-JWT · pairwise DIDs · PQC (ML-DSA, ML-KEM) |
| `@mitch/predicates` | ZK-style predicates (`isOver18`, `isStudent`, …) |
| `@mitch/shared-types` | Shared TypeScript types across all packages |

### Protocol

| Package | Purpose |
|---|---|
| `@mitch/oid4vci` | OpenID for Verifiable Credential Issuance |
| `@mitch/oid4vp` | OpenID for Verifiable Presentations + SIOPv2 |
| `@mitch/oid4vp-verifier` | Verifier-side OID4VP request handling |
| `@mitch/mdoc` | ISO 18013-5 mDL/mdoc: CBOR codec, COSE Sign1 |
| `@mitch/verifier-sdk` | Server SDK: decrypt · verify · replay-check |
| `@mitch/verifier-browser` | Browser-side verifier integration |

### Storage & Security

| Package | Purpose |
|---|---|
| `@mitch/secure-storage` | AES-256-GCM credential store (IndexedDB) |
| `@mitch/secure-memory` | Secure in-memory key handling |
| `@mitch/wallet-core` | Wallet logic + CRDT multi-device sync |
| `@mitch/webauthn-verifier` | WebAuthn step-up authentication |
| `@mitch/audit-log` | WORM append-only audit log (GDPR Art. 32) |
| `@mitch/revocation-statuslist` | StatusList2021 — fail-closed revocation |
| `@mitch/anchor-service` | Merkle batch anchoring + L2 stubs |

### Identity & Compliance

| Package | Purpose |
|---|---|
| `@mitch/eid-issuer-connector` | eID/ID Austria bridge for credential issuance |
| `@mitch/layer-resolver` | DID + layer resolution |
| `@mitch/phase0-security` | Security hardening patterns |

### Demos & Testing

| Package | Purpose |
|---|---|
| `@mitch/poc-hardened` | Hardened proof-of-concept (standalone demo) |
| `@mitch/demo-liquor-store` | Age verification demo scenario |
| `@mitch/benchmarks` | Performance benchmarks |
| `@mitch/integration-tests` | Cross-package integration tests |
| `@mitch/mock-issuer` | Mock credential issuer for testing |
| `@mitch/secure-ui-test` | UI security testing |

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
| **Replay Protection** | Nonce + decision_id + verifier_did AAD binding |
| **Zero Identity Custody** | No PII on any server — infrastructure is blind |

---

## Compliance

| Standard | Status |
|---|---|
| **GDPR Art. 25** | Privacy by Design — data minimization by construction |
| **GDPR Art. 32** | WORM audit log, AES-256-GCM at rest |
| **eIDAS 2.0 / EUDI** | OID4VP + OID4VCI + SIOPv2 + DPoP + HAIP |
| **CIR (Implementing Regulation)** | 82% compliant ([matrix](docs/compliance/EUDI_CIR_MATRIX.md)) |
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
| Backlog | [docs/BACKLOG.md](docs/BACKLOG.md) |

---

## License

[Apache 2.0](LICENSE) — **Maintainer:** [@Late-bloomer420](https://github.com/Late-bloomer420)
