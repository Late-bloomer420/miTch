# AskMI — The Forgetting Layer

> **Privacy-preserving proof mediation for digital identity.**
> Policy-mediated disclosure: request only the attributes or proofs needed for a defined transaction.


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

**[🔴 Live Demo](https://late-bloomer420.github.io/miTch/)** — browser simulation using synthetic examples; separate from the multi-service real SD-JWT reference flow.

---

## What is AskMI?

AskMI sits between identity wallets and verifiers. When a website asks "Are you 18+?", AskMI evaluates what may be requested and disclosed. A boolean age proof is the target recipe; the real SD-JWT reference flow currently discloses numeric `age`.

- **Not a wallet** — works *with* EUDI wallets, not instead of them
- **Not a blockchain** — ephemeral keys, crypto-shredding, no on-chain PII
- **Not an identity provider** — the wallet-edge product direction avoids central identity custody; reference wallet storage and verifier data flows have separate boundaries

**Core principle:** fail-closed, deny-biased policy evaluation. Integration must enforce the resulting decision on its own request/presentation path.

---

## Integration findings — 14 October 2026

At source `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`, targeted checks reproduced request-binding/replay gaps on `/oid4vp-present` (#170) and a stored-SD-JWT single-use/UI mismatch (#171). Issuer-signature, disclosure-digest and holder-binding work remains implemented. #172 covers scoped audit-export integration; #173 covers evidence provenance and report serialization. These findings do not invalidate unrelated component tests.

See the [finding index](docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md), [dated probes](docs/qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md), and [release roadmap](docs/RELEASE_READINESS_ROADMAP.md). Accepted Connect contracts (#158–#160) are designs; the Connect package is not implemented at this baseline.

## Quick Start

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install --frozen-lockfile
pnpm dev        # wallet-pwa (5174), verifier-demo (3004), issuer-mock (3005)
```

`pnpm dev` has a dated `@askmi/poc-hardened` startup limitation; use the per-service commands in the [ADOPT live record](docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md) when applicable.

```bash
pnpm test       # record the result and revision of this run

pnpm lint       # check this checkout
pnpm build      # compile all packages
```

---

## npm Packages

AskMI is the active product/package brand. All workspace packages use the
`@askmi/*` scope.

Packages recorded as published in the repository rename notes:

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
                                     (profile-defined claims or proofs)
```

1. **Issuance** — Issuer issues credential (SD-JWT VC via OID4VCI; the reference service is a mock issuer)
2. **Storage** — Credential stored locally, AES-256-GCM encrypted
3. **Request** — Verifier asks for attributes via OID4VP
4. **Mediation** — Policy Engine evaluates: what's asked vs. what's allowed
5. **Proof** — Policy-selected claims or results leave the device; signature and binding requirements depend on the selected path
6. **Shredding** — Applicable ephemeral key/buffer material is cleaned up; verifier retention is a separate responsibility

---

## Architecture

pnpm monorepo (Turborepo) — **29 packages, 3 apps**.


### Core

| Package | Purpose |
|---|---|
| `@askmi/policy-engine` | Fail-closed rule evaluator · 31+ deny codes |
| `@askmi/shared-crypto` | ECDSA · AES-256-GCM · HKDF · SD-JWT · pairwise DIDs · PQC (ML-DSA, ML-KEM) |
| `@askmi/predicates` | Locally evaluated, signed predicates (`isOver18`, `isStudent`, …); not an issuer-authenticated ZK proof |
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
| `@askmi/audit-log` | Append-only hash/signature-chain audit helpers; storage durability is deployment-specific |
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
| **Fail-Closed** | Policy deny paths have scoped tests; HTTP session/eligibility integration is tracked in #170 |
| **Unlinkability** | Pairwise-DID helpers reduce identifier correlation; credential/network correlation is separate |
| **Data Minimization** | Policy-selected disclosure; numeric age is shared by the real SD-JWT demo |
| **Crypto-Shredding** | Owned-buffer cleanup; single-use on the stored-SD-JWT path is tracked in #171 |
| **WORM Audit** | Integrity-chained, user-readable local records; external export has its own schema |
| **Passkey-First** | WebAuthn-based onboarding/unlock; authenticator and fallback behavior are configuration-dependent |
| **Zero Identity Custody** | Wallet-edge design goal; verifier receipt of disclosed attributes and retention remain explicit data flows |

---

## Compliance

| Standard | Status |
|---|---|
| **GDPR Art. 25** | Privacy by Design — data minimization by construction |
| **GDPR Art. 32** | WORM audit log, AES-256-GCM at rest |
| **eIDAS 2.0 / EUDI** | OID4VP + OID4VCI + SIOPv2 + DPoP + HAIP |
| **CIR (Implementing Regulation)** | Detailed component mapping ([matrix](docs/compliance/EUDI_CIR_MATRIX.md)); no certification percentage |
| **EHDS** | Break-glass WebAuthn step-up for health data |

---

## Use Cases

- **🍺 Age Verification** — Age-policy recipe; real SD-JWT demo shares numeric age
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
