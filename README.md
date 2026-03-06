# miTch — The Forgetting Layer

[![Tests](https://img.shields.io/badge/tests-845%2B%20passing-brightgreen)](https://github.com/Late-bloomer420/miTch/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GDPR](https://img.shields.io/badge/GDPR-Art.%2025%20compliant-blue)](docs/ops/EVIDENCE_PACK_P0.md)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

Privacy-preserving compliance middleware for digital identity wallets. Verifiers receive minimal cryptographic proofs instead of raw PII. Ephemeral keys are destroyed after each transaction (crypto-shredding). The system is **fail-closed** and deny-biased: ambiguity → deny.

**[Live Demo](https://late-bloomer420.github.io/miTch/)** — no server, no data collection, runs entirely in your browser.

---

## Quick Start

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install
pnpm dev        # starts wallet-pwa (5174), verifier-demo (3004), issuer-mock (3005)
```

```bash
pnpm test       # 845+ tests, 38/38 turbo tasks
pnpm lint       # 0 errors, 0 warnings
pnpm build      # compile all packages
```

---

## How It Works

```
Issuer (eID/gov)  →  Wallet (Edge)  →  Verifier (shop/hospital)
                         ↑
                    Policy Engine
                    (Fail-Closed)
```

1. **Issuance** — Government issues credential once (SD-JWT VC, OID4VCI)
2. **Storage** — Credential stored locally, AES-256-GCM encrypted (never leaves device)
3. **Presentation** — Policy Engine evaluates request; if allowed, generates minimal proof
4. **Proof** — ECDSA-signed, AAD-bound, RSA-OAEP wrapped, delivered via OID4VP
5. **Shredding** — Ephemeral keys destroyed; verifier has proof, no PII

---

## Architecture

pnpm monorepo (Turborepo) — 22 packages + 3 apps.

| Package | Purpose |
|---|---|
| `@mitch/shared-crypto` | ECDSA · AES-256-GCM · HKDF · pairwise DID derivation |
| `@mitch/policy-engine` | Fail-closed rule evaluator · 31+ deny reason codes |
| `@mitch/predicates` | ZK-style predicates (isOver18, hasLicense, …) |
| `@mitch/verifier-sdk` | Server-side: decrypt · verify · replay-check |
| `@mitch/oid4vci` | OpenID for Verifiable Credential Issuance |
| `@mitch/secure-storage` | AES-256-GCM credential store (IndexedDB) |
| `@mitch/audit-log` | WORM append-only audit log (GDPR Art. 32) |
| `@mitch/anchor-service` | Merkle batch anchoring + L2 stubs |
| `@mitch/revocation-statuslist` | StatusList2021 — fail-closed revocation check |

Apps: `wallet-pwa` (React PWA) · `verifier-demo` (Express API + frontend) · `issuer-mock` (OID4VCI server)

Full diagram: [docs/presentation/ARCHITECTURE.md](docs/presentation/ARCHITECTURE.md)

---

## Key Properties

| Property | Implementation |
|---|---|
| Fail-Closed | Every ambiguous state → DENY (no silent allow) |
| Unlinkability | HKDF pairwise DIDs per verifier session (Spec 111) |
| Data Minimization | Only proven claims leave the device, never raw attributes |
| WORM Audit | Append-only IndexedDB log, integrity-chained |
| Replay Protection | Nonce + decision_id + verifier_did AAD binding |
| Zero Identity Custody | No PII on any server — miTch infrastructure is blind |

---

## Compliance

- **GDPR Art. 25** — Privacy by Design, Data Minimization by Construction
- **GDPR Art. 32** — WORM audit log, AES-256-GCM at rest
- **eIDAS 2.0 / EUDI Wallet** — OID4VP + OID4VCI protocol stack
- **EHDS** — Break-glass WebAuthn step-up for health data (Art. 9 GDPR)

---

## Docs

| Document | Link |
|---|---|
| Architecture Diagrams | [docs/presentation/ARCHITECTURE.md](docs/presentation/ARCHITECTURE.md) |
| Presentation Outline | [docs/presentation/OUTLINE.md](docs/presentation/OUTLINE.md) |
| Demo Script | [docs/presentation/DEMO_SCRIPT.md](docs/presentation/DEMO_SCRIPT.md) |
| P0 Evidence Pack | [docs/ops/EVIDENCE_PACK_P0.md](docs/ops/EVIDENCE_PACK_P0.md) |
| Pilot Dry Run | [docs/pilot/PILOT_DRY_RUN_01.md](docs/pilot/PILOT_DRY_RUN_01.md) |
| Master Backlog | [docs/BACKLOG.md](docs/BACKLOG.md) |
| Unlinkability Spec 111 | [docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md](docs/specs/111_Unlinkability_Phase1_Pairwise_Ephemeral_DIDs.md) |

---

## License

[MIT](LICENSE) — **Maintainer:** [@Late-bloomer420](https://github.com/Late-bloomer420)
