# AskMI — privacy-preserving identity mediation

AskMI is an open-source, research-stage middleware project for minimizing identity disclosure. It evaluates verifier requests at the wallet edge, applies deny-biased policy, and supports selectively disclosed credential presentations.

> **Maturity:** development and evaluation software. AskMI is not certified, independently audited, or represented as production-ready. See [Maturity and known limitations](docs/MATURITY_AND_LIMITATIONS.md).

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

**[Browser demo](https://late-bloomer420.github.io/miTch/)** — a self-contained demonstration, not a hosted production service or interoperability certification.

## What AskMI is

AskMI is middleware intended to sit between a compatible identity wallet and a verifier. For a request such as “Are you 18+?”, its goal is to authorize and disclose the minimum sufficient proof rather than unrelated identity attributes.

- **Middleware, not an identity provider:** AskMI does not issue authoritative identities.
- **Designed for wallet integration:** the reusable policy, protocol, cryptographic, verifier, and audit packages are the product direction.
- **Includes an embedded reference wallet:** `wallet-pwa` exercises those packages and demonstrates end-to-end flows. It is a development/reference application, not an EUDI Wallet implementation approved for deployment.
- **No blockchain dependency:** the demonstrated paths do not require putting personal data on-chain.

The implementation follows a fail-closed design intent: evaluated ambiguous or invalid states should be denied. This is covered by repository tests for specific paths, but is not a guarantee that every integration or runtime state fails closed.

## Quick start

Prerequisites: a current Node.js release and pnpm.

```bash
git clone https://github.com/Late-bloomer420/miTch.git
cd miTch
pnpm install
pnpm dev
```

The development command starts the reference wallet, verifier demo, and mock issuer. These components use local/demo trust material and are for evaluation.

```bash
pnpm test
pnpm lint
pnpm build
pnpm guard:rebrand
```

Test totals change as the repository evolves; use the command output and dated records under [`docs/qa/`](docs/qa/) rather than a static badge as evidence.

## Implemented surface

The monorepo contains working TypeScript packages and automated tests for areas including:

- deny-biased policy evaluation and decision reason codes;
- SD-JWT VC / OID4VCI issuance and OID4VP presentation paths;
- selective disclosure, replay checks, revocation/status handling, and audit/data-flow views;
- cryptographic and secure-storage building blocks;
- mdoc/ISO 18013-5 building blocks and offline verification paths;
- verifier SDK/browser integration and an MCP adapter;
- a reference wallet, mock issuer, verifier, integration tests, and scenario demos.

“Implemented” means code exists in this repository. “Tested” means repository-controlled automated tests cover specified behavior. Neither implies external conformance, security assurance, operational readiness, or complete standards support. Package-level details are best read with their tests and current source.

## Maturity labels

| Label | Meaning |
|---|---|
| **Implemented / repository-tested** | Present in code and covered by local or CI tests for documented cases. |
| **Demo-only** | Scenario, fixture, mock service, local trust setup, or reference UI used to exercise the system. |
| **Experimental** | Implemented exploration whose API, security properties, or interoperability may change. |
| **Planned** | Design, backlog, or roadmap material; do not infer implementation. |
| **Externally unvalidated** | Not independently audited, certified, formally evaluated, or proven interoperable with production EUDI ecosystems. This applies to the repository as a whole. |

See [`docs/MATURITY_AND_LIMITATIONS.md`](docs/MATURITY_AND_LIMITATIONS.md) before relying on any feature or compliance mapping.

## Naming

- **AskMI** is the canonical product and active package brand.
- **`miTch`** is the historical GitHub repository/directory name and remains in clone URLs and legacy archival material.
- Active workspace packages use the **`@askmi/*`** scope. Only packages explicitly listed in [`docs/NPM_SCOPE_RENAME_ASKMI.md`](docs/NPM_SCOPE_RENAME_ASKMI.md) should be assumed published.
- Historical documents may use “miTch”; that does not define the current product name or prove that their status claims remain current.

## Architecture at a glance

```text
Issuer / credential source
          |
          v
Compatible wallet + AskMI mediation at the edge
  - request parsing
  - policy evaluation
  - user consent / step-up where configured
  - selective presentation
          |
          v
Verifier integration
```

The repository’s `wallet-pwa`, `issuer-mock`, and `verifier-demo` form an embedded reference environment around the middleware. Real deployments would need their own wallet integration, issuer and verifier trust configuration, key management, privacy analysis, operations, and assurance work.

## Standards and compliance positioning

The repository contains implementations and mappings related to GDPR privacy/security principles, OID4VCI, OID4VP/SIOPv2, SD-JWT VC, WebAuthn, StatusList2021, and ISO 18013-5/mdoc.

Those artifacts are engineering inputs and internal evidence. They are **not** legal advice, certification, a declaration of full conformance, or proof of regulatory compliance. Percentage-based compliance scores in historical documents are internal mapping snapshots, not externally validated measurements. Formal evaluation and ecosystem interoperability remain outstanding.

## Documentation

- [Documentation index and authority rules](docs/README.md)
- [Maturity, limitations, and claim interpretation](docs/MATURITY_AND_LIMITATIONS.md)
- [Architecture](docs/presentation/ARCHITECTURE.md)
- [Demo script](docs/presentation/DEMO_SCRIPT.md)
- [QA evidence records](docs/qa/README.md)
- [Security residuals](docs/security/RESIDUALS.md)
- [Backlog](docs/BACKLOG.md)

## License

[Apache 2.0](LICENSE) — Maintainer: [@Late-bloomer420](https://github.com/Late-bloomer420)
