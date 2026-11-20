# Security Policy

## Reporting a Vulnerability

**Please do not open public GitHub issues for security bugs.**

Report security vulnerabilities by email to **jonas.f.meyer@googlemail.com**.

Include a description of the issue, the affected component, steps to reproduce, and your assessment of impact. We will acknowledge your report within **7 business days** and aim to communicate a remediation plan or disposition within 30 days.

We operate in good faith: reporters who follow responsible-disclosure practice will not face legal action for good-faith research. We ask the same in return — no exploitation, no publication before a fix or agreed embargo date.

## Scope

This policy covers the AskMI codebase as hosted in this repository:

- `src/packages/policy-engine` — privacy-firewall / ZKQF verdict engine
- `src/packages/shared-crypto` — all cryptographic primitives (key generation, signing, encryption, WebAuthn, PQC)
- `src/packages/wallet-core` and `src/apps/wallet-pwa` — wallet credential storage and disclosure flows
- `src/packages/oid4vp`, `src/packages/oid4vp-verifier` — OID4VP presentation and verification
- `src/packages/webauthn-verifier`, `src/packages/secure-storage`, `src/packages/secure-memory`

**This is a research and pilot project, not a production service.** No real user personal data is processed. The threat model, evidence pack, and open residuals are documented in [`docs/security/`](docs/security/README.md).

Out of scope: third-party dependencies (report those upstream), the demo issuer mock, CI infrastructure.

## Known findings from external formal analysis

The OpenID Foundation published a formal security analysis of OpenID for Verifiable Credentials (University of Stuttgart, 2024-01-18): <https://openid.net/formal-security-analysis-openid-verifiable-credentials/>. The analysis is preliminary, not peer-reviewed, and based on spec versions from May 2023. It is evidence about the protocol specifications, not about this implementation.

| Finding (external) | Relevance to this repository (checked at `8dd7f3e`, 2026-11-20) | Status |
|---|---|---|
| Same-device flows proven secure in the analysed model | Scoped external evidence; no claim about this code | — |
| Cross-device flow (OID4VP) vulnerable to phishing without explicit user attention | QR/handoff paths exist (`@askmi/connect` handoff, verifier-demo QR, proximity engagement). No test models this attack; rotating-QR / number-matching measures are planned, not implemented | **Open** |
| Pre-authorized code flow (OID4VCI) vulnerable to phishing | No flow in this repository uses it; recorded as a design decision (avoid). The sibling issuer VeriCred (separate repository) does use it | Not used here; VeriCred open |

Details, evidence and source references: [ADR-009](docs/03-architecture/mvp/ADR-009_Threat_Model.md), section "Externe formale Analyse (OIDF)"; tracking in #196.

## Supported Versions

Security fixes are applied to the `master` branch only. No backport policy exists because the project has not reached a production release.

| Branch | Status |
|--------|--------|
| `master` | Supported |
| All others | Unsupported (feature / experiment branches) |
