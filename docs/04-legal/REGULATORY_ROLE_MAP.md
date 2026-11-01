# Regulatory Role Map — AskMI

**Date:** 2026-10-27
**Status:** living document; canonical statement of regulatory roles
**Scope:** the AskMI repository and its packages, under the accepted product boundary (`docs/tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md`)
**Nature:** engineering analysis of Regulation (EU) 2024/1183 (eIDAS 2.0) and its implementing acts. **Not legal advice.** See `docs/MATURITY_AND_LIMITATIONS.md`.

---

## 1. What AskMI is not

Under the accepted product boundary, AskMI:

- is **not an EUDI Wallet Solution** under CIR 2024/2982 and is not certified under CIR 2024/2981;
- is **not an EUDI Wallet Provider** (no Member State role);
- is **not a PID/QEAA issuer or attestation provider**, qualified or non-qualified;
- is **not a Certification Authority** (no CA-replacement role);
- does **not claim EUDI certification, LoA High assurance, or conformance** of any kind.

`wallet-pwa` and `wallet-core` are a **reference wallet and integration harness** (`docs/MATURITY_AND_LIMITATIONS.md`); their existence does not make AskMI a wallet product, and they must never be documented or marketed as EUDI-certifiable in their current state (no certified WSCA/WSCD, no TEE — `docs/_core/10_KEY_PROTECTION_REALITY.md`).

## 2. What AskMI is

A policy/orchestration and protection layer deployed **inside the relying party boundary** (ADOPT-1.0): it helps a relying party create a verification session, hand the user to a wallet, verify the returned presentation, apply a registered policy, and return a minimal application decision with provenance.

eIDAS 2.0 has **no dedicated legal category** for such a layer. Obligations attach to the roles around it, and they flow through the deploying relying party. This silence is an opportunity (no certification regime applies to AskMI itself while the boundary holds) and a gap (no regulation validates the layer either).

## 3. Component → role → obligations

| Component(s) | Regulatory role touched | Obligations that flow through | Honest posture |
|---|---|---|---|
| `@askmi/connect`, `oid4vp-verifier`, `verifier-sdk`, `verifier-demo` | Relying-Party-side components (eIDAS Art. 6b(6)) | Purpose limitation, data minimization, RP identification/registration, verification of wallet authenticity and validity | AskMI's policy engine, selective-disclosure clipping, DENY-on-over-ask and consent receipts are the mechanism that makes these obligations demonstrable. The deploying RP remains the accountable party. |
| `wallet-pwa`, `wallet-core`, `secure-storage`, `webauthn-verifier` | Would fall under EUDI Wallet Solution rules **only if** offered as a wallet product | CIR 2024/2982 + 2024/2981 (certified WSCA/WSCD, notified body, LoA High-grade key protection) | **Reference harness only.** Out of certification scope; do not present as certifiable. |
| `oid4vci`, `issuer-mock`, `mock-issuer`, `eid-issuer-connector` | Would be PID/QEAA issuer roles if used against real subjects | Qualified status, notification, certification | **Demo-only.** ADOPT-1.0 explicitly excludes this role. |
| `policy-engine`, `predicates`, `layer-resolver`, `audit-log`, `data-flow`, `evidence` | No dedicated legal category; GDPR processor/controller implications | GDPR Art. 5 (minimization), Art. 17 (erasure — see crypto-shredding memo), Art. 24/25 (accountability, privacy by design) | Lowest exposure: data-minimization tooling. "DSGVO-by-Design" is an engineering analysis, not legal advice. |
| All remaining packages (crypto, types, mdoc, status list, mcp-server, demos, benchmarks, …) | Infrastructure / libraries / demo | None directly; exposed only via the products they compose into | Keep demo-only labeling per `MATURITY_AND_LIMITATIONS.md`. |

## 4. Which regulations do not apply while the boundary holds

- **CIR 2024/2981** (certification of WSCA/WSCD) — AskMI is not a wallet solution or secure component.
- **CIR 2024/2982** (wallet functionalities) — only relevant as correct *interaction with* certified wallets (RP authentication, unlinkability preservation), not as wallet obligations.
- **eIDAS wallet certification/notification machinery (Arts. 5a–9a wallet provisions)** — no notified body, no Member State notification.

## 5. Open and unresolved points (honest list)

1. **CIR 2024/2983** (verification of qualified attestations) is not mapped in this repository. It applies the moment qualified attributes are verified rather than demo credentials.
2. **WRPRC / RP registration / intended-use certificates** are not implemented (Wave-2 gap, `docs/eudi/EUDI_SOURCE_BASELINE.md`). Where a Member State register requires RP registration before wallets may present, it is a hard prerequisite for RPs deploying `@askmi/connect`.
3. **Hosted AskMI-as-intermediary** is deferred by ADOPT-1.0. An intermediary is a new role with its own obligations (ARF RP-intermediary concept, ETSI TS 119 476) and requires its own decision record before that product shape ships.
4. **Data-subject rights at the RP boundary** (access, erasure, portability requests arriving at the deploying RP) are the RP's accountability; AskMI tooling supports but does not discharge them.

## 6. Local data ownership without being a wallet

AskMI's honesty model depends on the **holder's device remaining the point of custody**, without AskMI operating a wallet product:

- credentials and keys stay with the wallet (reference harness or a national EUDI Wallet); AskMI never becomes their custodian;
- locally, the user's **own data** (audit trail, consent receipts, disclosure history — `audit-log`, `data-flow`, `evidence`) is stored on the user's side and under the user's control;
- "data ownership" here means **control and provenance over disclosures**, not acquiring new regulatory status. Owning a local record of what was shared, with whom, and under which policy is what makes applications built on AskMI truthful: they can show their users exactly what left the device.

This section states a design principle; it does not create a GDPR "controller of everything" role for AskMI. Each deployment must still determine its controller/processor split for the data it actually processes.

---

*Matrix of component implementations: `docs/compliance/EUDI_CIR_MATRIX.md`. Canonical maturity statement: `docs/MATURITY_AND_LIMITATIONS.md`.*
