# AskMI API & Protocol v2 Architecture Plan — 2026-11-03

**Date:** 2026-11-03  
**Baseline:** `chore/enable-entire` (`f15cf8d`)  
**Input Evidence:** [`docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](../qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md)  
**Status:** Accepted architectural direction and 4-stage execution plan (documentation & planning gate; executable code changes follow in Stages 0–3).

---

## 1. Strategic & Architectural Decisions

The following six architectural invariants govern the evolution of AskMI's APIs and packages:

1. **Open Commercial Deployment Role (Pending G0/G1 Discovery Gate `#143`):**
   - Customer and legal role validation (Relying-Party-deployed middleware vs. Registered Intermediary vs. Wallet Provider / SDK vendor) remains open pending G0/G1 discovery evidence.
   - Package boundaries must preserve all three deployment options without conflating their regulatory responsibilities under CIR (EU) 2024/2982, ETSI TS 119 475 (WRPAC/WRPRC), and CIR (EU) 2024/2981 (LoA High).
2. **Dual Wallet Strategy (`@askmi/wallet-guard` SDK + Long-Term `AskMI-Wallet` Product):**
   - **Extract `@askmi/wallet-guard`:** The portable holder-side privacy firewall (request normalization, `PolicyEngine` evaluation, claim clipping to `authorized_requirements`, single-use pool consumption `#171`, `DecisionCapsule` signing, and local tamper-evident audit logging) will be extracted from `wallet-pwa/src/services/WalletService.ts` into a standalone, embeddable `@askmi/wallet-guard` package.
   - **Retain & Evolve `wallet-pwa` (`AskMI-Wallet`):** `wallet-pwa` becomes a thin UI/platform shell over `@askmi/wallet-guard` and remains the foundation for a standalone AskMI Wallet product (with a long-term path toward native hardware-keystore integration and certification).
3. **Unified 3-Surface Northbound RP API (`@askmi/connect`):**
   - A single framework-agnostic `VerificationSessionCore` will power three northbound Relying Party integration surfaces:
     1. **Connect Session API (`/askmi/connect/sessions`):** Evolved browser session & widget API.
     2. **Headless REST API (`POST /v2/verifications`, `GET /v2/verifications/:id`, webhooks):** Stripe-style backend verification API returning minimized predicate verdicts (`{ status, claims: { age_over_18: true }, receipt }`).
     3. **OIDC-Provider-Bridge (`/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`):** Zero-code drop-in for enterprise IAMs (Keycloak, Auth0, NextAuth, Cognito) issuing pseudonymous, data-minimized ID tokens (`{ sub, age_over_18: true, acr }`).
4. **Two-Tier Southbound Wire Protocol (100% Standard Baseline + Optional `askmi_ext` Negotiation):**
   - **Mandatory Interop Baseline:** Every OpenID4VP request and response MUST be 100% compliant with standard **OpenID4VP 1.0 Final** and **W3C Digital Credentials API** (`navigator.credentials.get({ digital })`), ensuring:
     - `@askmi/connect` verifiers interoperate out-of-the-box with any third-party EUDI Wallet.
     - `@askmi/wallet-guard` and `AskMI-Wallet` interoperate out-of-the-box with any third-party EUDI Verifier.
   - **Optional AskMI-to-AskMI Extension (`askmi_ext`):** When both Verifier and Wallet run AskMI components, they optionally negotiate AskMI privacy extensions (`client_metadata.askmi_ext` in the JAR request; `askmi_capsule` in the response) to exchange verifier policy manifest hashes, privacy-budget attestations, and hardware-/passkey-signed `DecisionCapsule` receipts without breaking standard wallets or verifiers.
5. **Southbound Credential Profile Sequencing:**
   - First wire the existing canonical contract in [`src/packages/shared-types/src/contracts/claim-contract.ts`](../../src/packages/shared-types/src/contracts/claim-contract.ts) (`age_over_18`, `birthdate`) in Stage 0; select the primary production profile (`dc+sd-jwt` `urn:eudi:pid:1` vs. `mso_mdoc` `eu.europa.ec.av.1`, Issue `#97`) in Stage 1 based on G0/G1 evidence.
6. **Documentation-First Governance:**
   - Record all reproduced defects (`API-01`..`API-07`) and stage gates transparently in repository trackers before modifying executable code in `src/`.

---

## 2. Two-Tier Wire Protocol & Multi-Surface Architecture

```mermaid
flowchart TB
  subgraph RP["Relying Party"]
    IAM["Enterprise IAM (OIDC)"]
    Backend["RP Backend"]
    Browser["RP Browser Checkout"]
  end

  subgraph Connect["@askmi/connect (RP-Side Middleware)"]
    Core["VerificationSessionCore + Claim Contract v1"]
    S_OIDC["OIDC Bridge (/oauth2/*)"]
    S_REST["Headless REST (/v2/verifications)"]
    S_Sess["Connect Sessions (/askmi/connect/sessions)"]
    VP["OpenID4VP 1.0 Verifier (DCQL + JAR + direct_post.jwt)"]
    IAM --> S_OIDC --> Core
    Backend --> S_REST --> Core
    Browser --> S_Sess --> Core
    Core --> VP
  end

  subgraph Southbound["Southbound Wire Protocol"]
    Base["Tier 1 (Mandatory): Standard OpenID4VP 1.0 + W3C DC API"]
    Ext["Tier 2 (Optional): askmi_ext PolicyManifest & DecisionCapsule Negotiation"]
  end

  subgraph Holder["Holder / Wallet Side"]
    EUWallet["Third-Party EUDI Wallet"]
    Guard["@askmi/wallet-guard (Embeddable Privacy Firewall SDK)"]
    PartnerWallet["Partner Wallet embedding @askmi/wallet-guard"]
    AskMIWallet["AskMI Wallet (wallet-pwa / future Native Host)"]
    Guard --> PartnerWallet
    Guard --> AskMIWallet
  end

  VP ==> Base
  VP -.-> Ext
  Base ==> EUWallet
  Base ==> PartnerWallet
  Base ==> AskMIWallet
  Ext -.-> PartnerWallet
  Ext -.-> AskMIWallet
```

### Graceful `askmi_ext` Negotiation Rules
- **Verifier → Wallet (Request Object):**
  - Standard fields (`response_type: "vp_token"`, `client_id` with prefix, `response_mode: "direct_post.jwt"`, `response_uri`, `nonce`, `state`, `dcql_query`, `verifier_info`) strictly follow OpenID4VP 1.0 Final.
  - Optional extension field `client_metadata.askmi_ext` carries `{ version: "1.0", policy_manifest_hash, requested_attestations: ["decision_capsule_v1"] }`.
  - Standard third-party EUDI wallets ignore unknown `client_metadata` keys per RFC 7519 / OpenID4VP 1.0 and return a standard `{ vp_token, state }` response.
- **Wallet → Verifier (Response):**
  - If `@askmi/wallet-guard` detects a standard third-party verifier (no `askmi_ext`), it emits a pure standard OpenID4VP response (`{ vp_token, state }`) and stores the `DecisionCapsule` locally in the holder's audit log.
  - If `@askmi/wallet-guard` detects a valid `askmi_ext` from an AskMI verifier, it additionally attaches `askmi_capsule` (PII-free cryptographic proof of local policy evaluation and holder presence) to the encrypted `direct_post.jwt` payload.

---

## 3. Four-Stage Execution Roadmap

### Stage 0 — Security, Spec-Compliance & E2E Hardening (`API-V2-S0`)
**Goal:** Fix all reproduced security, cryptographic, and live E2E integration defects (`API-01`..`API-05`) on the existing stack before adding new protocol surfaces.

| Task ID | Scope | Target Files | Acceptance Criteria |
|---|---|---|---|
| **API-01** | Fix 4-way live browser E2E break & wire `claim-contract.ts` | `src/packages/connect/src/core/profile.ts`, `src/packages/connect/src/browser/handoff.ts`, `src/apps/wallet-pwa/src/App.tsx`, `src/apps/wallet-pwa/src/data/DemoPolicy.ts`, `src/apps/issuer-mock/src/index.ts`, `src/apps/verifier-demo/backend/src/app.ts`, `dev-demo.ps1` | 1. Connect profile uses canonical `claim-contract.ts` (`age_over_18` / `birthdate`) instead of raw `$.age`.<br>2. Handoff URL routes directly into `<WalletApp>` when `request_uri` is present.<br>3. HTTPS/HTTP & CORS origins match across `wallet-pwa`, `verifier-demo`, and `dev-demo.ps1`.<br>4. `issuer-mock` and `verifier-demo` share a consistent default `iss`.<br>5. Unmocked E2E test runs real `PolicyEngine.evaluate()` with `DemoPolicy` (no `bootstrapFetchMocks('ALLOW')` override). |
| **API-02** | Close `presentOID4VP` policy-clipping bypass | `src/apps/wallet-pwa/src/App.tsx:959-961` | `presentOID4VP` discloses only claims present in `result.decisionCapsule.authorized_requirements`; negative test proves over-asked claims in `authRequest.presentation_definition` are excluded from the SD-JWT presentation. |
| **API-03** | Enforce RFC 9901 §7.1 & mandatory KB-JWT verification | `src/packages/shared-crypto/src/sd-jwt-vc.ts`, `src/packages/oid4vp-verifier/src/response-verifier.ts` | 1. `validateSDJWTVC` enforces `typ` (`dc+sd-jwt` / `vc+sd-jwt`) and allowed `algorithms`.<br>2. `extractDisclosedClaims` rejects the presentation on any malformed or unmatched disclosure (no `continue`).<br>3. `buildSdJwtPresentation` emits `<issuerJwt>~<kbJwt>` (single `~`) when 0 disclosures are selected.<br>4. `response-verifier.ts` defaults `verifyCredentialSignatures` to `true` and rejects missing KB-JWT (`<issuerJwt>~<disc>~`) when holder binding / `expectedNonce` applies. |
| **API-04** | Fix ISO/IEC 18013-5 §9.1.3.6 `DeviceAuthenticationBytes` | `src/packages/mdoc/src/device-auth.ts` | `signDeviceAuth` and `verifyDeviceAuth` sign/verify detached payload (`payload: null`) over `Tag24(CBOR(["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]))` with empty `external_aad`; test vectors cover `OpenID4VPHandover` and `OpenID4VPDCAPIHandover`. |
| **API-05** | Fail-closed Trust List, Status List & WebAuthn Verifier | `src/packages/shared-crypto/src/trust-list-resolver.ts`, `src/packages/revocation-statuslist/src/index.ts`, `src/packages/webauthn-verifier/src/index.ts` | 1. `trust-list-resolver` never returns `verified: true` when `anchorPublicKey === null` and enforces immediate fail-closed on expired cache for `riskTier === 'high'`.<br>2. `revocation-statuslist` verifies the status list issuer signature and supports IETF `statuslist+jwt`.<br>3. `webauthn-verifier` cryptographically verifies `signedAssertion.response.signature` against `publicKeyCose`. |

---

### Stage 1 — G0/G1 Discovery Evidence & Southbound Profile Selection (`API-V2-S1`)
**Goal:** Align technical buildout with validated customer demand (`#143`) and select the primary southbound credential profile (`#97`).

- Complete G0/G1 discovery interviews (`#143`) and document the primary commercial deployment model (RP-deployed middleware vs. wallet SDK licensing vs. intermediary).
- Select the primary southbound credential format for the beachhead pilot:
  - **Option A (`dc+sd-jwt`):** `urn:eudi:pid:1` with `age_equal_or_over.18` (`nested-threshold` binding in `claim-contract.ts`).
  - **Option B (`mso_mdoc`):** EU Age Verification Profile `eu.europa.ec.av.1` (`age_over_18` boolean element, Issue `#97`).

---

### Stage 2 — `@askmi/wallet-guard` Extraction & 3-Surface RP Northbound API (`API-V2-S2`)
**Goal:** Decouple portable wallet protection logic from the PWA shell and expose all three RP integration surfaces on a shared core.

- **`@askmi/wallet-guard` Package:**
  - Extract framework-agnostic holder firewall (`evaluateIncomingRequest`, `clipDisclosuresToCapsule`, `consumeSingleUseCredential` for `#171`, `buildAskMICapsule`, `recordDisclosureAudit`) from `wallet-pwa/src/services/WalletService.ts`.
  - Refactor `wallet-pwa` to consume `@askmi/wallet-guard` while continuing to evolve `wallet-pwa` as the standalone AskMI Wallet application.
- **`@askmi/connect` Multi-Surface Northbound API:**
  - Unify session management in `VerificationSessionCore` and expose:
    1. `/askmi/connect/sessions` (Browser Session & Widget API)
    2. `/v2/verifications` (Headless REST API + signed webhook notifications)
    3. `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token` (OIDC Provider Bridge returning pseudonymous, PII-minimized claims)

---

### Stage 3 — OpenID4VP 1.0 Final, DCQL, W3C DC API, ETSI TS 119 475/602 & `askmi_ext` (`API-V2-S3`)
**Goal:** Upgrade southbound wire protocols to 2026 final EUDI specifications with optional AskMI-to-AskMI extension negotiation.

- **OpenID4VP 1.0 Final & HAIP 1.0:**
  - Implement DCQL (`dcql_query`) evaluation and `{ [queryId]: [...] }` `vp_token` map in `@askmi/oid4vp` and `@askmi/oid4vp-verifier`.
  - Replace `client_id_scheme` with Client Identifier Prefixes (`x509_san_dns:`, `x509_hash:`, `verifier_attestation:`, `redirect_uri:`), enforce `response_uri` on `direct_post.jwt`, and support `verifier_info` (WRPRC per ETSI TS 119 475).
- **W3C Digital Credentials API:**
  - Add `navigator.credentials.get({ digital: { requests: [{ protocol: 'openid4vp-v1-signed', data }] } })` as the primary same-device browser invocation path in `@askmi/connect/browser`, with cross-device QR (`openid4vp://`) and `walletBaseUrl` retained only as a developer/web-wallet fallback.
- **Optional `askmi_ext` Wire Negotiation:**
  - Implement non-breaking `askmi_ext` request/response negotiation between `@askmi/connect` and `@askmi/wallet-guard` / `AskMI-Wallet`, verified with interoperability tests proving both AskMI-to-third-party and AskMI-to-AskMI flows.
- **ETSI TS 119 602 (LoTE) & EUDI TS07/TS08:**
  - Support ETSI TS 119 602 JSON/JWS Lists of Trusted Entities in `EUDITrustListResolver` and align data-erasure / DPA-reporting helpers with EUDI TS07 and TS08.

---

## 4. Zero-Account ID Document & Photo-ID Onboarding ("Where Am I Registered?")

To achieve minimal user friction (< 15 seconds) without requiring pre-existing institutional accounts (e.g., student portals) or turning AskMI into a central PII honeypot, onboarding unifies three physical ID verification paths into a single **"Onboard Once → Passkey Vault on Device"** flow:

1. **Path 1a — PIN-Free ICAO 9303 ePassport NFC (MRZ Camera Scan + NFC Chip + Active/Chip Auth + Local Selfie Match):**
   - Many citizens do not have their 6-digit national eID PIN activated or at hand during everyday checkout flows.
   - **ePassports (ICAO Doc 9303):** Scanning the printed MRZ unlocks BAC/PACE over NFC **without requiring a 6-digit eID PIN**, reading the government-signed Document Security Object (`EF.SOD`), `DG1` (birthdate), and `DG2` (chip portrait). Note on technical boundaries:
     - **German Personalausweis (nPA) distinction:** On the German national ID card, sovereign Extended Access Control (EAC) restricts `DG2` portrait access to authorized sovereign terminals; PIN-free `DG1`/`DG2` reading applies to ICAO 9303 ePassports (while German nPA holders without an active PIN use Path 1c or PIN reset).
     - **Clone resistance:** ICAO Passive Authentication (`EF.SOD` CSCA/DS signature check) proves issuer data integrity, whereas **Chip Authentication (`DG14`) or Active Authentication (`DG15`)** is required to verify that the NFC chip itself was not cloned.
   - Matching a live selfie against the authenticated ePassport `DG2` portrait yields hardware-bound credential bootstrap with cryptographic document-signer provenance and zero PIN friction.
2. **Path 1b — Classic eID with 6-Digit PIN / Existing EUDI PID:**
   - Direct eID NFC authentication (e.g., German nPA with 6-digit PIN) or PID credential import for users who already use an activated national eID PIN or state EUDI Wallet.
3. **Path 1c — Optical Photo-ID + Liveness Fallback:**
   - Camera-based document + liveness verification for national ID cards without PIN/ePassport or devices without NFC, explicitly tagged in credential metadata and UI with its distinct assurance level (`LoA Substantial/Low` rather than `LoA High`, preserving the honest assurance boundaries of `#174`/`#176`).
4. **"Where Am I Registered?" — On-Device Passkey Account + Zero-Retention Blind Issuance:**
   - **User Experience:** To the user, their device Passkey (`G-130.1`) + encrypted local credential vault (with optional E2E-encrypted iCloud/Google Keychain backup) acts as a permanent, zero-friction account — they verify their ID document only once.
   - **Server Reality (The Forgetting Layer):** The issuer verifies the ID document in ephemeral memory, issues the credential, and **immediately discards all cleartext PII** (name, portrait, full birthdate, document number). To prevent Sybil multi-enrollment or revoke stolen documents without tracking users, the issuer stores at most a **blinded cryptographic accumulator entry / revocation handle** (per Dynamic $k$-TAA below).

---

## 5. Hybrid QR-Code Architecture, Anti-Relay Security (`#196`) & Apple PCC Observable Trust (`#174`–`#177`)

### 5.1 Dual QR-Code Modes & Zero-App-Install Friction (with Legal/Compliance Co-Governance)
Both online and offline QR code topologies are supported so neither connectivity gaps nor missing app installations block verification (subject to deployment-specific Legal & Compliance sign-off):

- **Mode A — Online Cross-Device "Universal QR" (`https://...` Universal Link / App Clip / PWA + `openid4vp://`):**
  - Standard `openid4vp://` QR codes fail when scanned with a stock iOS/Android camera if no wallet app is installed yet.
  - AskMI encodes an HTTPS Universal Link / App Link that:
    1. Directly launches the native AskMI Wallet or partner EUDI Wallet app if installed (distributed via standard App Stores or **EU Digital Markets Act (DMA)** alternative app distribution / direct web distribution, leveraging EU DMA NFC/SE access).
    2. Gracefully falls back to the instant browser PWA / App Clip (using the Passkey-bound credential vault or ad-hoc NFC/Photo-ID bootstrap) when no native app is installed.
- **Mode B — Offline / Point-of-Sale Proximity QR (`ProximityView` / ISO 18013-5 & Offline ZKP QR):**
  - Supports supermarkets, clubs, vending machines, and physical entry terminals without internet access: the holder device displays a time-/challenge-bound QR code (or scans an offline reader challenge QR and displays the compact ZKP response QR).

### 5.2 Honest, Tiered Anti-Relay & Anti-Phishing UX (Fett/Küsters `#196` + Apple PCC Observable Trust)
Per the formal security analysis of OpenID4VP by Fett/Küsters (`docs/research/FORMAL_VERIFICATION_CREDENTIALS_RESEARCH_2026-10-24.md`, `#196`), cross-device QR flows without proximity binding are vulnerable to remote session fixation / QR forwarding. Combining this with the **Apple PCC / Observable Trust** principles (`docs/security/TRUST_ASSURANCES_AND_ROLE_BOUNDARIES.md`, `TA-01`..`TA-05`, `#174`–`#177`), AskMI uses a **tiered defense with honest UI signaling**:

1. **Dynamic Rotating QR Codes (10–15s Epoch):** Online QR codes rotate their ephemeral nonce every 10–15 seconds via SSE/WebSocket, rendering static screenshots forwarded over chat apps immediately invalid.
2. **Automatic Background Proximity Check (Where Available):** When the browser/terminal and phone can exchange a short-range signal (WebBluetooth / FIDO2 `caBLE`-style hybrid advertisement or optical camera echo), proximity is proven with **zero extra user taps**.
3. **Honest Observable-Trust UI Indicator & Risk-Tiered Step-Up:**
   - **🟢 Same-Device (W3C DC API) or Verified Proximity:** UI displays *"Gerät in direkter Nähe bestätigt — [RP Domain]"* → **1-Tap Passkey/FaceID approval**.
   - **🟡 External Screen Without Verifiable Proximity Channel:** UI honestly states *"Externer Bildschirm — physische Nähe technisch nicht prüfbar"*:
     - **Layer 0 (`WELT` — anonymous `age_over_18` predicate only, no account login):** **1 conscious tap** with prominent verifier domain display (even if relayed, zero PII is leaked and no user account exists to hijack).
     - **Layer 1 & Layer 2 (`GRUNDVERSORGUNG` / `VULNERABLE` — pseudonymous login, healthcare, finance):** **Automatic step-up to 2-digit Number Matching** between the desktop screen and the wallet so remote attackers cannot hijack an authenticated session.

---

## 6. Two-Track Cryptographic Unlinkability: EUDI ARF Standard + HPI (`av-demo.hpi.de`), Boneh–Boyen & Dynamic $k$-TAA

As documented in `docs/research/FORMAL_VERIFICATION_CREDENTIALS_RESEARCH_2026-10-24.md` (`#196`–`#199`), selective disclosure splits into two mathematically distinct families: **Hiding Commitments** (`SD-JWT`, `mso_mdoc`) and **Non-Interactive Zero-Knowledge Proofs / Anonymous Credentials** (`BBS+`, $q$-SDH short-signature credentials, Dynamic $k$-TAA). AskMI builds and documents both tracks side-by-side with explicit UI privacy labels:

| Dimension | Track A: EUDI ARF Standard (`dc+sd-jwt` / `mso_mdoc`) | Track B: HPI ZKP & Dynamic $k$-TAA (`BBS+` + Hardware P-256 + $k$-TAA) |
|---|---|---|
| **Primary References** | RFC 9901, `draft-ietf-oauth-sd-jwt-vc`, ISO/IEC 18013-5, EU AV Profile (`eu.europa.ec.av.1`) | Prof. Dr. Anja Lehmann / HPI ([`av-demo.hpi.de`](https://av-demo.hpi.de/), [`hpi.de/lehmann/eudi`](https://hpi.de/lehmann/eudi), `github.com/hpicrypto/age-verification` — *cited from published HPI project documentation; external repository code not yet independently audited here*); Boneh & Boyen (*Short Signatures Without Random Oracles*, [EUROCRYPT 2004, `10.1007/978-3-540-24676-3_4`](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_4)); Au, Susilo & Mu (*Constant-Size Dynamic k-TAA*, [SCN 2006, `10.1007/11832072_8`](https://doi.org/10.1007/11832072_8)) |
| **Cryptographic Mechanism** | Static issuer signature over salted attribute hashes (`_sd` / `MobileSecurityObject`) + holder ECDSA P-256 signature (`KB-JWT` / `DeviceAuth`). | **BBS+** multi-message anonymous credentials (from the Boneh–Boyen–Shacham CRYPTO 2004 lineage / W3C `vc-di-bbs`) bridged to **standard ECDSA P-256 hardware device binding** (Secure Enclave / StrongBox) via commit-and-prove techniques (per HPI's published `av-demo.hpi.de` architecture), complemented by **$q$-SDH Boneh–Boyen (`10.1007/978-3-540-24676-3_4`)** foundations for **Constant-Size Dynamic $k$-TAA (`10.1007/11832072_8`)** ($O(\log k)$ / constant proving effort). |
| **Multi-Show Unlinkability** | Requires **Single-Use Batch Credentials (`#171`)**; if the same credential is presented twice, the static issuer signature and `cnf` key correlate the presentations. Colluding Issuer + Verifier can link batch issuance to presentation unless re-blinded. | **True Mathematical Multi-Show Unlinkability:** A single credential issued once during ID onboarding can be presented **infinitely many times** offline or online. Neither colluding verifiers nor a colluding issuer+verifier can link presentations. |
| **Abuse Prevention & "Login Without Registration"** | Rate-limiting requires IP/session heuristics or linkable identifiers. | **Dynamic $k$-TAA Scope-Bound Nullifiers (`10.1007/11832072_8`):** Allows a holder to authenticate anonymously up to $k$ times per verifier domain/epoch (blocking Sybil/bot floods) OR derive a deterministic, cross-domain-unlinkable pseudonym (`nym_RP`) for zero-registration returning user sessions, plus dynamic group revocation without tracing. |
| **Wire Negotiation** | Standard OpenID4VP 1.0 (`dc+sd-jwt` / `mso_mdoc`). | Negotiated via `askmi_ext` (or W3C `vc-di-bbs` / ZKP format identifier in DCQL `dcql_query`). |
| **Observable-Trust UI Badge** | 🟡 *"Standard-EUDI Einmal-Beweis (Single-Use Token)"* | 🟢 *"Mathematisch Unverkettbar (Multi-Show ZKP + Hardware-Binding)"* |
