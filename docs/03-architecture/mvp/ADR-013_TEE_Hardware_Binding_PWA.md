# ADR-013: TEE & Hardware Binding in PWA (LoA High)

**Status:** Research / Proposed
**Date:** 2026-05-21
**Context:** EUDI CIR 2024/2981 requires Level of Assurance (LoA) "High", which mandates hardware-backed keys that are non-extractable even if the OS is compromised. miTch is a Progressive Web App (PWA), which has limited access to native secure hardware (Secure Element / TEE).

## 1. Problem Statement
How can a browser-based EUDI Wallet achieve LoA High certification?
Standard WebCrypto `non-extractable` keys are stored in the browser's profile. If the OS is rooted/compromised, these keys might be accessible (depending on browser implementation). Certification usually requires a hardware root of trust.

## 2. Viable Hardware Binding Options for PWA

### Option A: WebAuthn (Passkeys) — Recommended
Use the Web Authentication API to create a hardware-bound key.
- **Mechanism:** `navigator.credentials.create({ publicKey: ... })` with `authenticatorAttachment: "platform"`.
- **Pros:** 
  - Accesses iOS Secure Enclave / Android StrongBox.
  - User verification (Biometrics/PIN) is mandatory and handled by hardware.
  - Keys never leave the hardware.
- **Cons:**
  - WebAuthn keys are "opaque" — they can only sign/verify, not wrap other keys (in standard implementations).
  - No direct support for ECDH key agreement (needed for mdoc proximity encryption).

### Option B: WebCrypto with Hardware-Backed Storage
Some browsers (e.g., Chrome on Android with StrongBox) attempt to back WebCrypto keys with hardware.
- **Mechanism:** Standard `crypto.subtle.generateKey`.
- **Pros:** Native WebCrypto API, supports ECDH and Wrapping.
- **Cons:** Browser-dependent, no guarantee of hardware backing on all platforms, difficult to prove for certification.

### Option C: Native Bridge / Hybrid Approach
A tiny native "Key Guardian" app that communicates with the PWA via a local loopback or custom URI scheme.
- **Mechanism:** PWA sends requests to `localhost:port` or `mitch-guard://`.
- **Pros:** Full access to Secure Element / TEE.
- **Cons:** Breaks the "pure PWA" model, requires user to install a second app.

## 3. Tradeoffs & Certification Impact

| Feature | Software Key | WebAuthn (Option A) | Native Guard (Option C) |
|---|---|---|---|
| **LoA Potential** | Low / Substantial | **High (with caveats)** | **High** |
| **UX** | Seamless | Biometric Prompt | App Install Required |
| **Portability** | Excellent | Excellent | Medium |
| **EUDI Compliance** | ❌ (Missing Hardware) | 🟡 (Implementation dependent) | ✅ (Full control) |

## 4. Proposed Strategy for miTch (Phase 4)
1. **Primary Identity Key:** Use **WebAuthn** to create the "Primary Identity Key". This satisfies the requirement for a hardware-bound "Wallet Instance" identity.
2. **Key Wrapping:** Use the WebAuthn key to sign a "Wallet Attestation" for ephemeral session keys.
3. **Mdoc Support:** Since WebAuthn doesn't support ECDH, use WebCrypto for session keys but cryptographically bind them to the WebAuthn identity.
4. **Certification Path:** Engage with a CAB to determine if WebAuthn (platform authenticator) is accepted as a TEE equivalent under CIR 2024/2981 Annex VI (Reuse of existing certificates).

## 5. References
- ISO/IEC 15408 (Common Criteria)
- EUDI CIR 2024/2981 (Certification)
- FIDO Alliance Security Requirements
