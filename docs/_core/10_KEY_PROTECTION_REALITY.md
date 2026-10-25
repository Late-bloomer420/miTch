# 10 — Key Protection Reality (Software vs. WebAuthn vs. planned Hardware/TEE)

> **Status:** binding honesty boundary — verified against source 2026-07-07.
> **Why this file exists:** the North Star honesty-check forbids TEE /
> hardware-attestation / ZK-strength claims unless implemented **and**
> verifiable ([`01_NORTH_STAR.md`](01_NORTH_STAR.md)). This document records
> what is actually built today so no external claim outruns the code.

## TL;DR

- **There is no TEE.** No Trusted Execution Environment, no secure-enclave
  compute, no SGX / TrustZone / StrongBox code anywhere in the repo. "Secure
  computations run in a TEE" would be a **false claim** today.
- **Runtime crypto is software** (WebCrypto `crypto.subtle`), with keys held
  in-memory and non-extractable.
- **The one real hardware-trust seam that IS wired is WebAuthn / passkeys** —
  a hardware-bound *key* for possession/presence proof, **not** a general
  compute enclave. On a device with a secure element the passkey private key
  never leaves the authenticator.
- A unified `KeyGuardian` abstraction with a `HARDWARE_BOUND` level exists as a
  **design seam** for future hardware-bound keys, but its only implementation is
  software and it is **not wired into the wallet** (test-only today).

## Evidence (verified against source)

### 1. The hardware seam is designed but not produced
- `KeyProtectionLevel` defines three levels — `SOFTWARE_EPHEMERAL`,
  `SOFTWARE_PERSISTED`, `HARDWARE_BOUND`
  (`src/packages/shared-crypto/src/types/KeyProtectionLevel.ts`).
- `KeyGuardian` interface + a dedicated `HARDWARE_BOUND` result variant carrying
  a WebAuthn-shaped `credentialId`
  (`src/packages/shared-crypto/src/interfaces/KeyGuardian.ts`).
- **`HARDWARE_BOUND` is never produced anywhere** — it is only *defined*.

### 2. The only implementation is software
- `SoftwareKeyGuardian implements KeyGuardian`
  (`src/packages/shared-crypto/src/SoftwareKeyGuardian.ts`): keys via
  `crypto.subtle.generateKey` (ECDSA-P256 signing, ECDH-P256 encryption,
  strictly separated — G-07), private keys **non-extractable**, held in in-memory
  `Map`s, **ephemeral**. `getLevel()` always returns `SOFTWARE_EPHEMERAL`.

### 3. The KeyGuardian layer is not wired into the running wallet
- `new SoftwareKeyGuardian()` appears **only in its own unit test**
  (`src/packages/shared-crypto/test/key-guardian.test.ts`). The wallet app does
  not import `KeyGuardian` at all.

### 4. What the wallet actually uses for keys
- `src/apps/wallet-pwa/src/services/WalletService.ts`: WebCrypto directly
  (`globalThis.crypto.subtle.generateKey / importKey / sign / verify`),
  in-memory `holderKeys` / `keyCache`, **and** `WebAuthnService`
  (`isIdentityRegistered()`, `signWithIdentityKey()`, `provePresence()`) —
  variable literally named `hasHardwareIdentity`. This WebAuthn path (passkey
  onboarding, G-130.1) is the real hardware-bound-key mechanism.

### 5. The old "TEE" file is an empty placeholder
- `src/packages/shared-crypto/src/tee-attestation.ts` — *"Attestation module is
  intentionally removed. No exports. … placeholder to avoid breaking imports
  during migration."* Superseded by the KeyGuardian seam
  (`shared-crypto/src/index.ts:19` — *"Phase 0: KeyGuardian (replaces
  tee-attestation)"*). Removing it loses no capability.
- Note: the word *"attestation"* elsewhere (e.g. `WalletService.ts` capsule
  check) means **capsule signature verification**, not hardware remote
  attestation.

## Honest external framing

> Software-based cryptography (WebCrypto, non-extractable keys) plus
> **hardware-bound identity via WebAuthn/passkeys**. A TEE / `HARDWARE_BOUND`
> key path is designed as an architecture seam but **not yet implemented**.

Do **not** state or imply: "computations run inside a TEE", "hardware
attestation", or "keys are protected by a secure enclave" as a general
property. The only defensible hardware statement is the WebAuthn passkey one,
and only on devices whose authenticator is hardware-backed.

## Open follow-ups (see [`06_OPEN_DECISIONS.md`](06_OPEN_DECISIONS.md))

- If hardware-bound keys become a goal, implement a real `HardwareKeyGuardian`
  (WebAuthn-largeBlob / platform authenticator) that returns `HARDWARE_BOUND`,
  and wire `KeyGuardian` into `WalletService` (today it bypasses the abstraction).
- Decide the fate of the unused `KeyGuardian`/`SoftwareKeyGuardian` layer: wire
  it or drop it — currently test-only shelf-ware.
- `tee-attestation.ts` can be deleted once the above is decided (no consumers).
