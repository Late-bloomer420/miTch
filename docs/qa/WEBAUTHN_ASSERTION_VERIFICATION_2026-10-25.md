# WebAuthn Assertion Verification — Wallet Side (2026-10-25)

**Scope:** wallet-pwa + `@askmi/shared-crypto` + `@askmi/shared-types`, browser wallet profile.
**Follows:** [WEBAUTHN_FAIL_CLOSED_2026-07-12.md](WEBAUTHN_FAIL_CLOSED_2026-07-12.md). That record and
its outcomes stay unchanged. This record addresses only its residual item
"WebAuthn assertion verification", and only on the wallet side.
**Tracking:** #218 (closed by #222).

## Finding (reproduced 2026-10-25 on master `07ceb5f`)

- A decision capsule labelled `HARDWARE_BOUND` was **not signature-checked** in
  `WalletService.generatePresentation`. Only the metadata labels were compared, followed by
  the log line "✅ Capsule Attestation Bound to Hardware Identity Key (WebAuthn)".
- Two causes:
  - `WebAuthnService.signWithIdentityKey` returned only `response.signature`, discarding
    `authenticatorData` and `clientDataJSON`.
  - Registration stored a placeholder public key (`x: ''`, `y: ''`), so there was nothing to
    verify against.
- Reproduced by tests written before the fix. On master, a capsule changed after signing, a
  capsule signed for another rpId, and a capsule with its assertion stripped were all
  presented ("promise resolved instead of rejecting").

## Fix (three PRs)

| PR   | Merge commit | Change                                                                                                                                                                                                                                                                                                                                                                   |
| ---- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| #219 | `faadb28`    | Registration stores the real P-256 public key (SPKI → JWK; RS256 or no key → `null`). `signWithIdentityKeyAssertion` returns the full assertion (challenge = SHA-256(data)). `verifyIdentityAssertion` checks type, challenge, optional origin, rpId hash, UP and UV flags, and the ECDSA signature over `authenticatorData ‖ SHA-256(clientDataJSON)`. It never throws. |
| #221 | `87c5ab7`    | Proof tokens (erasure, verifier report, document proof) are signed with the identity key, not the audit key. v2 format is labelled and covers its header. A passkey token carries the assertion. WebAuthn available but no passkey → the request is refused with `IDENTITY_KEY_REQUIRED`. Replaces #150.                                                                 |
| #222 | `4b7e393`    | Capsules carry the optional `wallet_attestation_assertion` (additive `shared-types` field, encoding `webauthn-assertion`). They are verified against **this device's registration** (`getIdentityVerificationKey`; never the rpId inside the assertion). There is a one-time prompt to re-register legacy passkeys.                                                      |

### Capsule check after #222

| Situation                                                                   | Result                                                                                                           |
| --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Stored public key; assertion verifies                                       | `✅ Capsule Attestation Verified (device passkey)`                                                               |
| Stored public key; assertion fails (changed capsule, other rpId, other key) | `SECURITY ALERT`, not presented                                                                                  |
| Hardware claim; key stored; assertion missing                               | `SECURITY ALERT`                                                                                                 |
| Hardware claim; no passkey registered                                       | `SECURITY ALERT`                                                                                                 |
| Legacy passkey (registered before #219, no stored key)                      | `⚠️ … not verifiable … Re-register the passkey`. **Proceeds**, never logged as verified (product decision, #218) |
| Software capsule (no WebAuthn)                                              | ECDSA check, unchanged                                                                                           |

## Evidence

- **Unit and integration tests (Node 22, Windows, vitest):**
  - shared-crypto: 28 files, 291/291 at #219 head `ca2108c`. The verifier and service tests use a simulated P-256 platform authenticator with DER signatures.
  - wallet-pwa: 244/244 at #221 head `c30ff31`; 255/255 at #222 head `93c5453`.
  - CI required checks passed on each PR before merge.
- **Real-browser check (2026-10-25, #222 branch, Vite dev server over HTTP on localhost, Chrome via Playwright, CDP virtual authenticator `ctap2`/`internal`, UV on):**
  1. "Create my AskMI account" stored a real P-256 public key (rpId `localhost`).
  2. Age check: the Audit log showed `✅ Capsule Attestation Verified (device passkey)`.
  3. With the stored key replaced by the legacy placeholder and the page reloaded, the re-register prompt was shown and the age check logged the "not verifiable … Re-register" warning, with no ✅.
  4. "Re-register passkey" stored a real key and hid the prompt. The next age check logged `✅ Capsule Attestation Verified (device passkey)`.

## Known limits (still open)

- **Wallet-side only.** This is not a server-side WebAuthn verifier. The signature counter is not checked, and the capsule check does not pass an expected origin (rpId hash and UV are checked).
- **Legacy passkeys** (no stored key) stay unverifiable until re-registered. By decision they proceed with a warning.
- **Stripped-assertion detection** relies on a stored key. On a legacy device, a capsule without an assertion is "unverified", not blocked.
- **RS256 passkeys** get no stored key and are therefore unverifiable.
- **Re-registering creates a new passkey.** The old one stays in the OS keychain but is no longer used.
- **Not addressed here** (from the 2026-07-12 record): point 4 (`verifyPresence` rejecting `software-fallback`) and `provePresence()` presence-level propagation. Presence proofs are still bare signatures.
- **Proof tokens are still stored in the audit log** (`proof_token`). Minimisation belongs to #172.
