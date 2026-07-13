# WebAuthn Fail-Closed — Finding & Fix (2026-07-12)

**Status:** Increment 1 fixed `webauthn.ts`; Increment 2 wires the real wallet
identity-key gate via `IdentityKeyGuardian`. Branch `fix/webauthn-fail-closed`
off `master`.
**Invariant enforced:** North-Star **Fail-Closed** ("ambiguity = DENY") applied to the
hardware-bound identity key. See also `docs/_core/10_KEY_PROTECTION_REALITY.md`
(arriving via PR #130) for the honest crypto-protection baseline.

## TL;DR
The wallet's "real secure key" is the **WebAuthn/passkey identity key** (platform
authenticator, `userVerification:'required'`, `residentKey:'required'`). A software
ECDSA fallback exists for environments without WebAuthn (Node/tests/legacy browsers).
The problem: that software fallback was reachable **as an error-recovery and
missing-key path even when WebAuthn was available**, and the resulting signature was
**typed identically** to a hardware one — so a caller (or an attacker who can induce an
error) could obtain a software-signed result that silently **bypasses the secure key**.
This contradicts the Fail-Closed invariant.

## The four silent-downgrade surfaces (as found)
| # | Location | Behaviour |
|---|----------|-----------|
| 1 | `wallet-pwa/src/services/WalletService.ts:461-476` | No passkey registered → inline software ECDSA `policyPrivateKey` created and used to sign **all** DecisionCapsules. Only a `console.warn`. |
| 2 | `shared-crypto/src/webauthn.ts` `signWithIdentityKey` | Missing/`software-fallback` meta → `SoftwareFallback.sign()`, returned as a bare signature string. |
| 3 | `shared-crypto/src/webauthn.ts` `provePresenceDetailed` (final `catch`) | **Worst.** Any unexpected assertion error (not `NotAllowed`/`Security`/`InvalidState`/`NotSupported`) → `SoftwareFallback.sign()` **returned as a valid result**, even when WebAuthn is present and a real passkey exists. Fail-**open**. |
| 4 | `shared-crypto/src/webauthn.ts` `verifyPresence` | Verifier side accepts any `attestation.length > 0` — does not distinguish `method:'webauthn'` from `method:'software-fallback'`. |

### Root cause
The protection level is **invisible and unenforced**. `PresenceProof` carries a
`method: 'webauthn' | 'software-fallback'` marker, but `provePresence()` discards it
(returns only `.signature`), and `signWithIdentityKey` returns a bare string with no
marker. Nothing downstream can tell hardware from software, so nothing can refuse
software. This is exactly the gap `KeyGuardian.getLevel()` / `KeyProtectionLevel`
(`HARDWARE_BOUND`) was meant to close — but that abstraction is not wired into the
live signing path (test-only shelf-ware), so the decision is made ad-hoc inline.

## What this increment fixed (points 2 & 3 — `webauthn.ts`)
Rule enforced: **software fallback is allowed ONLY when `isWebAuthnAvailable() === false`.**
Never as error-recovery or missing-key recovery when WebAuthn is present.

- `signWithIdentityKey`: if no identity key is registered **and** WebAuthn is available →
  `throw IDENTITY_KEY_NOT_REGISTERED` instead of silently software-signing.
- `provePresenceDetailed` final `catch`: `throw WEBAUTHN_ASSERTION_FAILED` instead of
  returning a `SoftwareFallback.sign()` result. (The legitimate early-return software
  path for `!isWebAuthnAvailable()` — Node/tests — is unchanged.)

### Test that locks it (TDD, RED→GREEN)
`shared-crypto/test/webauthn-fail-closed.test.ts`:
1. `provePresenceDetailed` **throws** on an unexpected assertion error when WebAuthn is
   available (was: returned a software signature).
2. `signWithIdentityKey` **throws** when WebAuthn is available but no identity key is
   registered (was: returned a software signature).
3. Guard: with WebAuthn **unavailable** (Node), `signWithIdentityKey` still returns a
   software signature — the legitimate test/Node path is preserved.

Verification: 3/3 green; full `shared-crypto` suite unchanged except two **pre-existing,
unrelated** timing failures (`did.test.ts` DENY-on-timeout, `pqc.test.ts` SLH-DSA) that
also fail on clean `master` (confirmed by re-running the two files with the fix stashed);
neither file imports `webauthn`.

## Increment 2 — WalletService/KeyGuardian wiring
Point 1 is now closed for DecisionCapsule signing.

- New `shared-crypto/src/IdentityKeyGuardian.ts` is the concrete key-protection
  bridge used by the wallet. It implements the `KeyGuardian` contract and exposes
  the selected identity-key protection level.
- If a WebAuthn/passkey identity key is registered, DecisionCapsules are signed via
  `WebAuthnService.signWithIdentityKey()` and annotated as
  `wallet_attestation_method:'webauthn'`,
  `wallet_attestation_protection:'HARDWARE_BOUND'`, `encoding:'base64'`.
- If WebAuthn is available but no identity key is registered, signing fails with
  `HARDWARE_IDENTITY_REQUIRED`. No session software key is created as a substitute.
- The software signer remains only for runtimes where WebAuthn is not available
  at all (Node/tests/legacy), and capsules are explicitly annotated as
  `SOFTWARE_EPHEMERAL` / `software-fallback` / `hex`.
- `generatePresentation()` now enforces those annotations. Software capsules must
  pass the existing local ECDSA verification; hardware-bound capsules must carry
  the WebAuthn/HARDWARE_BOUND metadata and no longer trip the old
  `Missing Policy Key` path.

### Tests that lock Increment 2
`wallet-pwa/src/__tests__/WalletService.test.ts`:
1. Node/test software attestations are explicitly marked `SOFTWARE_EPHEMERAL`.
2. Browser/WebAuthn available + no registered identity key rejects with
   `HARDWARE_IDENTITY_REQUIRED`.
3. Registered WebAuthn identity key path calls `signWithIdentityKey()` and produces
   a `HARDWARE_BOUND` capsule attestation.

Verification: WalletService 41/41 green; `shared-crypto` targeted WebAuthn/KeyGuardian
tests 12/12 green; `shared-crypto` lint clean; `shared-types` build clean;
`wallet-pwa` production build clean.

## What remains after Increment 2
- **Point 4** (`verifyPresence`): make the verifier reject `method:'software-fallback'`
  in production paths. This needs the full proof object, not the legacy bare string.
- **Presence level propagation:** `provePresence()` still returns only `.signature`
  for compatibility; callers that need assurance must use `provePresenceDetailed()`
  and enforce `method:'webauthn'`.
- **WebAuthn assertion verification:** the current wallet-side hardware attestation
  is fail-closed against software downgrade, but it is not a full server-side
  WebAuthn assertion verifier. That belongs in the verifier/native hook work where
  public key, authenticatorData, clientDataJSON, signature counter, rpId and origin
  can be checked together.

These are tracked here rather than fixed silently, to keep the increment small and the
security-critical change reviewable.
