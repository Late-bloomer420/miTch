# WebAuthn Fail-Closed — Finding & Fix (2026-07-12)

**Status:** Fix landed (Increment 1 of 2). Branch `fix/webauthn-fail-closed` off `master`.
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

## What remains (Increment 2 — not in this branch)
- **Point 1** (`WalletService.ts:461-476`): the inline software `policyPrivateKey` used
  for DecisionCapsule signing when no passkey exists. This is a larger design change
  (the demo currently *needs* a software signer to run without a passkey). Options:
  gate high-assurance operations behind a required `HARDWARE_BOUND` level (fail-closed
  DENY otherwise), and/or route key acquisition through `KeyGuardian` so the level is
  explicit and checkable.
- **Point 4** (`verifyPresence`): make the verifier reject `method:'software-fallback'`
  in production paths.
- **Level propagation:** stop discarding `PresenceProof.method`; surface protection
  level to callers so a policy can enforce it.

These are tracked here rather than fixed silently, to keep the increment small and the
security-critical change reviewable.
