# Reduced-assurance modes — static inventory, 2026-11-13

**Status:** dated static inventory for [#242](https://github.com/Late-bloomer420/miTch/issues/242). Input for decisions, not a security PASS and not a closure of #242.
**Baseline:** `master` @ `a688164`. File and line references are for that commit.
**Labels:** the "Assurance" column uses the vocabulary of [`docs/MATURITY_AND_LIMITATIONS.md`](../MATURITY_AND_LIMITATIONS.md) (Demo-only, Experimental, Planned).

## What this covers and how it was made

A reduced-assurance mode is any path where the code accepts, skips or substitutes a check that the full path would enforce: mock services, unsigned inputs, software stand-ins for hardware, stubs that report success.

Method: text search of non-test TypeScript under `src/` for mode switches and fallback wording (`TEST_MODE`, `fallback`, `skip`, `structural`, `insecure`, `bypass`, `demo-only`, `import.meta.env.DEV`, and similar), then reading the code around each hit. 131 hits were reviewed; most are ordinary uses of the word "fallback" and are not listed.

Limits:

- Nothing was executed. Each row is what the code says, not an observed runtime result.
- A text search misses modes that use none of the searched words. This list is not proof that no other mode exists.
- Not reviewed: `src/packages/poc-hardened` (about 30 environment switches of its own), `src/packages/benchmarks`, and test code.
- `src/packages/phase0-security` is listed by reference to its existing assessment and was not re-read.

## A. Active without an explicit choice

These are the rows #242 is about. Nobody has to opt in; the reduced path is the default or is entered on its own.

| # | Where | What is reduced | How it becomes active | Assurance | Tracking |
|---|---|---|---|---|---|
| A1 | `shared-crypto/src/trust-list-resolver.ts:158-162` | Trust-list signature is not checked; the fetched list is trusted | No anchor key configured. No code configures one. Console warning only | Demo-only | #240; fix proposed in PR #276 |
| A2 | `shared-crypto/src/trust-list-resolver.ts:121` | A stale trust list is used after a fetch failure | `low` risk: without time limit. Other tiers: inside the grace window, which the option name reserves for low risk | Demo-only | #240; PR #276 |
| A3 | `audit-log/src/storage/l2-anchor-client.ts:311-329` | `verifyAnchor()` returns `true` on every path: mock network, pending receipt, undeployed contract, and the final stub | Always | Experimental | none found |
| A4 | `audit-log/src/storage/escrow-backup.ts:132-135` | The encrypted backup is not uploaded | No endpoint configured. Console warning, then normal return | Experimental | none found |
| A5 | `oid4vp-verifier/src/response-verifier.ts:44-45` | Credential signatures are not verified; the check is structural | Default. Cryptographic verification needs `verifyCredentialSignatures: true` | Implemented, but the reduced path is the default | EV-08 |
| A6 | `mdoc/src/verifier.ts:65-70` | Issuer trust is not verified; the key from the document's own `x5chain` is used | Default when neither `issuerPublicKey` nor `trustAnchorVerifier` is passed | Implemented, but the reduced path is the default | #97 |
| A7 | `wallet-pwa/src/App.tsx:428-430`, `shared-crypto/src/webauthn.ts:400-407` | Wallet unlocks without a passkey; identity operations use a software key | Platform WebAuthn is unavailable. Log line only. Refused when WebAuthn is available (`webauthn.ts:282-289`) | Demo-only | #186 |
| A8 | `wallet-pwa/src/services/PrivacyAuditService.ts:63 ff.` | Mock heuristics produce detection results | Always; issue #245 reports they reach the audit log. That write was not traced here | Demo-only | #245 |
| A9 | `verifier-sdk/src/ad-verifier.ts:232-242` | Scope binding uses a "structural placeholder" | Per the code comment; the call path was not traced here | Experimental | none found |
| A10 | `phase0-security` (several classes) | Checks that always succeed, for example `VerifierDirectClient.verifyResponse()` | Always, per #243. Not re-read for this inventory | Demo-only | #243 |

A7 is labelled in the data it produces: decision capsules carry `wallet_attestation_method: 'software-fallback'` (`WalletService.ts:523`). The person using the wallet sees only a log line.

## B. Active only by explicit choice

These already follow the pattern #242 asks for: someone has to turn them on.

| # | Where | What is reduced | Switch | Assurance |
|---|---|---|---|---|
| B1 | `verifier-demo/backend/src/app.ts:48-49, 216, 250-253` | Placeholder verifier key pair; nonce store not persisted | `ASKMI_TEST_MODE=1` (or legacy `MITCH_TEST_MODE=1`) | Demo-only |
| B2 | `verifier-demo/backend/src/app.ts:254-296` | Verifier private key written to a local file in plaintext | `VERIFIER_KEY_PERSISTENCE=local` | Demo-only |
| B3 | `wallet-pwa/vite.config.ts:6` | Wallet dev server over HTTP | `ASKMI_DEV_HTTPS=0` | Demo-only |
| B4 | `shared-crypto/src/did.ts:31-34, 212-214` | Mock DID documents; `did:web` on localhost over HTTP | `allowMockFallback`, `allowInsecureLocalhostDidWeb`; both default to `false`, localhost is refused in production regardless | Demo-only |
| B5 | `policy-engine/src/config-profiles.ts:69-78` | `failClosed: false`, no explicit rule required, no WebAuthn required | Profile `pilot`. `getConfig()` defaults to `default` (line 104) | Demo-only |
| B6 | `policy-engine/src/engine.ts:183-186` | Unknown verifier becomes PROMPT, not DENY | `context.overrideGranted` | Implemented |
| B7 | `oid4vp-verifier/src/response-verifier.ts:43, 121` | Nonce check skipped | `skipNonceCheck: true`. Commented "for testing only" but a public option with no guard | Demo-only |
| B8 | `wallet-pwa/src/data/DemoPolicy.ts:28` | Verifier origin is not compared with the verifier ID | `strictVerifierBinding: false` in the demo policy | Demo-only |
| B9 | `verifier-demo/backend/src/app.ts:361-365, 646-650` | `/wallet-present` simulates the wallet with keys it generates itself | Calling the route. It and the legacy `/present` route are rejected once a real authorization exists for the session | Demo-only |
| B10 | `wallet-pwa/src/App.tsx:2283-2317` | Developer tools, including a credential corruption probe | `import.meta.env.DEV`; not in production builds | Demo-only |

## What follows from this

1. **A1 and A2** have a proposed fix (PR #276) that makes `ASKMI_TRUST_MODE` real and defaults to fail-closed.
2. **A3 and A4** report success for work that did not happen. Returning an explicit "not verified" / "not uploaded" result would be the smallest honest change. No issue tracks either.
3. **A5 and A6** have the full check available but off by default. Inverting the default is a public API behaviour change and needs owner approval (see `CLAUDE.md`, "No breaking changes").
4. **B7** would be safer behind the same explicit dev/test mode as the trust list, since nothing stops a caller from passing it in production.
5. A single runtime switch for all of section B does not exist. `ASKMI_TEST_MODE`, `ASKMI_TRUST_MODE` (after #276), `ASKMI_DEV_HTTPS` and per-call options each cover one piece.

## Not established here

- Whether any row is reachable in a deployed configuration. No deployment was inspected.
- Whether `docs/ops/RUNBOOKS_V1.md` needs matching entries. A search of that file for "fallback", "degrad" and "mode" found no existing wording to align with.
- The reduced-assurance switches inside `poc-hardened`.
