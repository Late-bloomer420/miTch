# ADOPT-1.1 — Minimal Session Contract

Date: 2026-10-01
Status: accepted implementation contract for the first `@askmi/connect` code
slice.
Depends on: [`ADOPT_1_PRODUCT_BOUNDARY_DECISION.md`](ADOPT_1_PRODUCT_BOUNDARY_DECISION.md).

## Decision

The first `@askmi/connect` code slice must implement an explicit verifier-side
session contract instead of reusing the verifier demo's global status variables.

The contract is deliberately small:

- one registered age/liquor-store policy;
- one fresh verifier session per presentation;
- one wallet handoff per session;
- one accepted presentation response per session;
- one minimal application result;
- no simulated `/wallet-present` success path.

## Current Code Boundary

Observed current-state anchors:

- `src/packages/verifier-sdk/src/VerifierSDK.ts` exposes
  `createRequest(requestedClaims, purpose)` and `verifyPresentation(input)`.
- `src/apps/verifier-demo/backend/src/app.ts` still uses global
  `lastVerificationStatus` for the demo status endpoint.
- `/oid4vp-present` is the real ADOPT-0a/0b presentation endpoint.
- `/wallet-present` remains the legacy simulated-wallet demo route and must not
  satisfy `@askmi/connect`.

## Policy Registry

ADOPT-1.1 supports exactly one policy id:

```ts
type AskMIConnectPolicyId = 'age-liquor-store-v1';
```

Policy definition:

```ts
interface AskMIConnectPolicy {
  id: 'age-liquor-store-v1';
  version: 1;
  purpose: 'Liquor purchase age eligibility';
  profile: 'sd-jwt-vc-age-v1';
  requestedClaims: ['age'];
  requiredClaims: ['age'];
  verifierDid: string;
  resultClaim: 'eligible';
}
```

No public ADOPT-1.1 API accepts arbitrary requested claims. Additional policies
require a later policy-registry/policy-pack gate.

## Session State Machine

```ts
type AskMIConnectSessionStatus =
  | 'pending'
  | 'wallet_opened'
  | 'verified'
  | 'failed'
  | 'expired';
```

Allowed transitions:

| From | To | Cause |
|---|---|---|
| `pending` | `wallet_opened` | optional wallet-open notification for the same session |
| `pending` / `wallet_opened` | `verified` | one valid presentation for the expected session |
| `pending` / `wallet_opened` | `failed` | malformed input, wrong audience, wrong nonce, invalid issuer trust, invalid signature, insufficient claims, policy deny or simulated-route attempt |
| `pending` / `wallet_opened` | `expired` | session TTL elapsed before a valid presentation |
| `verified` / `failed` / `expired` | no transition | terminal |

Rules:

- Every session has `createdAt`, `expiresAt`, `nonce`, `audience`,
  `verifierDid`, `policyId`, `policyVersion`, and `correlationId`.
- A presentation consumes the session attempt. A second presentation for the
  same session fails as replay/terminal-state use.
- Unknown session ids are `404` and must not leak whether a nearby id exists.
- Expiry is evaluated on read and before presentation verification.
- A result never moves from `failed` or `expired` back to success.

## Storage Interface

The implementation must introduce a pluggable session store:

```ts
interface AskMIConnectSessionStore {
  create(session: AskMIConnectSession): Promise<void>;
  get(sessionId: string): Promise<AskMIConnectSession | null>;
  update(session: AskMIConnectSession): Promise<void>;
  consume(sessionId: string): Promise<AskMIConnectSession | null>;
  deleteExpired(now: Date): Promise<number>;
}
```

Required first implementation:

- `InMemoryAskMIConnectSessionStore`;
- concurrent-session safe for ordinary single-process use;
- no global singleton session state;
- deterministic TTL tests.

Production Redis/DB stores are out of scope for the first code slice, but the
interface must not make them awkward.

## Routes

Route names are intentionally not the legacy demo names.

### `POST /askmi/connect/sessions`

Creates a verifier-side session from a registered policy.

Request:

```json
{
  "policyId": "age-liquor-store-v1",
  "returnUrl": "https://rp.example/after-askmi"
}
```

Rules:

- `policyId` is required and must be registered.
- `returnUrl` is optional for the first implementation and must be treated as
  display/navigation metadata, not as a trust source.
- caller-supplied `requestedClaims`, `verifierDid`, `nonce`, `audience`,
  `issuer`, `result`, or `eligible` fields are ignored or rejected.

Response `201`:

```json
{
  "sessionId": "askmi_sess_...",
  "status": "pending",
  "expiresAt": "2026-10-01T12:00:00.000Z",
  "correlationId": "txn_...",
  "policy": {
    "id": "age-liquor-store-v1",
    "version": 1
  },
  "handoff": {
    "url": "https://wallet.example?...",
    "method": "browser-redirect-or-qr",
    "presentationEndpoint": "https://rp.example/askmi/connect/sessions/askmi_sess_.../presentation"
  }
}
```

### `POST /askmi/connect/sessions/{sessionId}/opened`

Optional wallet-open notification.

Response:

- `204` for a valid pending session;
- `404` for unknown;
- `409` for terminal;
- `410` for expired.

This route never verifies claims and never changes the application result.

### `POST /askmi/connect/sessions/{sessionId}/presentation`

Consumes a wallet presentation for exactly one session.

Request:

```json
{
  "vp_token": "...",
  "presentation_submission": {},
  "state": "askmi_sess_..."
}
```

The concrete body may follow the current ADOPT-0 verifier payload shape, but the
session id must be bound to the server-created expectation. The implementation
may internally adapt to `VerifierSDK.verifyPresentation(input)` or the
OID4VP verifier, but the route contract remains session-oriented.

Response `200` for success:

```json
{
  "sessionId": "askmi_sess_...",
  "status": "verified",
  "result": {
    "eligible": true
  },
  "verification": {
    "cryptographic": "passed",
    "issuerTrust": "passed",
    "policy": "allowed",
    "userApproval": "presentation_received"
  },
  "provenance": {
    "policyId": "age-liquor-store-v1",
    "policyVersion": 1,
    "credentialProfile": "sd-jwt-vc-age-v1",
    "claimsShared": ["age"],
    "claimsWithheld": [],
    "correlationId": "txn_..."
  }
}
```

Failure responses:

- `400` malformed request/body;
- `401`/`403` invalid cryptography, issuer trust, holder binding or policy deny;
- `404` unknown session;
- `409` session already terminal or already consumed;
- `410` expired session.

Every failure response must return:

```json
{
  "sessionId": "askmi_sess_...",
  "status": "failed",
  "error": {
    "code": "WRONG_AUDIENCE",
    "message": "Presentation was not issued for this verifier session."
  }
}
```

Use stable error codes, not raw exception text.

### `GET /askmi/connect/sessions/{sessionId}`

Returns the minimal session status.

Response:

```json
{
  "sessionId": "askmi_sess_...",
  "status": "pending",
  "expiresAt": "2026-10-01T12:00:00.000Z",
  "policy": {
    "id": "age-liquor-store-v1",
    "version": 1
  }
}
```

If verified, include the same minimal `result`, `verification` and `provenance`
fields as the presentation success response. Never include credential bytes,
raw disclosures, holder keys, or stable person identifiers.

## Error Codes

Required first error-code set:

| Code | Meaning |
|---|---|
| `UNKNOWN_POLICY` | `policyId` is not registered |
| `UNKNOWN_SESSION` | session id not found |
| `SESSION_EXPIRED` | session expired before success |
| `SESSION_TERMINAL` | session already verified/failed/expired |
| `MALFORMED_PRESENTATION` | body cannot be parsed as a supported presentation |
| `WRONG_AUDIENCE` | presentation audience/verifier/session binding does not match |
| `WRONG_NONCE` | nonce/state does not match session expectation |
| `REPLAY_DETECTED` | session or presentation was reused |
| `UNTRUSTED_ISSUER` | issuer is absent from trust source or cannot be resolved |
| `SIGNATURE_INVALID` | issuer/holder/signature verification failed |
| `INSUFFICIENT_CLAIMS` | required claim missing after valid verification |
| `POLICY_DENIED` | policy engine denied the request |
| `SIMULATED_ROUTE_REJECTED` | legacy `/wallet-present` style simulated result attempted |
| `INTERNAL_ERROR` | unexpected implementation failure, fail-closed |

## Negative Test Requirements

The first code PR must add tests proving:

- two concurrent sessions do not collide;
- unknown session id fails;
- expired session fails;
- a second presentation for a verified session fails;
- wrong audience fails;
- wrong nonce/state fails;
- invalid issuer/trust source fails;
- invalid signature fails;
- missing `age` fails with `INSUFFICIENT_CLAIMS`;
- policy deny produces failure, not ambiguous success;
- a `/wallet-present`-style simulated body cannot produce `verified`;
- GET status never returns raw credential/disclosure content;
- application-provided arbitrary requested claims are rejected or ignored.

## Implementation Notes

The first implementation may be an internal package or verifier-demo-backed
adapter, but it must expose the contract above and keep the core independent of
Express types where practical.

Do not start by polishing UI. The first proof is server contract correctness and
negative tests.

## Acceptance For ADOPT-1.1

ADOPT-1.1 is complete when:

- this contract is linked from `docs/BACKLOG.md` and `docs/DOCS_CANON.md`;
- ADOPT-1.1 in the backlog is marked done;
- ADOPT-1.2 remains the next open gate for SDK/API package shape;
- `pnpm guard:rebrand` passes;
- GitHub required checks pass on the docs PR.

## Next Work

Next gate: ADOPT-1.2 SDK/API Shape.

The first code-bearing slice should start only after ADOPT-1.2 names the package
layout, exported types, internal adapter boundary and example scope.
