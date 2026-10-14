# ADOPT-1.2 — SDK/API Shape

Date: 2026-10-01
Status: accepted implementation boundary for the first `@askmi/connect` code
slice.
Depends on: [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](ADOPT_1_MINIMAL_SESSION_CONTRACT.md).

## Decision

The first `@askmi/connect` SDK must be a small server-side verification kit with
a framework-agnostic core and one thin Express adapter.

It must wrap the existing ADOPT-0 verifier path and session contract. It must
not create a new issuer role, request wallet private keys, accept arbitrary
claim lists from applications, or treat the legacy simulated `/wallet-present`
route as a successful Connect flow.

## Package Layout

Create one workspace package:

```text
src/packages/connect/
  package.json
  tsconfig.json
  tsconfig.build.json
  src/
    index.ts
    core/
      verifier.ts
      policies.ts
      session-store.ts
      types.ts
    express/
      router.ts
    browser/
      handoff.ts
  test/
    core.test.ts
    session-store.test.ts
    express.test.ts
    browser-handoff.test.ts
```

Package name:

```json
{
  "name": "@askmi/connect",
  "type": "module"
}
```

The package may be internal/private for the first code slice. Publishing to npm
is out of scope until the real session flow is proven.

## Exported API

Public exports from `@askmi/connect`:

```ts
export type AskMIConnectPolicyId = 'age-liquor-store-v1';
export type AskMIConnectSessionStatus =
  | 'pending'
  | 'wallet_opened'
  | 'verified'
  | 'failed'
  | 'expired';

export interface AskMIConnectConfig {
  verifierDid: string;
  audienceBaseUrl: string;
  walletBaseUrl: string;
  sessionTtlMs?: number;
  store?: AskMIConnectSessionStore;
}

export interface AskMIConnectSessionStore {
  create(session: AskMIConnectSession): Promise<void>;
  get(sessionId: string): Promise<AskMIConnectSession | null>;
  update(session: AskMIConnectSession): Promise<void>;
  consume(sessionId: string): Promise<AskMIConnectSession | null>;
  deleteExpired(now: Date): Promise<number>;
}

export function createAskMIConnect(config: AskMIConnectConfig): AskMIConnect;
export class InMemoryAskMIConnectSessionStore implements AskMIConnectSessionStore {}
```

Subpath exports:

```ts
export { askmiConnectExpressRouter } from '@askmi/connect/express';
export { buildAskMIHandoff } from '@askmi/connect/browser';
```

No public API accepts:

- holder private keys;
- exported wallet keys;
- credential bytes as application input;
- arbitrary `requestedClaims`;
- caller-supplied nonce, audience, verifier DID, issuer, result or `eligible`.

## Core Interface

The core is transport-neutral:

```ts
interface AskMIConnect {
  createSession(input: CreateSessionInput): Promise<CreateSessionResult>;
  markWalletOpened(sessionId: string): Promise<WalletOpenedResult>;
  completeSession(input: CompleteSessionInput): Promise<CompleteSessionResult>;
  getSession(sessionId: string): Promise<GetSessionResult>;
}
```

First supported create input:

```ts
interface CreateSessionInput {
  policyId: 'age-liquor-store-v1';
  returnUrl?: string;
}
```

The core owns session id generation, nonce generation, audience construction,
policy lookup, expiry evaluation, terminal-state handling and conversion of raw
verification failures into stable Connect error codes.

## Policy Registry

The first code slice registers exactly one policy:

```ts
const ageLiquorStorePolicy = {
  id: 'age-liquor-store-v1',
  version: 1,
  purpose: 'Liquor purchase age eligibility',
  profile: 'sd-jwt-vc-age-v1',
  requestedClaims: ['age'],
  requiredClaims: ['age'],
  resultClaim: 'eligible'
} as const;
```

Applications choose a registered policy id. They do not provide claim lists.
Additional policies require a later policy-pack or registry decision.

## Express Adapter

The Express adapter is a thin route binding over the core contract from ADOPT-1.1:

- `POST /askmi/connect/sessions`;
- `POST /askmi/connect/sessions/:sessionId/opened`;
- `POST /askmi/connect/sessions/:sessionId/presentation`;
- `GET /askmi/connect/sessions/:sessionId`.

Rules:

- no session state in module globals;
- no verifier result stored outside the configured session store;
- no raw exception text in HTTP responses;
- no raw credential payloads or disclosed values in status responses beyond the
  minimal allowed result/provenance fields.

## Browser Helper

The first browser export is a handoff helper, not a full branded auth product:

```ts
interface AskMIHandoff {
  url: string;
  method: 'browser-redirect-or-qr';
  presentationEndpoint: string;
}

function buildAskMIHandoff(input: BuildAskMIHandoffInput): AskMIHandoff;
```

The optional button UI is deferred until the server session contract is green.
This prevents UI polish from hiding protocol mistakes.

## Reused Existing Components

The first code PR should reuse:

- `@askmi/verifier-sdk` for verifier request creation and presentation
  verification;
- `@askmi/shared-types` correlation id helpers;
- the existing ADOPT-0 `/oid4vp-present` semantics as the real verification
  path;
- existing trust-list/JWKS issuer-key resolution.

It must not reuse:

- verifier-demo global `lastVerificationStatus`;
- legacy `/wallet-present` simulated success bodies;
- the old `feat/adopt-1-connect-kit` route names as current truth;
- marketing claims from the old July design note.

## First Code PR Acceptance

The first code-bearing PR after ADOPT-1.2 must prove:

- `@askmi/connect` builds and has its own test task;
- two concurrent sessions do not collide;
- unknown, expired and terminal sessions fail closed;
- wrong audience and wrong nonce/state fail closed;
- missing `age` produces `INSUFFICIENT_CLAIMS`;
- a `/wallet-present`-style simulated body produces
  `SIMULATED_ROUTE_REJECTED` or another stable failure, never `verified`;
- status responses never include credential bytes, SD-JWT payloads, disclosures,
  holder keys or stable person identifiers;
- the core module imports no Express types.

## Security Interaction

`@askmi/connect` adds a new verifier-facing surface. The code PR must therefore
include a focused security checklist:

- session ids and nonces generated with cryptographic randomness;
- one-shot consume semantics tested;
- stale sessions expire before verification;
- failure codes are stable and non-oracular;
- logs contain only allowed telemetry from ADOPT-1.0;
- all evidence harness additions are shell-injection safe.

## Next Work

Next gate: ADOPT-1.2-code / first `@askmi/connect` implementation slice.

In parallel, start the Security Audit Remediation track from
[`../security/SECURITY_AUDIT_ROADMAP_2026-10-01.md`](../security/SECURITY_AUDIT_ROADMAP_2026-10-01.md), beginning with small security/code-health fixes before broad dependency churn.
