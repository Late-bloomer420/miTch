# ADOPT-1.0 — AskMI Connect Product Boundary Decision

Date: 2026-10-01
Status: accepted planning decision for ADOPT-1 implementation.
Scope: `@askmi/connect` / "Sign in with AskMI".

## Decision

The first AskMI Connect product is a relying-party deployed verifier and policy
integration kit.

It helps a relying party create an approved verification session, hand the user
to a wallet, verify the returned presentation, apply a registered AskMI policy,
and return a minimal application result.

It does not issue a new credential, operate as a qualified or non-qualified
attestation provider, replace the wallet, or claim EUDI certification.

## Deployment Boundary

ADOPT-1 starts in the relying party boundary:

- the relying party is the presentation audience and operational recipient;
- AskMI code is deployed by, or on behalf of, that relying party;
- the wallet controls credential custody, holder keys and user approval;
- the original issuer remains authoritative for credential facts;
- AskMI produces an application decision with provenance, not new issuer
  evidence.

Hosted AskMI-as-intermediary, wallet-provider integration and AskMI-operated
attestation issuance are separate later product decisions.

## Supported First Profile

The first implementation slice is the existing age/liquor-store profile only.

Supported credential and claim vocabulary:

- SD-JWT VC credential path proven by ADOPT-0a/0b;
- `age` as the first disclosed claim for the liquor-store reference flow;
- configured verifier DID and trust-list/JWKS issuer key resolution;
- one fresh verifier session per presentation;
- one-time nonce/audience binding;
- fail-closed status and signature handling.

Explicitly out of scope for ADOPT-1.0:

- doctor, EHDS and pharmacy real-credential support;
- arbitrary verifier-supplied claim lists;
- mdoc/proximity integration;
- cross-RP reusable assertions;
- OIDC provider facade;
- partner registry and reusable policy packs.

## Session Contract Shape

The later code slice should implement the smallest useful contract, not a broad
identity platform:

1. `POST /verification-sessions`
   - caller selects a registered policy/profile, not arbitrary claims;
   - server creates a fresh session, audience, nonce and expected verifier;
   - response returns wallet handoff metadata and an opaque session id.
2. Wallet handoff
   - preserves RP identity, verifier DID, endpoint, audience and transaction
     state;
   - must not hide the relying party behind a generic AskMI identity.
3. Presentation endpoint
   - receives exactly one response for the expected session;
   - verifies cryptography, issuer trust, disclosure digests, holder binding
     where applicable, audience, nonce and policy result.
4. `GET /verification-sessions/{id}`
   - returns only `pending`, `verified`, `failed` or `expired`;
   - verified results contain the minimum application result and provenance
     metadata, not raw credential payloads.

## Result Semantics

A successful response may say, in substance:

> This relying party verified, for this session and policy version, that the
> wallet presented issuer-backed evidence sufficient for the configured
> age-eligibility decision.

A successful response must not say or imply:

- AskMI issued a new EUDI credential;
- AskMI's decision inherits the issuer's legal status;
- the user is globally identified across relying parties;
- the result is reusable at another relying party;
- the integration is EUDI-certified, LoA High certified, qualified, or Wallet
  Trust Mark approved.

Separate result fields are required for:

- cryptographic verification;
- issuer/trust status;
- user/wallet approval state where observable;
- policy/business authorization;
- final application result.

Do not collapse these into a single ambiguous `verified: true`.

## Operational Records And Telemetry

Allowed by default:

- opaque session id;
- non-semantic correlation id;
- verifier/customer id;
- policy id and version;
- credential/profile type;
- claim names requested/authorized/shared/withheld;
- timestamps, expiry and failure reason codes;
- high-level trust/status source references;
- final application result.

Not allowed in general telemetry:

- credential bytes;
- SD-JWT payloads or disclosures;
- stable person identifiers;
- raw attribute values unless explicitly justified by the selected RP workflow;
- holder private keys or exported wallet keys;
- logs that allow cross-RP correlation beyond the relying party's own lawful
  boundary.

Retention and audit-export rules must be decided per pilot before production.

## Prior Art Disposition

The old local branch `feat/adopt-1-connect-kit` is useful as a design sketch but
not current truth.

Salvage into implementation:

- framework-agnostic core idea;
- pluggable multi-session store;
- fail-closed session states;
- thin Express adapter as first adapter;
- browser button/handoff ergonomics;
- TDD outline, especially concurrent-session and failure-path tests.

Re-check before reuse:

- verifier-sdk API details;
- wallet deeplink shape and endpoint semantics;
- the "under 30 minutes" setup claim;
- OIDC-later language;
- any use of the legacy simulated `/wallet-present` route.

Reject or rewrite:

- any phrasing that treats the result as issuer-equivalent;
- any design that hides the RP identity;
- any design that asks applications for holder private keys or raw credential
  bytes;
- any assumption that a demo wallet path equals production wallet support.

## Acceptance For ADOPT-1.0

ADOPT-1.0 is complete when:

- this decision is linked from `docs/BACKLOG.md` and `docs/DOCS_CANON.md`;
- ADOPT-1.0 in the backlog is marked done;
- ADOPT-1.1 remains open as the next implementation-spec gate;
- `pnpm guard:rebrand` passes;
- GitHub required checks pass on the docs PR.

## Next Work

Next gate: ADOPT-1.1 Minimal Session Contract.

The first code-bearing PR should not start until ADOPT-1.1 defines:

- exact request/response schemas;
- supported policy id(s);
- one-shot session state machine;
- nonce/audience/replay failure cases;
- route names;
- storage interface;
- negative tests proving the simulated `/wallet-present` route cannot satisfy
  the real connect flow.
