# ADOPT-1 — AskMI Connect Planning Gate

Date: 2026-10-01
Status: ADOPT-1.0 and ADOPT-1.1 accepted; ADOPT-1.2 is the next open gate.

## Goal

Turn the live-verified ADOPT-0a/0b credential path into a small relying-party
integration surface: "Sign in with AskMI" / `@askmi/connect`.

The product shape is deliberately narrow:

- AskMI runs as verifier and policy integration software for a relying party.
- The wallet remains responsible for custody, holder keys and user approval.
- AskMI returns a scoped application result, not a new government credential,
  QEAA, PID, or cross-RP attestation.

## Starting Evidence

- `docs/qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md` proves the real age
  credential path against live local services: issuance, storage, selective
  disclosure, trust-list/JWKS key resolution, and fail-closed issuer rejection.
- `docs/compliance/EXTERNAL_DESK_AUDIT_EUDI_2026-09-11.md` recommends the
  RP-deployed verifier/integration route first and treats issuer operation as a
  separate later business decision.
- `docs/05-business/USE_CASE_LANDSCAPE_AND_SEQUENCED_ROADMAP_2026-09-11.md`
  proposes broad candidate workflows, but does not prove customer demand.

## Prior Art To Review

A local historical branch, `feat/adopt-1-connect-kit`, contains a 2026-07-14
design-only spec for `@askmi/connect` with a framework-agnostic core, pluggable
session store, Express adapter, browser button and minimal example. That work
was not merged and must be treated as design input, not current truth.

Before implementing ADOPT-1, salvage only the parts that still fit the current
trust boundary:

- useful: multi-session store, fail-closed session status, thin Express adapter,
  button/handoff ergonomics, and TDD outline;
- re-check: any assumption about verifier-sdk APIs, demo deeplink shape, OIDC
  later seam, and "under 30 minutes" product claim;
- avoid: treating the SDK result as issuer-equivalent, hiding RP identity, or
  relying on the legacy simulated `/wallet-present` route.

## Non-Goals

- Do not build an independently certified AskMI wallet in this sprint.
- Do not create AskMI-issued reusable attestations.
- Do not claim EUDI certification, Wallet Trust Mark readiness, LoA High, or
  qualified status from this integration kit.
- Do not support arbitrary verifier-supplied claim lists without a registered
  policy and profile.
- Do not add public tunnels, hosted previews, or local exposure.

## Proposed Scope

### ADOPT-1.0: Product Boundary Decision

Record the first `@askmi/connect` deployment mode:

- customer/RP-deployed library or service;
- selected credential profile and supported claim vocabulary;
- exact trust and status sources;
- audit fields allowed in operational telemetry;
- language for public product claims.

Acceptance:

- one decision record or task note names the RP boundary, data controller role
  assumptions, credential profile, and output semantics;
- no output is described as a new EUDI credential or issuer-equivalent proof.

Status: done in [`ADOPT_1_PRODUCT_BOUNDARY_DECISION.md`](ADOPT_1_PRODUCT_BOUNDARY_DECISION.md).

### ADOPT-1.1: Minimal Session Contract

Define the smallest developer contract:

- `POST /verification-sessions` creates a verifier-side session from an
  approved use-case policy;
- wallet handoff preserves RP identity, audience, nonce and transaction state;
- `POST /oid4vp-present` consumes exactly one expected response;
- `GET /verification-sessions/{id}` returns only the minimal application result.

Acceptance:

- request/response schema is documented;
- wrong audience, reused nonce, missing session, missing trust, invalid
  signature and insufficient claims are explicit fail-closed cases;
- result separates cryptographic verification, issuer trust, user approval and
  business authorization.

Status: done in [`ADOPT_1_MINIMAL_SESSION_CONTRACT.md`](ADOPT_1_MINIMAL_SESSION_CONTRACT.md).

### ADOPT-1.2: SDK Shape

Draft the package/API boundary for `@askmi/connect`:

- server-side verifier helper for session creation and result polling;
- front-end handoff helper or button copy;
- policy registration helpers constrained to known profiles;
- examples for one concrete age/liquor-store flow only.

Acceptance:

- no SDK method asks for holder private keys or credential bytes from the
  application;
- the age flow uses the real ADOPT-0 path, not the legacy simulated
  `/wallet-present` frontend route;
- examples clearly label demo services and localhost trust roots.

### ADOPT-1.3: First Vertical Discovery Gate

Use the September use-case research only to choose interviews, not to build 72
flows.

Immediate discovery candidates:

- vehicle rental eligibility;
- hotel registration minimisation;
- learning/student/professional credential verification;
- contractor/site access as a controlled ecosystem fallback.

Acceptance before implementation:

- named buyer or partner reachable;
- selected country;
- accessible credential source or issuer;
- measurable manual pain;
- lawful-basis and retention assumptions identified;
- paid-pilot path plausible.

## Stop Conditions

Stop or re-scope ADOPT-1 if:

- the flow needs AskMI to issue reusable attestations before the verifier route
  is proven;
- the only value proposition is broad identity brokering;
- credential supply is unavailable for the chosen pilot;
- public claims would require legal/certification assertions not yet reviewed;
- the implementation would store credential payloads or stable person IDs in
  general telemetry.

## First Implementation Slice

The first code slice, after this plan is approved, should be a narrow
age-verification connect sample:

1. register a fixed age policy;
2. create a verifier session with fresh nonce/audience;
3. hand off to wallet;
4. verify the stored real SD-JWT VC presentation;
5. return a minimal `eligible: true/false` result plus provenance metadata;
6. add negative tests for wrong audience, reused nonce, invalid issuer,
   insufficient claims and simulated-route accidental use.

This slice should land before adding extra verticals.
