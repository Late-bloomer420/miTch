# ADOPT-1 — "Sign in with AskMI" Integration Kit (`@askmi/connect`)

**Status:** Design — awaiting approval
**Date:** 2026-07-14
**Author:** Claude (Opus 4.8) with J F M / AskMI
**Track:** ADOPT (first of two: ADOPT-1 integration kit → ADOPT-2 partner registry + policy packs)
**Relates to:**
- `docs/BACKLOG.md` → EPIC G-150 (Sign in with AskMI integration kit), G-160 (partner reuse)
- `src/packages/verifier-sdk/` (`VerifierSDK`: `createRequest`, `verifyPresentation`, `replayCheck` hook) — the crypto foundation this kit wraps
- `src/packages/oid4vp-verifier/` — real SD-JWT VC + KB-JWT signature verification (SECURE-1 / F-14)
- `src/apps/verifier-demo/` — the existing bespoke reference integration (single-session)

---

## 1. Context

AskMI can verify presentations today, but only via low-level building blocks. `@askmi/verifier-sdk` exposes `createRequest(requestedClaims, purpose)` and `verifyPresentation(body)`; the wallet handoff (QR + deeplink), status polling, session correlation, and claim mapping are all hand-wired in the `verifier-demo` app, which tracks a **single global session** (`lastVerificationStatus`) — fine for a demo, unusable as a product.

The user's goal for the ADOPT track is **"adoptable by others"**: a third-party developer should add a privacy-preserving "Sign in with AskMI" the way they add "Sign in with Google/Apple." The chosen shape is **native SDK now, OIDC facade later** (§9 seam), with a **framework-agnostic core + Express adapter** server surface.

## 2. Goal & Non-Goals

**Goal:** A minimal *complete* drop-in kit — `@askmi/connect` — so a developer goes from zero to a working, multi-user, privacy-preserving "Sign in with AskMI" in **under 30 minutes**, reusing the verifier-sdk crypto (+ F-14 signature verification).

**Non-Goals (explicit):**
- The **OIDC provider facade** (authorization/token/discovery endpoints, ID-token issuance) — the core is *designed* so a later `@askmi/connect/oidc` can wrap it, but it is not built here.
- The **partner registry + reusable policy packs** (ADOPT-2 / G-160).
- Any **wallet-side** changes — the kit is verifier-side only; it drives the existing wallet handoff.
- Non-Express server adapters (Fastify/Next/Hono) — the core stays agnostic so they can be added later, but only the Express adapter ships here.
- Replacing `verifier-sdk` or `oid4vp-verifier` — the kit **wraps** them; their crypto is not reimplemented.

## 3. Architecture — one new package `@askmi/connect`

A private-scope-consistent `@askmi/connect` workspace package under `src/packages/connect/`, three focused units + a reference:

### 3.1 `core/` — framework-agnostic verifier orchestration
`createAskMIVerifier(config): AskMIVerifier` wrapping a `VerifierSDK` instance and a `SessionStore`. Three pure operations (no framework types):
- `begin(request: AskMIRequest): Promise<{ session: AskMISession; handoffUrl: string; qrSvg: string }>` — creates a verifier-sdk request, persists a `pending` session, builds the wallet deeplink (`<walletUrl>/?scenario=…&endpoint=…&verifier=…`, matching the demo's proven format) + a QR SVG.
- `status(sessionId: string): Promise<AskMISession>` — returns the current session; fail-closed to `expired` past TTL; `unknown` id → a `failed`/not-found result, never a throw that leaks.
- `complete(sessionId: string, presentation: unknown): Promise<AskMISession>` — runs verifier-sdk `verifyPresentation` (which uses F-14 crypto), stores `verified` (with disclosed claims) or `failed`.

Types:
```ts
interface AskMIRequest { requestedClaims: string[]; purpose: string; }
type AskMISessionStatus = 'pending' | 'verified' | 'failed' | 'expired';
interface AskMISession {
  id: string;
  status: AskMISessionStatus;
  purpose: string;
  claims?: Record<string, unknown>;   // present only when verified
  verifierDid: string;
  createdAt: string;                    // ISO
  verifiedAt?: string;                  // ISO, present only when verified
  reason?: string;                      // present on failed/expired
}
```

### 3.2 `SessionStore` — pluggable, in-memory default
```ts
interface SessionStore {
  get(id: string): Promise<AskMISession | null>;
  set(session: AskMISession): Promise<void>;
  delete(id: string): Promise<void>;
}
```
Ships `InMemorySessionStore` (Map + TTL sweep) as the default. Production users inject Redis/DB — the same "bring-your-own hook" ergonomics as verifier-sdk's `replayCheck`. This is what makes the kit multi-user (vs. the demo's single global).

### 3.3 `express/` — thin binding
`askmiExpress(verifier: AskMIVerifier, opts?): Router` mounting:
- `POST /askmi/begin` → `verifier.begin(req.body)` → `{ sessionId, handoffUrl, qrSvg }`
- `GET  /askmi/status/:id` → `verifier.status(id)`
- `POST /askmi/callback` → `verifier.complete(body.sessionId, body.presentation)`
~50 lines over the core; no core logic here.

### 3.4 `browser/` — the button
- `mountAskMIButton(el: HTMLElement, opts): AskMIButtonHandle` — **vanilla JS**, embeddable in any stack. Renders a branded "Sign in with AskMI" button → on click calls `POST /askmi/begin` → shows the QR + "Open in wallet" deeplink → polls `GET /askmi/status/:id` → on `verified`/`failed` fires `opts.onResult(session)`.
- `<AskMIButton/>` — a thin optional React wrapper over `mountAskMIButton` (the repo's apps are React).

### 3.5 Reference integration
A minimal example (`src/packages/connect/examples/express-minimal/`) — an Express server mounting `askmiExpress` + an HTML page mounting the button — proving the <30-min setup, with a short README walkthrough. Not the full demo.

## 4. Data flow

`mountAskMIButton` → `POST /askmi/begin` (core: verifier-sdk request + `pending` session + handoff URL/QR) → user's wallet presents to the verifier endpoint → `POST /askmi/callback` (core: verifier-sdk `verifyPresentation` + F-14 crypto → `verified`/`failed` session) → button's `status` poll resolves → `onResult(session)` with disclosed claims. The `SessionStore` correlates the three HTTP calls by `sessionId`.

## 5. Error handling (fail-closed)

Every failure path — verification failure, expired session, unknown/replayed session id, malformed presentation, missing config — resolves to a session `status` of **`failed`** or **`expired`** with a `reason`; it is **never** reported as `verified`. Sessions carry a TTL (default 5 min, matching the demo) and fail-closed on expiry. The core's operations never throw raw errors out to the transport in a way that could be read as success; the Express adapter maps `failed`/`expired` to appropriate non-2xx where relevant. Reuses verifier-sdk's crypto guarantees (confidentiality/integrity/authenticity/freshness) + F-14 signature verification.

## 6. Testing (TDD)

- **core:** `begin` (creates pending session + handoff), `status` (pending/verified/expired/unknown), `complete` happy path + every fail-closed path (bad presentation → `failed`; unknown session → `failed`; expired → `expired`). Verification uses **real** verifier-sdk crypto in integration tests (issue a real presentation via shared-crypto helpers, as F-14's tests do), not mocked crypto.
- **SessionStore:** `InMemorySessionStore` get/set/delete + TTL expiry.
- **express:** supertest against the mounted router (begin→status→callback→status verified; and a failed path).
- **browser:** jsdom — button renders, calls begin, polls, fires `onResult` on verified and on failed; fetch mocked at the HTTP boundary (not the core).

## 7. Definition of Done

- [ ] `@askmi/connect` builds (`tsc`) and its tests pass (adds one turbo test task).
- [ ] A developer can, per the reference example, mount `askmiExpress` + drop `mountAskMIButton` and complete a **verified** sign-in against the demo wallet, and a tampered/failed presentation yields `failed` (fail-closed).
- [ ] `SessionStore` is pluggable with a working in-memory default; the kit is multi-session (two concurrent sessions don't collide).
- [ ] The core carries no OIDC or Express types (the OIDC-later seam, §9, holds).
- [ ] Reference example + README document the <30-min setup.
- [ ] `pnpm build` + `pnpm test` (new task included) + `pnpm lint` (0 errors) + `pnpm guard:rebrand` + `pnpm evidence` all green.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Building a *new* verifier surface widens attack surface (the reason SECURE ran first) | The kit adds **no new crypto** — it wraps verifier-sdk + F-14. Fail-closed is the default session state; every non-verified path is `failed`/`expired`. A `@askmi/connect` evidence claim can later be added to the SECURE-2 harness. |
| Session store as a footgun (global/demo-style single session) | Pluggable `SessionStore` with a multi-session in-memory default is a hard DoD item; a concurrency test proves two sessions don't collide. |
| Coupling to Express leaks into the core | The core exposes plain functions + data types only; the Express adapter is a separate module. A test asserts the core module imports no `express`. |
| Over-building toward OIDC now | OIDC is explicitly out of scope; the core just keeps a clean `AskMISession` result the facade can later map. |
| Handoff/deeplink format drift from the wallet | Reuse the exact deeplink shape the demo already uses (`scenario`/`endpoint`/`verifier`), verified live during SECURE-2 inspection. |

## 9. Successor

**ADOPT-2** (separate spec → plan → build): partner/verifier onboarding **registry** + reusable **policy packs** (G-160) so many partners onboard without code changes — built *on* this kit. And the **OIDC facade** (`@askmi/connect/oidc`) wrapping this core, if/when prioritized.
