# Execution Plan — Epic 4 (UX Polish) & Epic 5 (MCP Integration)

Date: 2026-06-06 · Mode: Scout & Advisor (all work on `proposal/*` branches, no
direct commits to `master`).

This document records the corrected, executed plan for Epics 4 and 5. It
supersedes the first-draft plan (which had been written without inspecting the
codebase). Each epic notes what the draft assumed, what the code actually was,
and what was done.

---

## Epic 4 — Consent Manager UX Polish

**Branch:** `proposal/epic4-ux-polish` · **PR:** #77

### Draft assumption vs. reality
- **Assumed:** `ConsentManagerPanel.tsx` was an already-styled component full of
  inline styles and flat lists to modernise; validation would re-run an existing
  `ConsentManagerPanel.test.tsx`.
- **Reality:**
  1. The panel already used a clean `consent-manager-panel__*` BEM class
     contract — but **no matching stylesheet existed in any CSS file**. The
     panel rendered effectively unstyled. The real gap was a *missing
     stylesheet*, not inline-style debt.
  2. The only inline styles were in the `StateBadge` sub-component (a hardcoded
     light-palette).
  3. The referenced test `ConsentManagerPanel.test.tsx` **did not exist** — so
     "ensure tests still pass" was impossible as written.

### What was done
1. Authored the missing `UX-09: Consent Manager Panel` section in
   `src/apps/wallet-pwa/src/wallet.css`, mirroring the `credential-card` design
   language and reusing the shared `--accent-*` / `--text-*` tokens from
   `App.css`.
2. Status badges via design tokens: green `SUCCESS`, red `DENIED`, amber
   `ERROR`. CSS Grid/Flex layouts for summary, claim cards, and the receipt
   history; responsive collapse `< 480px`.
3. Refactored `StateBadge` to themed CSS classes — panel now has **zero inline
   styles**.
4. Wrote `ConsentManagerPanel.test.tsx` (10 tests) pinning the structural
   contract the CSS hooks into.

### Constraints honoured
UI only — no React state or business logic changed.

### Validation
- `pnpm --filter @askmi/wallet-pwa build` → ✓ (tsc + vite)
- `pnpm --filter @askmi/wallet-pwa test` → ✓ **105 / 105** (baseline 95; +10 new)

---

## Epic 5 — MCP Integration (CI-01)

**Branch:** `proposal/epic5-mcp-wiring` · **PR:** _(see PR link)_

### Draft assumption vs. reality
- **Assumed:** `@askmi/mcp-server` was a dormant, near-empty stub; the task was
  to invent a new tool `evaluate_request_intent` with a camelCase schema and
  wire it up.
- **Reality:**
  1. The server already had real structure: a server factory (`index.ts`), a
     functional fail-closed **stub** tool `askmi_evaluate_disclosure`, a test
     suite, and a full architecture spec (`docs/mcp-server-architecture.md`).
  2. A new `evaluate_request_intent` tool would have **forked** the existing,
     richer `askmi_evaluate_disclosure` contract and **violated** the repo's
     `snake_case` + `askmi_*` naming convention.
  3. **Critically:** the architecture doc (§10.3–10.5) had **deliberately
     frozen** the disclosure wiring — "build nothing, hold stub discipline" —
     because an embedded default policy would produce real decisions without an
     authorised policy source. The draft ignored this.

### Decision: thaw, but preserve the freeze's intent
The freeze was a reasoned privacy decision, not a TODO. Rather than silently
overriding it, the wiring was treated as an explicit **thaw** (recorded in
architecture §11), with the original concern preserved:

- **Did not** create a new tool. Wired the existing `askmi_evaluate_disclosure`.
- **Mock scope, not embedded default** (`src/server-scope.ts`): the engine runs
  for real, but against a synthetic, clearly-labelled policy **and** credential
  inventory. Nothing is authoritative; every response is tagged `scope: "mock"`.
  The real-wallet path (`MITCH_WALLET_DB`, §9.2) stays open and simply replaces
  this module later — the tool contract is unchanged.

### What was done
1. `src/server-scope.ts` — non-authoritative mock policy + credentials with a
   deterministic verdict matrix (liquor-store → ALLOW, hospital → PROMPT, else →
   DENY fail-closed).
2. `src/sanitize.ts` — the **Controlled Insight** boundary. Reduces the rich
   `PolicyEvaluationResult` to a whitelist object; never spreads the engine
   result, so future fields cannot leak. Drops credential ids, issuer DIDs,
   hashes, signatures, pairwise DID, `authorized_requirements`.
3. `src/tools/evaluate-disclosure.ts` — replaced the stub body: maps MCP input →
   engine `VerifierRequest`/`EvaluationContext`, runs `PolicyEngine.evaluate`
   against the mock scope, sanitises the result. Fail-closed `try/catch` →
   `DENY ERR_EVALUATION_FAILED`; errors to stderr only (stdout is the MCP wire).
4. Rewrote the test suite (stub assertions → wired behaviour) and added:
   ALLOW/PROMPT/DENY verdicts, `structuredContent`, Markdown rendering, and a
   **PII-leak guard** asserting credential ids / issuer DIDs / internal fields
   never appear and the output key set is exactly the whitelist.
5. Updated `docs/mcp-server-architecture.md` (§11 thaw) and the package README.

### Security / "Controlled Insight" check (draft Step 5.3)
The sanitiser is the enforcement point and is covered by an explicit leak test.
The agent receives only: `verdict`, `decision_id`, `policy_hash`,
`reason_codes`, `disclosed_claims` (names), `proven_claims` (names), `scope`,
`evaluated_at`.

### Validation
- `pnpm --filter @askmi/mcp-server... build` → ✓ (full dependency chain, tsc)
- `pnpm --filter @askmi/mcp-server test` → ✓ **9 / 9** (baseline 4)
- `pnpm --filter @askmi/mcp-server smoke` → ✓ (built stdio server subprocess,
  tool inventory, ALLOW/PROMPT/DENY matrix, Controlled-Insight leak guard)
- `pnpm turbo run test` → see PR description for the full-sweep result.

---

## Open items / follow-ups
- Real-wallet scope loader (`MITCH_WALLET_DB`) to replace `server-scope.ts` when
  a real consumer needs authoritative decisions (architecture §9.2).
- Read tools (`get_decision`, `list_decisions`, `explain_denial`) remain frozen
  per architecture §10.4 until a concrete audit use-case exists.
