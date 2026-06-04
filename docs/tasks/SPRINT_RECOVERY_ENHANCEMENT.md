# Sprint Plan: Recovery, Hardening & Sovereignty (Phase 6b)

**Status:** Epic 1 complete; wallet recovery RC accepted on `master`
**Objective:** Safely restore security patches, integrate the Sovereignty Center UI without modifying the core architecture, polish existing components, and prepare the MCP Server for the "Agentic Future".
**Rule of Engagement:** STRICT NON-DESTRUCTIVE MODE. No architectural refactoring. No deletion of core files.
**Recovery Gate:** `v1.0.1-wallet-recovery-rc` on commit `f2a6ae1`; wallet flow accepted on canonical port `5174`, verifier `3004`, issuer `3005`.

---

## Epic 1: Security & Hardening (Immediate Fixes)
*Restore the security posture lost during the rollback.*

### Task 1.1: Dependency Patch (Vitest RCE) — DONE
- **Target:** Monorepo-wide Vitest usage, not only `src/apps/wallet-pwa/package.json`.
- **Action:** Update Vitest consistently across the workspace and keep the lockfile/audit gate clean.
- **Acceptance Criteria:** `pnpm audit` shows no known vulnerabilities.

### Task 1.2: Anti-Fingerprinting Wiring (U-22 / U-23) — DONE
- **Target:** `src/apps/wallet-pwa/src/App.tsx`
- **Action:** In the `proceedWithProof` function (around line 315), import and apply `padPayload`, `applyJitter`, and `UNIFORM_HEADERS` from `src/apps/wallet-pwa/src/utils/anti-fingerprinting.ts`.
- **Acceptance Criteria:** The fetch request to the verifier endpoint includes uniform headers, the payload is padded to a fixed block size, and a random delay (jitter) is applied before sending.

### Task 1.3: Recovery Flow Regression Gate — DONE
- **Target:** `wallet-pwa` + `verifier-backend`
- **Action:** Restore age predicate proof verification for the recovered demo credential shape and current verifier predicate result shape.
- **Acceptance Criteria:** Wallet seed render, OID4VCI issuance, Age Proof, Doctor Login, ER Access, and Pharmacy flows pass on `5174` / `3004` / `3005`.

---

## Epic 2: Visual Sovereignty ("miTch Insights" Restoration)
*Safely re-introduce the Data Value Ticker and Exposure Heatmap.*

**Current status:** Analysis/prep only. Do not merge UI work into `master` until the
recovery RC remains stable and the audit-log metadata contract is reconciled.

### Task 2.1: Data Aggregation Engine
- **Target:** `src/packages/data-flow/src/InsightAggregator.ts` (New File), `src/packages/data-flow/src/summary.ts` (Update), `src/packages/data-flow/src/index.ts` (Update)
- **Action:** Implement the `InsightAggregator` class as a pure function that takes `AuditLogEntry[]` and returns `InsightMetrics`. Do NOT touch `@mitch/wallet-core`.
- **Acceptance Criteria:** Aggregator correctly calculates "Data Value Retained" based on non-disclosed claims and builds an exposure heatmap array.

### Task 2.2: Sovereignty Center UI Component
- **Target:** `src/apps/wallet-pwa/src/components/SovereigntyCenter.tsx` (New File)
- **Action:** Build the "Facts First" React component. It receives `AuditLogEntry[]` as a prop. Uses `InsightAggregator` internally. No external state dependencies.
- **Acceptance Criteria:** Component renders a professional dashboard. "Estimated Value" and "Projections" are hidden behind an expandable button.

### Task 2.3: App Integration
- **Target:** `src/apps/wallet-pwa/src/App.tsx`
- **Action:** Add a `showSovereignty` boolean state. Add a "🛡️ Sovereignty Center" button to the sidebar. Render `<SovereigntyCenter>` conditionally.
- **Acceptance Criteria:** Modal opens and closes correctly. Existing wallet flows remain 100% unaffected.

---

## Epic 3: Verifier Reputation Network (VRN)
*Implement the watchdog sensor.*

### Task 3.1: Reputation Schema
- **Target:** `src/packages/shared-types/src/reputation.ts` (New File), `src/packages/shared-types/src/index.ts` (Update)
- **Action:** Define `VerifierReportCard` interface.
- **Acceptance Criteria:** Schema is available across the monorepo.

### Task 3.2: Sensor Engine
- **Target:** `src/packages/wallet-core/src/ReputationSensor.ts` (New File), `src/packages/wallet-core/src/index.ts` (Update)
- **Action:** Implement pure function `ReputationSensor.generateReport(request, capsule, trackers)`.
- **Acceptance Criteria:** Correctly detects "over-requesting" (e.g., asking for `birthDate` when `age >= 18` is proven).

### Task 3.3: Reporting UI
- **Target:** `src/apps/wallet-pwa/src/components/ConsentModal.tsx`, `src/apps/wallet-pwa/src/App.tsx`
- **Action:** Add an `onReportReputation` callback to `ConsentModal`. Implement the callback in `App.tsx` to generate and locally store the report.
- **Acceptance Criteria:** User can click "Report bad behavior" in the consent modal. A log entry confirms the report generation.

---

## Epic 4: UX Polish (Consent Manager)
*Align the Consent Manager with the Wallet's design system.*

### Task 4.1: Styling Update
- **Target:** `src/apps/wallet-pwa/src/components/ConsentManagerPanel.tsx`, `src/apps/wallet-pwa/src/wallet.css`
- **Action:** Apply CSS grid, glassmorphism/gradient backgrounds, and standard `wallet.css` button classes to the Consent Manager. Remove inline styles where appropriate.
- **Acceptance Criteria:** The Consent Manager visually matches the high-quality look of the Credential Cards and the Consent Modal.

---

## Epic 5: The Agentic Future (CI-01)
*Prepare miTch for AI integration.*

### Task 5.1: MCP Server Implementation
- **Target:** `src/packages/mcp-server/src/index.ts`
- **Action:** Transition the server from a stub to a functional Model Context Protocol implementation. Expose tools for an LLM to query the `PolicyEngine` (e.g., `evaluate_request_intent`).
- **Acceptance Criteria:** An AI agent (like Claude Desktop) can connect to the MCP server, ask "Am I allowed to share age with a liquor store?", and receive a deterministic `ALLOW` or `DENY` response based on the active policy, without accessing real PII.
