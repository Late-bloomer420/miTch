# G-140 Follow-up — Sensitivity View + First-Class DataFlowPanel (Gap D + E)

**Status:** Design — awaiting approval
**Date:** 2026-06-22
**Author:** Lumen (with J F M / miTch)
**Relates to:** `docs/_core/09_LAYER2_VISIBILITY_PLAN.md` §4 "Follow-up — Surfacing (Gap D + E)"
**Predecessors (merged):** PR1 #112, PR2 #114, PR3 #115, PR4 #116

---

## 1. Context

The G-140.1 Layer-2-Visibility code chain is closed on master:

- **#112** — log ALL raw `requested_claims` on every verdict (`POLICY_EVALUATED` / `DisclosureDecisionMetadata`).
- **#114** — `data-flow` reads the denied side; DENY produces a transaction.
- **#115** — proximity/mdoc gets `decision_id` + `claims_requested`.
- **#116** — proximity mdoc is policy-routed before disclosure.

The plan explicitly parked the **Surfacing follow-up (Gap D + E)** as *"nicht Teil der geschlossenen G-140.1-Kette; nur starten, wenn konkret priorisiert."* It is now prioritized. Two gaps remain:

- **Gap D** — `DataFlowPanel` is a demo toggle (`App.tsx:1711`, default `showDataFlow=false`), not an always-reachable view.
- **Gap E** — no request-sensitivity classification (`specs/36` Track A1: low/medium/high).

## 2. Decisions (settled with user, 2026-06-22)

1. **Sensitivity = a read-only view over the existing layer classification.** Map: `ProtectionLayer.WELT(0)→low`, `GRUNDVERSORGUNG(1)→medium`, `VULNERABLE(2)→high`. No second classification authority; `layer-resolver` stays canonical.
2. **Unmapped claims render as `unclassified`** — never a false "low." A **visibility map** (superset of the enforcement map) covers the real demo vocabulary; anything still unmapped is honestly `unclassified`. *(Updated post-implementation: the demo vocabulary lives in a separate `VISIBILITY_LAYER_MAP`, not the enforcement `LAYER_MAP` — see §4.)*
3. **Sensitivity is sourced from the audit event**, not recomputed in the UI — the value shown is exactly what the engine resolved at decision time.
4. **`DataFlowPanel` becomes a permanent wallet section** — the hide-toggle is removed; per-transaction expand/collapse stays.
5. `unclassified` is a **neutral factual state**, not a warning/alarm level.

## 3. Why this is neutral-by-construction

The core invariant (`02_POLICY.md`, plan §5) forbids scoring and value judgments. By making sensitivity a *projection* of `layer-resolver` output rather than a new model:

- The UI cannot assert a sensitivity the policy engine did not already resolve structurally.
- There is exactly one place to change the mapping (`layer-resolver` — one file holding both the enforcement base and the visibility superset).
- The honesty invariant holds: we never label a claim "low" when we never classified it — we say `unclassified`.

This mirrors PR1's discipline (measure withheld against the *raw* request, not a recomputed set): derive, don't duplicate.

## 4. The resolver problem (why this needs a resolver change, not just a label)

`getMinimumLayerForData(dataType)` (`layer-resolver/src/index.ts:178`) **defaults unknown → `WELT(0)`**. So today "genuinely Layer 0" and "never classified" are indistinguishable, and most demo claims (`given_name`, `bloodGroup`, `allergies`, `medication`, `licenseId`, `emergencyContacts`, …) are unmapped and would show as "low."

Resolution — two read modes over two maps in one file (`layer-resolver`):

- **Enforcement path** keeps `getMinimumLayerForData` reading the original `LAYER_MAP` with its safe WELT default — **unchanged**.
- **Visibility path** uses a new non-defaulting `resolveLayerForData` reading `VISIBILITY_LAYER_MAP` (a `{ ...LAYER_MAP, ...demoVocabulary }` superset), returning `undefined` for still-unmapped claims so the UI can show `unclassified` truthfully.

**Why two maps, not one (discovered during PR-A implementation):** `getMinimumLayerForData` is also consumed by the **policy-engine's layer-violation check**. Putting the demo vocabulary (`bloodGroup`, `medication`, `role`, …) directly into the enforcement `LAYER_MAP` raised the required layer for those claims and **changed policy verdicts** — it broke 23 EHDS break-glass / geo-scope / dispensed-credential tests by short-circuiting them with `LAYER_VIOLATION`. This proved the user's condition *"don't add a standalone visibility map unless the layer model is insufficient"* — it **is** insufficient. The superset keeps a single shared base in a single file (one authority) while guaranteeing visibility classification can never alter an enforcement verdict. A guard test asserts `getMinimumLayerForData('bloodGroup') === WELT` to lock this.

## 5. Architecture — two small PRs (E → D)

Sequenced E-before-D because the panel (D) consumes the audit data produced by the substrate (E). Matches the project's "small targeted commits" hygiene and prior PR1→PR2 cadence.

### PR-A — Substrate (no visible UI change)

| # | File | Change |
|---|---|---|
| A1 | `src/packages/layer-resolver/src/index.ts` | Add `VISIBILITY_LAYER_MAP = { ...LAYER_MAP, ...demoVocabulary }` (the real demo vocabulary). Add `resolveLayerForData(dataType): ProtectionLayer \| undefined` (no default, reads the visibility map), `sensitivityFromLayer(...)` and `sensitivityForData(dataType): Sensitivity`. Leave enforcement `LAYER_MAP` / `getMinimumLayerForData` **unchanged** (guard test enforces this). |
| A2 | `src/packages/shared-types/src/audit.ts` | Add optional `requested_claim_layers?: Record<string, number \| null>` to `DisclosureDecisionMetadata` (raw `ProtectionLayer` value `0/1/2`, kept as `number` so `shared-types` stays dependency-free; `null` = unclassified). Optional → back-compatible. |
| A3 | `src/apps/wallet-pwa/src/services/WalletService.ts` | In `logDisclosureDecision`, populate `requested_claim_layers` for each entry in `requested_claims` via `resolveLayerForData`. |
| A4 | `src/packages/data-flow/src/{types,service}.ts` | Carry optional per-claim sensitivity onto `DataFlowTransaction` (mirrors how #114 added `verdict`). Read from the `POLICY_EVALUATED` event. |

New shared type: `type Sensitivity = 'low' | 'medium' | 'high' | 'unclassified'`.

### PR-B — Surfacing

| # | File | Change |
|---|---|---|
| B1 | `src/apps/wallet-pwa/src/components/DataFlowPanel.tsx` | Render a neutral sensitivity badge per claim tag, derived from the audit-resolved layer (not recomputed). `unclassified` rendered as a plain neutral chip. |
| B2 | `src/apps/wallet-pwa/src/App.tsx` (~:1711) | Remove the `showDataFlow` toggle; render `DataFlowPanel` as a permanent first-class wallet section. |

## 6. Data flow

```
verifier request (raw requested_claims)
  → WalletService.evaluateRequest (policy-engine, unchanged enforcement)
  → logDisclosureDecision: POLICY_EVALUATED + DisclosureDecisionMetadata
        + requested_claim_layers { claim → ProtectionLayer | null }   [PR-A]
  → audit-log (hash-chained, WORM)
  → DataFlowService.buildTransactions: attach per-claim sensitivity     [PR-A]
  → DataFlowPanel: render claim tag + sensitivity badge                 [PR-B]
```

The UI's `low/medium/high/unclassified` is a pure mapping of the stored layer number/`null`; no re-resolution in the component.

## 7. Invariant guards (checked every PR)

- **Neutral / no scoring** — sensitivity is a structural projection with factual labels; no risk number.
- **Fail-closed** — enforcement default untouched; policy verdicts unchanged.
- **Additive** — all new fields optional; nothing removed; existing tests stay green.
- **Role separation** — sensitivity is a Convener-side visibility fact, not issuer/verifier data.
- **Honesty** — `unclassified` never claims "low"; raw layer kept for audit.

## 8. Testing (TDD — test first per PR)

- `layer-resolver`: new vocabulary entries resolve to expected layers; unmapped → `undefined`; `sensitivityForData` mapping incl. `unclassified`.
- `shared-types`: optional field is back-compatible (runtime-validation test).
- `WalletService`: `POLICY_EVALUATED` carries `requested_claim_layers`, including an unmapped claim → `null`.
- `data-flow` service: transaction carries per-claim sensitivity.
- `DataFlowPanel`: high-sensitivity claim shows the badge; unmapped claim shows `unclassified`.
- `App`: `DataFlowPanel` always rendered; toggle removed (update existing assertion).

Full suite (`turbo`) + `guard:rebrand` must stay green; validate on master after each merge before claiming done.

## 9. Out of scope (flagged, not touched)

- **Enforcement default:** unknown → `WELT(0)` is the *lowest* protection, which is arguably not fail-closed for enforcement either. Changing it risks policy tests and is a separate decision. Flagged only. **PR-A confirmed the stakes:** the policy-engine's layer check actively under-protects the demo health vocabulary (treats `bloodGroup`/`medication`/`role` as WELT). The visibility view now *surfaces* this gap (it shows them as `high`) without changing enforcement — a candidate for a future enforcement-map review, tracked separately.
- **Sensitivity as an *input* to `minimumLayer`:** plan §4 mentions sensitivity feeding `minimumLayer`. This design takes the inverse, simpler direction (layer → sensitivity view) per the user's decision. A future change could let sensitivity refine layer resolution; not here.
- **Top-level nav/tab** for the panel (option C) — out; permanent section is enough.

## 10. Companion

Pilot finding **AI-04** ("audit export format/schema not specified", Open P1) touches the same `POLICY_EVALUATED` metadata. The new `requested_claim_layers` field should be included whenever AI-04's export schema is specified. Noted, not blocking.
