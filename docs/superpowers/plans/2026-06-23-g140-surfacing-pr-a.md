# G-140 Surfacing PR-A (Substrate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve each requested claim's protection layer at decision time and carry a neutral per-claim sensitivity view through the audit log into the data-flow model — without any visible UI change.

**Architecture:** Sensitivity is a read-only projection of `@askmi/layer-resolver` (`0→low, 1→medium, 2→high, unmapped→unclassified`). The enforcement resolver keeps its safe WELT default; a new non-defaulting sibling powers the honest "unclassified" visibility state. `WalletService.logDisclosureDecision` writes the resolved raw layers onto the existing `POLICY_EVALUATED` event; `DataFlowService` projects them onto a sensitivity map on each transaction.

**Tech Stack:** TypeScript, pnpm 9.15.9 workspaces, turbo, vitest. Packages: `@askmi/layer-resolver`, `@askmi/shared-types`, `@askmi/data-flow`, `@askmi/wallet-pwa`.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-06-22-g140-surfacing-design.md` (Gap E substrate only; Gap D surfacing is PR-B, a separate plan).
- **Neutral / no scoring:** sensitivity is a structural projection with factual labels — never a risk number.
- **Fail-closed untouched:** do NOT change `getMinimumLayerForData`'s WELT default or any policy verdict.
- **Additive only:** every new field is optional; remove nothing; existing tests stay green.
- **Single authority:** the claim→layer mapping lives only in `@askmi/layer-resolver`. `@askmi/shared-types` must stay dependency-free (store the raw layer as `number | null`, do not import the enum).
- **PII-minimal:** claim NAMES only, never values.
- **Commits are signed** (global git config) and end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Branch:** `feat/g140-surfacing` (already created; design doc committed at `c6530c9`).
- **Rebrand guard:** no `did:mitch` / `@mitch/*` tokens introduced.

---

### Task 1: layer-resolver — sensitivity view + non-defaulting resolver + extended map

**Files:**
- Modify: `src/packages/layer-resolver/src/index.ts`
- Test: `src/packages/layer-resolver/test/layer-resolver.test.ts`

**Interfaces:**
- Consumes: existing `ProtectionLayer` enum.
- Produces:
  - `type Sensitivity = 'low' | 'medium' | 'high' | 'unclassified'`
  - `resolveLayerForData(dataType: string): ProtectionLayer | undefined` (no default)
  - `sensitivityFromLayer(layer: ProtectionLayer | undefined | null): Sensitivity`
  - `sensitivityForData(dataType: string): Sensitivity`
  - `getMinimumLayerForData(dataType: string): ProtectionLayer` (unchanged signature/behavior; map extended)

- [ ] **Step 1: Write the failing tests**

Add these imports to the top of `src/packages/layer-resolver/test/layer-resolver.test.ts` (extend the existing import list):

```typescript
import {
    ProtectionLayer,
    getInheritedLayers,
    includesLayer,
    getLayerName,
    getMinimumLayerForData,
    resolveLayerForData,
    sensitivityFromLayer,
    sensitivityForData,
} from '../src/index.js';
```

Append these describe blocks to the end of the same file:

```typescript
describe('resolveLayerForData (visibility path, no default)', () => {
    it('returns the mapped layer for known claims', () => {
        expect(resolveLayerForData('bloodGroup')).toBe(ProtectionLayer.VULNERABLE);
        expect(resolveLayerForData('age')).toBe(ProtectionLayer.GRUNDVERSORGUNG);
        expect(resolveLayerForData('given_name')).toBe(ProtectionLayer.WELT);
    });

    it('returns undefined for unmapped claims (NOT a WELT default)', () => {
        expect(resolveLayerForData('somethingUnknown')).toBeUndefined();
    });
});

describe('sensitivityFromLayer', () => {
    it('projects layers onto low/medium/high', () => {
        expect(sensitivityFromLayer(ProtectionLayer.WELT)).toBe('low');
        expect(sensitivityFromLayer(ProtectionLayer.GRUNDVERSORGUNG)).toBe('medium');
        expect(sensitivityFromLayer(ProtectionLayer.VULNERABLE)).toBe('high');
    });

    it('maps undefined/null to unclassified', () => {
        expect(sensitivityFromLayer(undefined)).toBe('unclassified');
        expect(sensitivityFromLayer(null)).toBe('unclassified');
    });
});

describe('sensitivityForData', () => {
    it('classifies the demo vocabulary', () => {
        expect(sensitivityForData('medication')).toBe('high');
        expect(sensitivityForData('dosageInstruction')).toBe('high');
        expect(sensitivityForData('licenseId')).toBe('high');
        expect(sensitivityForData('age')).toBe('medium');
        expect(sensitivityForData('family_name')).toBe('low');
    });

    it('reports unclassified for unmapped claims', () => {
        expect(sensitivityForData('nonexistentClaim')).toBe('unclassified');
    });
});

describe('getMinimumLayerForData (enforcement default unchanged)', () => {
    it('still defaults unmapped claims to WELT', () => {
        expect(getMinimumLayerForData('somethingUnknown')).toBe(ProtectionLayer.WELT);
    });

    it('classifies newly-added health vocabulary as VULNERABLE', () => {
        expect(getMinimumLayerForData('bloodGroup')).toBe(ProtectionLayer.VULNERABLE);
        expect(getMinimumLayerForData('emergencyContacts')).toBe(ProtectionLayer.VULNERABLE);
    });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pnpm --filter @askmi/layer-resolver test`
Expected: FAIL — `resolveLayerForData is not a function` / `sensitivityFromLayer is not a function` (and `bloodGroup` currently resolves to WELT, not VULNERABLE).

- [ ] **Step 3: Implement in `src/packages/layer-resolver/src/index.ts`**

Replace the existing `getMinimumLayerForData` function (the one with the inline `layerMap`, around lines 178–202) with the following module-scope map + functions. Place `LAYER_MAP` and `Sensitivity` above `getMinimumLayerForData`:

```typescript
/**
 * Neutral sensitivity view over a protection layer. NOT a risk score —
 * a structural projection of the layer the policy engine resolved.
 */
export type Sensitivity = 'low' | 'medium' | 'high' | 'unclassified';

/**
 * Single source of truth: claim/data type → minimum protection layer.
 * Shared by getMinimumLayerForData (enforcement, safe WELT default) and
 * resolveLayerForData (visibility, honest `undefined` when unmapped).
 */
const LAYER_MAP: Record<string, ProtectionLayer> = {
  // Layer 0 (WELT) — Universal / identity basics
  consent: ProtectionLayer.WELT,
  publicKey: ProtectionLayer.WELT,
  given_name: ProtectionLayer.WELT,
  family_name: ProtectionLayer.WELT,

  // Layer 1 (GRUNDVERSORGUNG) — Children + Basic
  age: ProtectionLayer.GRUNDVERSORGUNG,
  dateOfBirth: ProtectionLayer.GRUNDVERSORGUNG,
  birth_date: ProtectionLayer.GRUNDVERSORGUNG,
  education: ProtectionLayer.GRUNDVERSORGUNG,

  // Layer 2 (VULNERABLE) — Health / Finance / Professional
  healthRecord: ProtectionLayer.VULNERABLE,
  medicalHistory: ProtectionLayer.VULNERABLE,
  prescription: ProtectionLayer.VULNERABLE,
  financialData: ProtectionLayer.VULNERABLE,
  bankAccount: ProtectionLayer.VULNERABLE,
  creditScore: ProtectionLayer.VULNERABLE,
  employmentRecord: ProtectionLayer.VULNERABLE,
  professionalLicense: ProtectionLayer.VULNERABLE,
  // EHDS / health demo vocabulary
  bloodGroup: ProtectionLayer.VULNERABLE,
  allergies: ProtectionLayer.VULNERABLE,
  emergencyContacts: ProtectionLayer.VULNERABLE,
  medication: ProtectionLayer.VULNERABLE,
  dosageInstruction: ProtectionLayer.VULNERABLE,
  refillsRemaining: ProtectionLayer.VULNERABLE,
  // Professional credential demo vocabulary
  role: ProtectionLayer.VULNERABLE,
  licenseId: ProtectionLayer.VULNERABLE,
};

/**
 * Determine the minimum required layer for a given data type.
 * ENFORCEMENT path — keeps the safe WELT default for unmapped types.
 *
 * @example
 * getMinimumLayerForData('age');         // ProtectionLayer.GRUNDVERSORGUNG
 * getMinimumLayerForData('healthRecord'); // ProtectionLayer.VULNERABLE
 */
export function getMinimumLayerForData(dataType: string): ProtectionLayer {
  return LAYER_MAP[dataType] ?? ProtectionLayer.WELT;
}

/**
 * VISIBILITY path — returns the claim's protection layer, or `undefined`
 * when the claim is not classified. Unlike getMinimumLayerForData this does
 * NOT default to WELT, so the UI can honestly show "unclassified" instead of
 * a false "low". Same LAYER_MAP authority.
 */
export function resolveLayerForData(dataType: string): ProtectionLayer | undefined {
  return LAYER_MAP[dataType];
}

/** Project a protection layer onto a neutral sensitivity view (no scoring). */
export function sensitivityFromLayer(
  layer: ProtectionLayer | undefined | null
): Sensitivity {
  switch (layer) {
    case ProtectionLayer.WELT:
      return 'low';
    case ProtectionLayer.GRUNDVERSORGUNG:
      return 'medium';
    case ProtectionLayer.VULNERABLE:
      return 'high';
    default:
      return 'unclassified';
  }
}

/** Convenience: claim name → neutral sensitivity view. */
export function sensitivityForData(dataType: string): Sensitivity {
  return sensitivityFromLayer(resolveLayerForData(dataType));
}
```

Then extend the `default` export object at the bottom of the file to include the new functions:

```typescript
export default {
  ProtectionLayer,
  getInheritedLayers,
  includesLayer,
  getLayerName,
  getMinimumLayerForData,
  resolveLayerForData,
  sensitivityFromLayer,
  sensitivityForData,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pnpm --filter @askmi/layer-resolver test`
Expected: PASS (all existing tests + the four new describe blocks).

- [ ] **Step 5: Commit**

```bash
git add src/packages/layer-resolver/src/index.ts src/packages/layer-resolver/test/layer-resolver.test.ts
git commit -m "feat(layer-resolver): add sensitivity view + non-defaulting resolver, extend claim map" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Enrich POLICY_EVALUATED with per-claim layers

**Files:**
- Modify: `src/packages/shared-types/src/audit.ts:79-91` (extend `DisclosureDecisionMetadata`)
- Modify: `src/apps/wallet-pwa/package.json` (add layer-resolver dependency)
- Modify: `src/apps/wallet-pwa/src/services/WalletService.ts` (import + `logDisclosureDecision`)
- Test: `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts`

**Interfaces:**
- Consumes: `resolveLayerForData` from Task 1.
- Produces: `DisclosureDecisionMetadata.requested_claim_layers?: Record<string, number | null>` populated on every `POLICY_EVALUATED` event (raw `ProtectionLayer` value, `null` = unclassified).

- [ ] **Step 1: Add the type field (compiles the test below)**

In `src/packages/shared-types/src/audit.ts`, inside `interface DisclosureDecisionMetadata`, add after `source: 'policy_engine';`:

```typescript
    /**
     * Per requested-claim protection layer, resolved at decision time
     * (G-140 surfacing). Value is a ProtectionLayer (0=WELT, 1=GRUNDVERSORGUNG,
     * 2=VULNERABLE); null = unclassified (claim not in the layer map). Raw layer
     * kept here for audit; the UI projects it onto a neutral low/medium/high view.
     * Optional → backward-compatible. Names only, never values.
     */
    requested_claim_layers?: Record<string, number | null>;
```

- [ ] **Step 2: Add the workspace dependency**

In `src/apps/wallet-pwa/package.json`, add to `dependencies` (alongside `@askmi/data-flow`):

```json
    "@askmi/layer-resolver": "workspace:*",
```

Then link it:

Run: `pnpm install`
Expected: lockfile updates; `@askmi/layer-resolver` linked into wallet-pwa.

- [ ] **Step 3: Write the failing test**

Append to `src/apps/wallet-pwa/src/__tests__/WalletService.test.ts` inside the top-level `describe` block (reuse the existing `wallet` instance set up in `beforeEach`):

```typescript
  it('POLICY_EVALUATED carries per-claim layers, with unmapped claims as null', async () => {
    await wallet.evaluateRequest(
      {
        verifierId: 'did:askmi:verifier-liquor-store',
        nonce: crypto.randomUUID(),
        requirements: [
          {
            credentialType: 'HealthCredential',
            requestedClaims: ['bloodGroup', 'age', 'totallyUnknownClaim'],
          },
        ],
      },
      { timestamp: Date.now(), userDID: 'did:askmi:wallet-holder' }
    );

    const evt = wallet
      .getRecentAuditLogs(20)
      .find((e) => e.action === 'POLICY_EVALUATED');
    expect(evt, 'expected a POLICY_EVALUATED event').toBeDefined();

    const layers = (evt!.metadata as Record<string, unknown>)[
      'requested_claim_layers'
    ] as Record<string, number | null>;
    expect(layers['bloodGroup']).toBe(2); // VULNERABLE
    expect(layers['age']).toBe(1); // GRUNDVERSORGUNG
    expect(layers['totallyUnknownClaim']).toBeNull(); // unclassified
  });
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "POLICY_EVALUATED carries per-claim layers"`
Expected: FAIL — `requested_claim_layers` is `undefined`.

- [ ] **Step 5: Implement the enrichment**

In `src/apps/wallet-pwa/src/services/WalletService.ts`, add the import near the other `@askmi/*` imports at the top of the file:

```typescript
import { resolveLayerForData } from '@askmi/layer-resolver';
```

In `logDisclosureDecision`, after the `const denied = ...` line (currently `:863`) and before the `metadata` object, add:

```typescript
      const requestedClaimLayers: Record<string, number | null> = {};
      for (const claim of requested) {
        requestedClaimLayers[claim] = resolveLayerForData(claim) ?? null;
      }
```

Then add this field to the `metadata` object literal (after `source: 'policy_engine',`):

```typescript
        requested_claim_layers: requestedClaimLayers,
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "POLICY_EVALUATED carries per-claim layers"`
Expected: PASS.

- [ ] **Step 7: Run the full wallet-pwa + shared-types suites (no regressions)**

Run: `pnpm --filter @askmi/wallet-pwa test && pnpm --filter @askmi/shared-types test`
Expected: PASS (existing PR1 `POLICY_EVALUATED` tests still green; the new optional field is additive).

- [ ] **Step 8: Commit**

```bash
git add src/packages/shared-types/src/audit.ts src/apps/wallet-pwa/package.json pnpm-lock.yaml src/apps/wallet-pwa/src/services/WalletService.ts src/apps/wallet-pwa/src/__tests__/WalletService.test.ts
git commit -m "feat(G-140): record per-claim protection layers on POLICY_EVALUATED" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: data-flow projects per-claim sensitivity onto transactions

**Files:**
- Modify: `src/packages/data-flow/package.json` (add layer-resolver dependency)
- Modify: `src/packages/data-flow/src/types.ts` (add `claimSensitivity?`)
- Modify: `src/packages/data-flow/src/service.ts` (read `requested_claim_layers`, project)
- Test: `src/packages/data-flow/src/__tests__/service.test.ts`

**Interfaces:**
- Consumes: `Sensitivity` + `sensitivityFromLayer` from Task 1; `requested_claim_layers` from Task 2.
- Produces: `DataFlowTransaction.claimSensitivity?: Record<string, Sensitivity>`.

- [ ] **Step 1: Add the workspace dependency**

In `src/packages/data-flow/package.json`, add to `dependencies` (alongside `@askmi/shared-types`):

```json
    "@askmi/layer-resolver": "workspace:*",
```

Then link it:

Run: `pnpm install`
Expected: lockfile updates; `@askmi/layer-resolver` linked into data-flow.

- [ ] **Step 2: Add the type field**

In `src/packages/data-flow/src/types.ts`, add the import at the top (after the existing `@askmi/shared-types` import):

```typescript
import type { Sensitivity } from '@askmi/layer-resolver';
```

Add this field to `interface DataFlowTransaction` (after the `verdict?` field):

```typescript
  /**
   * Per requested-claim sensitivity (G-140 surfacing), projected from the
   * protection layer resolved at decision time (POLICY_EVALUATED →
   * requested_claim_layers). Neutral view, no scoring. Optional/back-compat.
   */
  claimSensitivity?: Record<string, Sensitivity>;
```

- [ ] **Step 3: Write the failing test**

Append to `src/packages/data-flow/src/__tests__/service.test.ts` inside the top-level `describe('DataFlowService', ...)` block. Use a self-contained entry builder so this test does not depend on existing helpers:

```typescript
  it('projects requested_claim_layers onto neutral claim sensitivities', () => {
    const DEC = 'dec-sensitivity-1';
    const mkEntry = (
      action: AuditLogEntry['action'],
      metadata: Record<string, unknown>
    ): AuditLogEntry => ({
      id: crypto.randomUUID(),
      timestamp: '2026-03-15T10:00:00Z',
      previousHash: '0'.repeat(64),
      currentHash: 'a'.repeat(64),
      action,
      metadata,
    });

    const entries: AuditLogEntry[] = [
      mkEntry('POLICY_EVALUATED', {
        decision_id: DEC,
        verifier_did: 'did:askmi:verifier-hospital',
        verdict: 'ALLOW',
        requested_claims: ['bloodGroup', 'age', 'mysteryClaim'],
        authorized_claims: ['bloodGroup', 'age'],
        denied_claims: [],
        reason_codes: [],
        source: 'policy_engine',
        requested_claim_layers: { bloodGroup: 2, age: 1, mysteryClaim: null },
      }),
    ];

    const [tx] = new DataFlowService().buildTransactions(entries);
    expect(tx.claimSensitivity).toEqual({
      bloodGroup: 'high',
      age: 'medium',
      mysteryClaim: 'unclassified',
    });
  });

  it('leaves claimSensitivity undefined when no layers were logged (back-compat)', () => {
    const DEC = 'dec-no-layers';
    const entry: AuditLogEntry = {
      id: crypto.randomUUID(),
      timestamp: '2026-03-15T10:00:00Z',
      previousHash: '0'.repeat(64),
      currentHash: 'a'.repeat(64),
      action: 'VP_GENERATED',
      metadata: {
        decision_id: DEC,
        verifier_did: 'did:askmi:verifier-liquor-store',
        claims_shared: ['age'],
      },
    };
    const [tx] = new DataFlowService().buildTransactions([entry]);
    expect(tx.claimSensitivity).toBeUndefined();
  });
```

Ensure `AuditLogEntry` is imported in the test file (add to the existing `@askmi/shared-types` type import if not already present):

```typescript
import type { AuditLogEntry } from '@askmi/shared-types';
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `pnpm --filter @askmi/data-flow test`
Expected: FAIL — `tx.claimSensitivity` is `undefined` for the first test (assertion expects the mapped object).

- [ ] **Step 5: Implement the projection in `src/packages/data-flow/src/service.ts`**

Add the import at the top (after the existing imports):

```typescript
import { sensitivityFromLayer, type Sensitivity } from '@askmi/layer-resolver';
```

Inside `buildTransactions`, after the `const verdict = ...` line (currently `:48`), add:

```typescript
      // G-140 surfacing: project the per-claim protection layers (logged on the
      // disclosure event) onto a neutral sensitivity view. No re-resolution here —
      // we read exactly what the engine classified at decision time.
      let claimSensitivity: Record<string, Sensitivity> | undefined;
      const rawLayers = disclosureEvent?.metadata?.requested_claim_layers as
        | Record<string, number | null>
        | undefined;
      if (rawLayers) {
        claimSensitivity = {};
        for (const [claim, layer] of Object.entries(rawLayers)) {
          claimSensitivity[claim] = sensitivityFromLayer(layer as number | null);
        }
      }
```

Add `claimSensitivity` to the `transactions.push({ ... })` object (after `verdict,`):

```typescript
        claimSensitivity,
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pnpm --filter @askmi/data-flow test`
Expected: PASS (both new tests + all existing data-flow tests).

- [ ] **Step 7: Commit**

```bash
git add src/packages/data-flow/package.json pnpm-lock.yaml src/packages/data-flow/src/types.ts src/packages/data-flow/src/service.ts src/packages/data-flow/src/__tests__/service.test.ts
git commit -m "feat(G-140): project per-claim sensitivity onto data-flow transactions" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Full-suite verification gate

**Files:** none (verification only).

- [ ] **Step 1: Run the full monorepo test suite**

Run: `pnpm test`
Expected: all turbo `test` tasks PASS (no regressions in policy-engine, integration-tests, verifier-demo, etc.).

- [ ] **Step 2: Run the rebrand guard**

Run: `pnpm guard:rebrand`
Expected: PASS — no `did:mitch` / `@mitch/*` tokens (this change introduces none).

- [ ] **Step 3: Push the branch and open PR-A**

```bash
git push -u origin feat/g140-surfacing
gh pr create --base master --head feat/g140-surfacing \
  --title "feat(G-140): surfacing PR-A — per-claim sensitivity substrate" \
  --body "Substrate for the G-140 surfacing follow-up (Gap E). Sensitivity as a read-only projection of layer-resolver (0/1/2 -> low/med/high, unmapped -> unclassified), recorded on POLICY_EVALUATED and projected onto data-flow transactions. No visible UI change (that is PR-B). Spec: docs/superpowers/specs/2026-06-22-g140-surfacing-design.md.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

Expected: PR opens against `master`; required checks (Build & Test, security, CodeQL, Layer Protection Validation, Dependency Security Audit) start. Note: branch protection is `strict` — update-branch + wait CI before merge.

---

## Self-Review

**Spec coverage:**
- Spec §5 PR-A/A1 (extend map + non-defaulting resolver + sensitivity view) → Task 1. ✔
- Spec §5 PR-A/A2 (audit field, `number | null`, optional) → Task 2 Step 1. ✔
- Spec §5 PR-A/A3 (`logDisclosureDecision` populates it) → Task 2 Steps 5–6. ✔
- Spec §5 PR-A/A4 (data-flow carries per-claim sensitivity) → Task 3. ✔
- Spec §7 invariants (enforcement default unchanged, additive, neutral) → Task 1 guard test + Task 3 back-compat test + Task 4 gate. ✔
- Spec §5 PR-B (DataFlowPanel badges + remove toggle) → intentionally OUT of this plan (separate PR-B plan after PR-A merges). ✔

**Placeholder scan:** none — every code/test step shows full content; every command has expected output.

**Type consistency:** `Sensitivity`, `resolveLayerForData`, `sensitivityFromLayer`, `sensitivityForData` defined in Task 1 and used with identical names/signatures in Tasks 2–3. Audit field `requested_claim_layers: Record<string, number | null>` defined in Task 2 and read with the same shape in Task 3. `DataFlowTransaction.claimSensitivity?: Record<string, Sensitivity>` defined and populated consistently. ✔
