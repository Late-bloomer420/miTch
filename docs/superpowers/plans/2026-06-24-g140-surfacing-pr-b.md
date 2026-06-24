# G-140 Surfacing PR-B (Gap D — Display) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`).

**Goal:** Make per-claim sensitivity visible — render neutral sensitivity badges in `DataFlowPanel` and promote the panel from a hidden toggle to a permanent first-class wallet section.

**Architecture:** Display-only. Reads `DataFlowTransaction.claimSensitivity` (shipped in PR-A). No changes to `layer-resolver`, `POLICY_EVALUATED`, or any policy/substrate code. The UI maps an already-computed `Sensitivity` to a German label + CSS class; it introduces no sensitivity logic.

**Tech Stack:** React 18 + TypeScript, vitest + @testing-library/react, pnpm/turbo.

## Global Constraints

- **Presentation only.** Do not touch `layer-resolver`, `WalletService` policy/audit code, or `data-flow` logic.
- **Source of truth:** `txn.claimSensitivity?.[claimName]` (`'low'|'medium'|'high'|'unclassified'`). Undefined → treat as `unclassified` (honest neutral fallback — never a false "low").
- **Neutral, no scoring:** factual labels (`niedrig/mittel/hoch/unklassifiziert`), muted styling; `high` is a muted rose, not alarm red.
- **No regressions:** claim name must stay in its own inner span so existing `getByText('age')`-style assertions pass.
- **Commits signed**, end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Branch:** `feat/g140-surfacing-pr-b` (off master, created).

---

### Task B1: Sensitivity badges in DataFlowPanel

**Files:**
- Modify: `src/apps/wallet-pwa/src/components/DataFlowPanel.tsx`
- Modify: `src/apps/wallet-pwa/src/wallet.css`
- Test: `src/apps/wallet-pwa/src/__tests__/DataFlowPanel.test.tsx`

- [ ] **Step 1: Write failing tests** (append inside `describe('DataFlowPanel', ...)`):

```tsx
  it('renders a sensitivity badge per claim from the disclosure event', () => {
    const DEC = 'dec-badge-1';
    const entries = [
      makeEntry({
        action: 'POLICY_EVALUATED',
        timestamp: '2026-03-15T10:00:00Z',
        metadata: {
          decision_id: DEC,
          verifier_did: 'did:askmi:verifier-hospital',
          verdict: 'ALLOW',
          requested_claims: ['bloodGroup', 'age'],
          authorized_claims: ['bloodGroup', 'age'],
          denied_claims: [],
          reason_codes: [],
          source: 'policy_engine',
          requested_claim_layers: { bloodGroup: 2, age: 1 },
        },
      }),
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-03-15T10:00:01Z',
        metadata: {
          decision_id: DEC,
          verifier_did: 'did:askmi:verifier-hospital',
          claims_shared: ['bloodGroup', 'age'],
          credential_types: ['HealthCredential'],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    render(<DataFlowPanel entries={entries} />);
    expect(screen.getByText('hoch')).toBeInTheDocument(); // bloodGroup → high
    expect(screen.getByText('mittel')).toBeInTheDocument(); // age → medium
  });

  it('shows the neutral unclassified badge for claims without a resolved layer', () => {
    const DEC = 'dec-badge-2';
    const entries = [
      makeEntry({
        action: 'POLICY_EVALUATED',
        timestamp: '2026-03-15T10:00:00Z',
        metadata: {
          decision_id: DEC,
          verifier_did: 'did:askmi:verifier-test',
          verdict: 'ALLOW',
          requested_claims: ['mysteryClaim'],
          authorized_claims: ['mysteryClaim'],
          denied_claims: [],
          reason_codes: [],
          source: 'policy_engine',
          requested_claim_layers: { mysteryClaim: null },
        },
      }),
      makeEntry({
        action: 'VP_GENERATED',
        timestamp: '2026-03-15T10:00:01Z',
        metadata: {
          decision_id: DEC,
          claims_shared: ['mysteryClaim'],
          verifier_did: 'did:askmi:verifier-test',
          credential_types: [],
          proven_claims: [],
          used_zkp: false,
        },
      }),
    ];
    render(<DataFlowPanel entries={entries} />);
    expect(screen.getByText('unklassifiziert')).toBeInTheDocument();
  });
```

- [ ] **Step 2: Run to verify fail**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "sensitivity badge"`
Expected: FAIL (no 'hoch'/'mittel' text yet).

- [ ] **Step 3: Implement `ClaimTag` in `DataFlowPanel.tsx`**

Add import at top:

```tsx
import type { Sensitivity } from '@askmi/layer-resolver';
```

Add above `TransactionCard`:

```tsx
const SENSITIVITY_LABEL: Record<Sensitivity, string> = {
  low: 'niedrig',
  medium: 'mittel',
  high: 'hoch',
  unclassified: 'unklassifiziert',
};

const ClaimTag: React.FC<{
  claim: string;
  variant: 'claim' | 'proven' | 'withheld';
  sensitivity?: Sensitivity;
}> = ({ claim, variant, sensitivity }) => {
  const level: Sensitivity = sensitivity ?? 'unclassified';
  return (
    <span className={`dataflow-card__tag dataflow-card__tag--${variant}`}>
      <span className="dataflow-card__claim-name">{translateClaim(claim)}</span>
      <span
        className={`dataflow-card__sensitivity dataflow-card__sensitivity--${level}`}
        title={`Sensitivität: ${SENSITIVITY_LABEL[level]}`}
      >
        {SENSITIVITY_LABEL[level]}
      </span>
    </span>
  );
};
```

Replace the three claim `.map` blocks (shared / proven / withheld) in `TransactionCard` with:

```tsx
        {txn.claimsShared.map((claim) => (
          <ClaimTag
            key={claim}
            claim={claim}
            variant="claim"
            sensitivity={txn.claimSensitivity?.[claim]}
          />
        ))}
        {txn.provenClaims.map((claim) => (
          <ClaimTag
            key={claim}
            claim={claim}
            variant="proven"
            sensitivity={txn.claimSensitivity?.[claim]}
          />
        ))}
        {txn.claimsWithheld !== null && txn.claimsWithheld.length > 0 &&
          txn.claimsWithheld.map((claim) => (
            <ClaimTag
              key={`withheld-${claim}`}
              claim={claim}
              variant="withheld"
              sensitivity={txn.claimSensitivity?.[claim]}
            />
          ))}
```

- [ ] **Step 4: Add neutral CSS** to `wallet.css`:

```css
.dataflow-card__sensitivity {
  margin-left: 6px;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 1px 5px;
  border-radius: 6px;
  opacity: 0.85;
  vertical-align: middle;
}
.dataflow-card__sensitivity--low { background: #1e293b; color: #94a3b8; }
.dataflow-card__sensitivity--medium { background: #29304a; color: #cbd5e1; }
.dataflow-card__sensitivity--high { background: #3a2a32; color: #fca5a5; }
.dataflow-card__sensitivity--unclassified { background: #1e293b; color: #64748b; }
```

- [ ] **Step 5: Run to verify pass**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "DataFlowPanel"`
Expected: PASS (new badge tests + all prior DataFlowPanel tests).

- [ ] **Step 6: Commit**

```bash
git add src/apps/wallet-pwa/src/components/DataFlowPanel.tsx src/apps/wallet-pwa/src/wallet.css src/apps/wallet-pwa/src/__tests__/DataFlowPanel.test.tsx
git commit -m "feat(G-140): render neutral per-claim sensitivity badges in DataFlowPanel" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task B2: DataFlowPanel as a permanent first-class section

**Files:**
- Modify: `src/apps/wallet-pwa/src/App.tsx` (state `:122`, `onOpenDataFlow` `:1697`, section `:1710-1715`)
- Test: `src/apps/wallet-pwa/src/App.test.tsx`

- [ ] **Step 1: Write failing test** (append inside `describe('G-03 — Wallet App', ...)`):

```tsx
  it('always shows the data-flow section, with no show/hide toggle (G-140 Gap D)', async () => {
    render(<App />);
    await screen.findByText('Age Credential (GovID)'); // main authenticated view
    // Panel is permanent → its empty-state renders even with no audit logs:
    expect(screen.getByText('Noch keine Transaktionen')).toBeInTheDocument();
    // The old toggle is gone:
    expect(screen.queryByText('Datenflüsse anzeigen')).not.toBeInTheDocument();
    expect(screen.queryByText('Datenflüsse ausblenden')).not.toBeInTheDocument();
  });
```

- [ ] **Step 2: Run to verify fail**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "always shows the data-flow section"`
Expected: FAIL — toggle button 'Datenflüsse anzeigen' still present / panel not rendered by default.

- [ ] **Step 3: Implement in `App.tsx`**

Delete the state declaration (`:122`):

```tsx
  const [showDataFlow, setShowDataFlow] = useState(false);
```

Change the ConsentManagerPanel callback (`:1697`) to scroll to the now-permanent section:

```tsx
          onOpenDataFlow={() =>
            document.getElementById('dataflow-section')?.scrollIntoView({ behavior: 'smooth' })
          }
```

Replace the toggle section (`:1710-1715`) with a permanent section:

```tsx
      <div className="wallet-section" id="dataflow-section" style={{ marginTop: 10 }}>
        <DataFlowPanel entries={recentAuditEntries} />
      </div>
```

- [ ] **Step 4: Run to verify pass**

Run: `pnpm --filter @askmi/wallet-pwa test -- -t "always shows the data-flow section"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/apps/wallet-pwa/src/App.tsx src/apps/wallet-pwa/src/App.test.tsx
git commit -m "feat(G-140): promote DataFlowPanel to a permanent first-class section" -m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task B3: Verification gate, push, PR-B

- [ ] **Step 1: Full wallet-pwa suite** — `pnpm --filter @askmi/wallet-pwa test` → all pass.
- [ ] **Step 2: Full suite** — `pnpm test` → 46/46 turbo tasks pass.
- [ ] **Step 3: Rebrand guard** — `pnpm guard:rebrand` → pass.
- [ ] **Step 4: Push + open PR-B** against `master`; wait required checks; do not merge without user nod.

## Self-Review

- Spec §5 PR-B B1 (badges from audit-resolved layer) → Task B1. ✔
- Spec §5 PR-B B2 (remove toggle → permanent) → Task B2. ✔
- Neutral/no-scoring, unclassified fallback, no enforcement touch → Global Constraints + muted CSS. ✔
- No-regression (inner claim-name span) → Task B1 Step 3. ✔
- Placeholder scan: none. Type consistency: `Sensitivity` from `@askmi/layer-resolver`, `claimSensitivity?` from PR-A `DataFlowTransaction`. ✔
