# AskMI Security Evidence Pack

This directory is the navigable entry-point for AskMI's security artifacts. It links every artifact required to assess the project's security posture, reproduce the claim evidence, and understand the open residuals.

> **Research / pilot project** — AskMI is not a production service. No real personal data is processed.

---

## Artifact Map

| Artifact | Path |
|----------|------|
| Responsible-disclosure policy | [../../SECURITY.md](../../SECURITY.md) |
| Security Target (CC-ready) | [../compliance/SECURITY_TARGET_CC_READY.md](../compliance/SECURITY_TARGET_CC_READY.md) |
| Threat model (ADR-009) | [../03-architecture/mvp/ADR-009_Threat_Model.md](../03-architecture/mvp/ADR-009_Threat_Model.md) |
| EUDI-CIR compliance matrix | [../compliance/EUDI_CIR_MATRIX.md](../compliance/EUDI_CIR_MATRIX.md) |
| P0 evidence pack | [../ops/EVIDENCE_PACK_P0.md](../ops/EVIDENCE_PACK_P0.md) |
| Runbooks | [../ops/RUNBOOKS_V1.md](../ops/RUNBOOKS_V1.md) |
| Claim→test harness source | [../../src/packages/evidence/](../../src/packages/evidence/) |
| Latest evidence report | [../qa/evidence-reports/](../qa/evidence-reports/) |
| SECURE-1 findings register | [../qa/SECURE_1_FINDINGS_REGISTER.md](../qa/SECURE_1_FINDINGS_REGISTER.md) |
| Open residuals register | [./RESIDUALS.md](./RESIDUALS.md) |

---

## Reproduce the Evidence

These commands reproduce every security claim from a clean checkout. Run them on Node 22 + pnpm 9.

```bash
# 1. Install dependencies
pnpm install

# 2. Build all 29 packages
pnpm build
# Expected: 29 tasks, 0 errors (turbo reports "29/29" on a warm cache)

# 3. Run the full test suite
pnpm test
# Expected: 47 turbo tasks green, 1820+ individual tests pass, 0 failures

# 4. Run the evidence harness
pnpm evidence
# Expected output (last line summary):
#   Proven: 10  Residual: 2  Failed: 0
# Report written to: docs/qa/evidence-reports/EVIDENCE_<timestamp>.md
```

The evidence harness (`@askmi/evidence`) maps each security claim ID to one or more Vitest test suites and replays them programmatically. A `RESIDUAL` result means the claim is intentionally not proven by a test — see [RESIDUALS.md](./RESIDUALS.md) for the rationale on each.

### Verifying a single claim

```bash
# Example: verify the anti-oracle DENY-path timing claim
pnpm --filter @askmi/policy-engine test -- --run src/__tests__/anti-oracle.test.ts
```

### Verifying the latest report integrity

Each report file includes a SHA-256 integrity hash of its JSON sibling. To recompute:

```bash
node -e "
const crypto = require('crypto');
const fs = require('fs');
const json = fs.readFileSync('docs/qa/evidence-reports/EVIDENCE_2026-07-14T00-04-05-971Z.json');
console.log(crypto.createHash('sha256').update(json).digest('hex'));
"
# Must match the hash in the .md report header
```

---

## Current Evidence Status (as of 2026-07-14)

| Metric | Value |
|--------|-------|
| Proven claims | 10 |
| Residual (documented open items) | 2 |
| Failed claims | 0 |
| SECURE-1 findings fixed | 14 of 22 |
| SECURE-1 documented residuals | 6 (F-05, F-06, F-15, F-19, F-20, F-22) |
| External security review | Not yet performed (GAP-4) |

See [RESIDUALS.md](./RESIDUALS.md) for the full open-items register.
