# L2 anchor client: honest status for F-05 / F-06 (2026-11-18)

> **Role:** dated evidence record. It supplements, and does not replace, the SECURE-1 records
> ([register](SECURE_1_FINDINGS_REGISTER.md), [gap closure](SECURE_1_GAP_CLOSURE_2026-07-13.md)), which stay unchanged.
> This is a scoped mitigation record, not a security PASS and not a closure of F-05 / F-06.

| Field | Value |
|---|---|
| Date | 2026-11-18 |
| Component / path | `src/packages/audit-log/src/storage/l2-anchor-client.ts`; type `L2AnchorReceipt` in `src/packages/shared-types/src/audit.ts` |
| Base revision | `58d0af9df2fa13f8f38359546c98efc54df542a2` (master at clone time) |
| Change revision | `a7ed22d194d944d35b78d29e364d580bf1f32dc8`, branch `fix/audit-log-l2-anchor-honest-status`, PR #297 |
| Profile / configuration | Vitest, `environment` default of the package, `NODE_ENV=test`; no RPC, no contract, no signer configured |
| Runtime | Node v22.23.4, pnpm 9.15.9, Vitest 4.1.12 (Linux sandbox) |
| Task IDs | L2A-01 (this change), L2A-02 (#294), L2A-03 (#295), L2A-04 (#296) |

## Claim evidenced (and nothing broader)

The audit-log L2 anchor client no longer reports a mocked submission as confirmed and no longer reports an unchecked
verification as verified. No on-chain transaction is sent and no on-chain check is made, before or after this change.

## Defects as recorded (source reading at the base revision)

| ID | Observation | Class |
|---|---|---|
| F-06 | `submitToL2()` fell through to `mockAnchor()`; the receipt had `status: 'confirmed'`; `processBatch()` logged "Batch anchored" and cleared the batch | Reproduced defect (false success) |
| F-05 | `verifyAnchor()` returned `true` for `pending` receipts, for the zero-address contract, and for a set contract address with no on-chain query | Reproduced defect (false success) |

The register classified both as `documented-residual`. That classification remains the record for its date.

## Change

- `L2AnchorReceipt.status` gains `'mocked'` (optional field; additive).
- `mockAnchor()` returns `status: 'mocked'`.
- `processBatch()` logs success only for `confirmed`; otherwise it warns that nothing was written on-chain and drops the batch (retry cannot succeed without a provider).
- New `verifyAnchorDetailed()` returns `{ status, reason }` with `verified | mock | pending | unverifiable`. No path reaches `verified` yet.
- `verifyAnchor()` stays a boolean: `true` only for `verified` or the explicit `mock` network.

## Behavior changes of public API (owner approval required, `CLAUDE.md`)

| Call | Before | After |
|---|---|---|
| `verifyAnchor()`, zero-address contract | `true` | `false` |
| `verifyAnchor()`, contract address set, no on-chain query | `true` | `false` |
| `verifyAnchor()`, `pending` receipt | `true` | `false` |
| `verifyAnchor()`, `mock` network | `true` | `true` |
| Receipt status from `mock` network or fall-through | `confirmed` | `mocked` |

No caller of `verifyAnchor()` outside the package tests was found at the base revision (`grep` over `src`).

## Verification

Tests were written first.

| Step | Command (in `src/packages/audit-log`) | Result |
|---|---|---|
| Red | `npx vitest run src/storage/__tests__/l2-anchor-client.test.ts` | 8 of 10 failed on the new expectations (`'confirmed'` instead of `'mocked'`, `true` instead of `false`, `verifyAnchorDetailed` missing) |
| Green | same command | 10 of 10 passed |
| Package suite | `npx vitest run` | 4 files, 26 tests passed |
| Typecheck | `npx tsc --noEmit` | exit 0, no output |

Before the workspace dependencies were built, two suites (`test/adversarial_audit.test.ts`, `test/proof_of_shredding.test.ts`) failed to resolve `@askmi/shared-crypto`, and `tsc` reported missing modules. This is an environment effect; `pnpm --filter "@askmi/audit-log^..." build` resolved it. Install used `pnpm install --frozen-lockfile --filter @askmi/audit-log...`.

New tests cover: mock-network receipt is `mocked`; real-network non-batched submission is `mocked`, never `confirmed`; `processBatch()` does not log "Batch anchored" for a mocked submission; zero-address, set-address-without-query, synthetic and pending receipts do not verify; the mock network still verifies as `mock`.

## Known limits

- Scope is `@askmi/audit-log` with its built dependencies. Full-repo `pnpm build`, `pnpm test` and `pnpm lint` were not run locally; CI on PR #297 is the broader check.
- Other packages that depend on `@askmi/shared-types` were not re-typechecked locally. A source search found `L2AnchorReceipt` only in `audit-log` and `shared-types`.
- `StateAnchorClient` (`src/anchor.ts`), the dev fallback of `AuditLog.syncToL2()`, still emits receipts with no status (tracked as L2A-04, #296). Its receipts are not covered by this evidence.
- The Entire Brain CLI named in `.entire/agent-guide.md` was not installed in the sandbox; direct source inspection was used instead.
- No real anchoring, contract, provider or verification exists. Nothing here supports an on-chain claim.

## Open work and close conditions

| Task | Issue | Close condition |
|---|---|---|
| L2A-02 real submit and verify | #294 | Real backend path, real verification, integration negatives (wrong root, wrong height, undeployed contract, RPC failure), dated evidence |
| L2A-03 ADR + `AnchorBackend` port | #295 | Accepted ADR, reconciliation with `@askmi/anchor-service`, privacy constraints fixed, interface with tests |
| L2A-04 `StateAnchorClient` labeling | #296 | Fallback receipts labeled `mocked`, export test |

## Reference note

The register text "Tracked as F-12 in the L2-anchoring roadmap" resolves to `docs/AUDIT_2026_03.md` F-12 ("L2-Anchoring ist komplett ein Stub"). The register's own F-12 is an unrelated `not-a-bug`. No roadmap item with that ID existed in `BACKLOG.md` or the roadmaps at the base revision; tracking now lives in L2A-02 to L2A-04.
