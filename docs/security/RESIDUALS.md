# AskMI Security Residuals Register

This register lists every security item that is **intentionally not closed** in the current codebase. Each row states what the item is, why it remains open, and what would be required to close it.

The evidence pack does **not** claim these items are covered. The `pnpm evidence` harness marks them `RESIDUAL` (not `PASS`) and they are counted separately in every report.

---

## Structural Gaps (from initial security target)

### GAP-1 — Browser RAM / TEE deferred

| Field | Detail |
|-------|--------|
| **What** | Physical RAM wipe of sensitive key material is unattainable in browser JavaScript / V8. The GC controls object lifetime; `Uint8Array` contents cannot be reliably zeroed before GC collection. The full solution is a hardware TEE (Trusted Execution Environment) or a native app with controlled memory. |
| **Why not closed** | TEE integration is deferred to a future platform milestone (ADR-010). The current architecture targets browser-based wallet deployments where native memory control is not available. |
| **What would close it** | Implement the TEE integration strategy described in [ADR-010](../03-architecture/mvp/ADR-010_TEE_Integration_Strategy.md): native secure enclave (e.g. Android StrongBox, iOS Secure Enclave, or a platform WebAuthn PRF extension for key wrapping) with a memory-safe companion process handling key operations outside the JS heap. |
| **Evidence harness claim** | `GAP-1` — status `RESIDUAL` |

---

### GAP-4 — External security review not yet performed

| Field | Detail |
|-------|--------|
| **What** | No independent third-party penetration test or code audit has been performed on the AskMI codebase. The SECURE-1 and SECURE-2 reviews are internal (conducted by the development team / Claude Code). |
| **Why not closed** | This is a human and budgetary precondition, not a code problem. The project is in research/pilot phase and has not yet engaged an external security firm. |
| **What would close it** | Commission a professional security review covering at minimum: cryptographic primitive usage (`shared-crypto`), the policy-engine verdict logic, the WebAuthn/passkey binding, and the OID4VP credential-presentation flow. Findings should be triaged against this register. |
| **Evidence harness claim** | `GAP-4` — status `RESIDUAL` |

---

## SECURE-1 Documented Residuals

These findings were raised during the SECURE-1 internal review (see [SECURE_1_FINDINGS_REGISTER.md](../qa/SECURE_1_FINDINGS_REGISTER.md)) and explicitly marked `documented-residual` because they cannot or should not be fixed within the current scope.

### F-05 — `verifyAnchor()` returns `true` for undeployed contracts

| Field | Detail |
|-------|--------|
| **What** | `audit-log/src/storage/l2-anchor-client.ts:311-328` — `verifyAnchor()` returns `true` unconditionally for any non-mock, non-pending receipt whose contract address is the zero-address sentinel (every production network before the anchor contract is deployed). Callers receive a `verified: true` response when no on-chain check was actually performed. |
| **Why not closed** | Deploying the anchor contract to a live L2 network is out of current project scope. The JSDoc on `verifyAnchor()` explicitly states "treat as unverifiable but non-blocking" for the zero-address case. Fixing the false-success requires deploying a real contract and wiring the verification call. |
| **What would close it** | Deploy the Merkle anchor contract (tracked in the L2-anchoring roadmap) and replace the zero-address sentinel branch with a real `eth_call` to `MerkleAnchor.verify()`. Update `verifyAnchor()` to return `false` (not `true`) when the contract is not deployed. |

### F-06 — `submitToL2()` always mocks the blockchain write

| Field | Detail |
|-------|--------|
| **What** | `audit-log/src/storage/l2-anchor-client.ts:119-128` — `submitToL2()` falls through to `mockAnchor()` even in non-mock mode, returning a synthetic confirmed receipt. `processBatch()` and `anchorRoot()` treat it as a successful on-chain write. |
| **Why not closed** | Same blocker as F-05: no real L2 contract deployment yet. The JSDoc header of `submitToL2()` explicitly documents "mocked: does NOT send a real on-chain transaction". |
| **What would close it** | Wire an ethers.js or viem provider, instantiate the deployed anchor contract, and replace `mockAnchor()` with a real signed transaction. Add integration tests against a local Hardhat/Anvil node. |

### F-15 — Break-glass issues ALLOW without presence/consent

| Field | Detail |
|-------|--------|
| **What** | `policy-engine/src/engine.ts:378-383` — The `allowBreakGlass` path issues an ALLOW verdict when `userAvailable === false`, bypassing normal presence and consent checks. This is an intentional fail-open branch. |
| **Why not closed** | Break-glass access is a **required** feature under EHDS Art. 8(5) (emergency access to health data without prior consent). Removing or blocking this branch would break a compliance requirement. The designed safeguard is the mandatory `BREAK_GLASS_ACTIVATED` audit event written on every invocation. |
| **What would close it** | This cannot be "fixed" without removing the EHDS Art. 8(5) compliance feature. Hardening options: add a signed break-glass token requirement (so the decision is bound to an authenticated emergency context), enforce a time-bounded validity window, and add real-time alerting for every `BREAK_GLASS_ACTIVATED` event. |

### F-19 — `AuditLog.append()` swallows persistence failures

| Field | Detail |
|-------|--------|
| **What** | `audit-log/src/index.ts:130-136` — `append()` catches IndexedDB persistence failures silently (`console.error` only) and continues. The in-memory log remains valid, but if the DB write fails the entry is not durably persisted. |
| **Why not closed** | Best-effort persistence is the documented design intent for the in-memory audit log. The comment in the code acknowledges this. A `console.error` is adequate for a PoC/research deployment. |
| **What would close it** | For production: propagate persistence failures as structured errors to the caller; add a dead-letter queue for failed appends; expose a health metric for audit-log DB error rate. Alternatively, switch to `useProductionStorage: true` with a hardened storage backend that retries on transient errors. |

### F-20 — Pairwise DID generation failure is silently swallowed

| Field | Detail |
|-------|--------|
| **What** | `policy-engine/src/engine.ts:800-803` — A failure in pairwise DID generation inside `result()` is caught and logged with `console.error`, then execution continues without a pairwise DID. The ALLOW/DENY verdict is unaffected, but the unlinkability goal (a verifier cannot correlate requests across sessions) is silently not met. |
| **Why not closed** | The pairwise-DID subsystem has its own known fragility; making the entire policy verdict fail when DID generation throws would break disclosure flows on benign errors. Fixing properly requires hardening the pairwise-DID generation path itself (a separate task). |
| **What would close it** | Ensure the pairwise DID generation path never throws (internal try/return-fallback with a deterministic ephemeral ID). If a DID cannot be generated, the `result()` call should still surface an explicit `unlinkabilityWarning` field rather than silently omitting the DID. |

### F-22 — L2 batch timer failures are fire-and-forget

| Field | Detail |
|-------|--------|
| **What** | `audit-log/src/storage/l2-anchor-client.ts:238-243` — `startBatchTimer()` calls `processBatch().catch(console.error)` via `setInterval`. Batch failures are logged but never retried beyond the in-function retry counter; the batch is silently dropped on final failure. |
| **Why not closed** | L2 anchoring is not yet wired to a real chain (same blocker as F-05/F-06). Until a real chain is deployed, a sophisticated retry/alerting path is premature. |
| **What would close it** | When real L2 integration lands: replace `console.error` with a structured alert (metric counter + dead-letter queue); implement exponential-backoff retry outside the batch timer; add a circuit-breaker so sustained L2 unavailability degrades gracefully instead of dropping batches silently. |

---

## Summary Table

| ID | Class | Severity | Why open | Closes when |
|----|-------|----------|----------|-------------|
| GAP-1 | Architecture gap | High | Browser JS has no memory control; TEE deferred | TEE / native enclave integration |
| GAP-4 | Process gap | High | Human/budget precondition | External security firm engaged |
| F-05 | false-success | Med | L2 contract not deployed | Anchor contract deployed + `verifyAnchor()` uses real `eth_call` |
| F-06 | false-success | Med | L2 contract not deployed | Real ethers.js/viem transaction path |
| F-15 | intentional fail-open | Med | EHDS Art. 8(5) compliance requirement | Cannot close without dropping the feature; can only harden |
| F-19 | swallowed-error | Low | Best-effort persistence by design | Production storage backend with retry + dead-letter |
| F-20 | swallowed-error | Low | Pairwise-DID subsystem fragility | Harden DID generation path; expose `unlinkabilityWarning` |
| F-22 | swallowed-error | Low | L2 not wired to real chain | Real L2 integration + retry/circuit-breaker |
