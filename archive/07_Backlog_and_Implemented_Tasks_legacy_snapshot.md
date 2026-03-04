# Backlog & Implemented Tasks (Snapshot)

## Implemented (as reported)
- **T-37: WORM logging** (append-only decision receipts)
- **T-38: AAD** (Associated Auth Data binding)
- **Policy Manifest** created
- **AQDR mock** created
- **T-39: Rate limiting** — fixed-window per requester (example: 10 req/min), executed first

## Urgent (policy / misleading risk)
1. **Remove or archive any `tee-attestation` modules for Phase 0**
   - If TEE attestation is not real + verifiable, it must not exist in core.
2. **Introduce `KeyGuardian` abstraction with honest protection levels**
   - `SOFTWARE_EPHEMERAL` at minimum; no enclave claims.
3. **Replace tests accordingly**
   - Migrate `tee-attestation.test` -> `key-guardian.test`
   - Ensure sign returns `Uint8Array`, verify via WebCrypto
   - Missing key => throws

## Next (high-value)
- Metrics upgrade kit:
  - schema normalizer (multiple JSONL formats)
  - confusion matrix collector (TP/FP/TN/FN)
  - cost_est respected + gate precedence tests
- Metadata leak review:
  - log minimization rules
  - correlation-resistance checks
- Social recovery (if needed)
  - Shamir secret sharing with user-chosen guardians
  - ensure no central recovery backdoor
