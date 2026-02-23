# Contributing to miTch

Thanks for contributing.

## Ground rules
- Privacy/security invariants are non-negotiable.
- Fail-closed behavior must be preserved.
- No raw PII in verifier-side logs/receipts.
- No misleading security claims (TEE/attestation/etc.).

## Workflow
1. Fork/branch from `main`.
2. Keep PRs focused and small.
3. Add or update tests for behavior changes.
4. Update docs/specs if contract/policy behavior changes.
5. Open PR with clear risk notes.

## Required checks before PR
- `npm run compile`
- `npm test`
- Verify deny-code mapping remains deterministic.
- Verify no new raw-PII logging paths.

## Commit style
Use clear imperative messages, e.g.:
- `Add binding hash mismatch deny mapping`
- `Implement nonce replay checks`

## Security issues
Do not open public issues for vulnerabilities.
Use `SECURITY.md` reporting path.
