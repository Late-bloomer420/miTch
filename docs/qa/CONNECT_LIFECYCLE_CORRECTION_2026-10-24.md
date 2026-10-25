# Connect lifecycle correction — 2026-10-24

Scope: PR #193 corrective commit, based on `afea2a778f31d18785eed5aaa981701ac24a94f4`.
The source/test tree is delivered in the same commit as this record; its GitHub
commit is the review anchor. No merge, human approval or release gate is claimed.

Runtime: Node v24.19.0, pnpm 9.15.9 (Corepack), Linux. CI uses Node 22 and must
separately pass on the new head. No dependency/lockfile change in this correction.

## Behavior and review targets

- Resolver rejection becomes `ISSUER_RESOLUTION_FAILED` / HTTP 503, while a null
  trusted-key result remains `UNTRUSTED_ISSUER` / 403. Both are terminal failures;
  retry requires a fresh verifier session and nonce.
- `InMemoryAskMIConnectSessionStore.update(id, lifecycleUpdate)` checks the
  current state and TTL in the same synchronous Map operation as the write.
  `get`, `consume` and updates use one injected clock. Terminal states absorb
  all later updates. A deleted record cannot be recreated by a late completion.
- Express 4 catches rejected handlers and awaits guarded failure persistence.
  If the store cannot write, the response is 503 with `status: unknown`; this is
  explicit unconfirmed persistence, not a successful persisted denial.
- Custom store implementations must adopt the new update return/guard contract.
  No non-atomic compatibility fallback exists. DB/Redis transaction/clock
  behavior, process restart and durable recovery remain unevidenced.

## Local validation

- `pnpm --filter @askmi/connect... build`: passed (package plus dependencies).
- `pnpm --filter @askmi/connect test`: **66/66**, 5 files.
- `pnpm --filter @askmi/connect lint`: passed.
- `pnpm build`: **30/30** Turbo tasks.
- `pnpm test`: **47/47** Turbo tasks.
- `pnpm lint`: **12/12** Turbo tasks.
- `pnpm guard:rebrand` and `pnpm guard:archived-imports`: passed.

Commands use the repository-pinned pnpm 9.15.9. `lifecycle.test.ts` adds 29 cases:
resolver failure vs untrusted issuer, HTTP response/persistence, one-shot failure
and fresh-session recovery, deterministic resolver/validator barriers with a
shared clock (with/without polling, allow/deny/throw), resolver rejection after
TTL, cleanup during verification, concurrent replay, all absorbing terminal
states, snapshot isolation, unexpected core/HTTP errors and unavailable storage.
No sleeps, real JWKS fetch, or cryptographic/interoperability claim is made by
these stub-validator lifecycle tests. Existing package tests remain intact.

Human reviewer must read the atomic store update, clock wiring, error handling
and custom-store API change on the actual corrective commit before merge. Bot
coverage is not a substitute. #170 stays open for the remaining integration and
profile work; no verifier-demo route integration is delivered here. Audit gate
and dependency triage are tracked separately in #185.
