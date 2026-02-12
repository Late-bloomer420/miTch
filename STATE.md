# STATE.md — Current Operating State

Stand: 2026-02-12

## Current baseline
- Repo: `https://github.com/Late-bloomer420/mitch-temp.git`
- Branch: `main`
- Last completed batch: visual operating layer + decision framework docs (`103`-`107`) and index refresh
- Operating mode: small autonomous hardening batches, fail-closed, pilot-focused

## Current security posture snapshot (latest local)
- `security_profile_score`: 100 (with strong+signe d test config)
- `false_allow_total`: 0
- `deny_resolver_quorum_failed_total`: 0
- `deny_reauth_proof_invalid_total`: 0
- Note: score depends on runtime config and current telemetry; this is not an absolute security guarantee.

## Now (do next)
1. Add doc/runbook for `security_profile_score` interpretation and operator actions
2. Start strict native verifier adapter contract (input/output + deny mapping)
3. Add kpi:check warning rule for sustained native deny rate spikes

## Next (short buffer)
1. Start strict native verifier adapter contract (input/output + deny mapping)
2. Revocation semantics tightening beyond light scaffold (scope-controlled)
3. Pilot alert routing/escalation ownership draft

## Later (important, not immediate)
1. PQ/hybrid signature migration v1
2. Recovery security design deepening
3. External legal completion (GDPR opinion + pilot wording)

## Active blockers / constraints
- `memory_search` quota blocked (OpenAI embeddings 429 insufficient_quota)
- Workaround: rely on repo-first memory discipline (`STATE.md`, backlog, numbered docs, daily memory log)

## Safe runtime config reminders (when testing stronger WebAuthn)
- `REQUIRE_STRONG_REAUTH=1`
- `WEBAUTHN_VERIFY_MODE=signed` (or native when adapter evidence is ready)
- `WEBAUTHN_ASSERTION_HMAC_SECRET=<strong secret>`
- Keep fail-closed defaults; never rely on weak compatibility mode in production.

## Fast visual entry points
- `105_Visual_Control_Panel.md` (scan priorities in 30 seconds)
- `106_Document_Map_By_Purpose.md` (find docs by intent)
- `103_GTM_Security_Decision_Framework.md` (decide GO/PILOT/DEFER)

## Batch-close checklist
- [ ] Code/tests green (`npm test`, `npm run kpi:check`)
- [ ] Relevant numbered doc updated/added
- [ ] `07_Backlog_and_Roadmap.md` kept current
- [ ] `00_README.md` index updated
- [ ] Commit + push with clear message
