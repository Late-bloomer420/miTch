# AskMI release-candidate evidence checklist

**Updated:** 2026-10-14. This checklist applies to the exact future integrated code/profile, not to a historical branch.
A documentation-only PR does not grant an RC, production or certification decision.

## Publication and scope

- [x] Product naming/boundary and dated current findings are documented in this change.
- [ ] Documentation reconciliation merged to master and authority links verified.
- [ ] #141 security code reconciled without reverting later master fixes; final-head checks passed.
- [ ] Exact release SHA/tree/lockfile/runtime/profile/configuration recorded.

## Executable security and integration gates

- [ ] #170 original-request binding, atomic one-shot state, crypto and eligibility/scope negatives passed on active HTTP path.
- [ ] #171 stored-SD-JWT single-use lifecycle and honest cleanup/failed-delivery/retry tests passed.
- [ ] #172 actual-output inventory completed; applicable external-export/telemetry schema, retention and canary/error-path checks passed for the selected deployment.
- [ ] #173 report source/profile binding and persisted-file-hash roundtrip passed.
- [ ] CORS, session isolation/expiry/cap, key-persistence and recovery controls from #141 verified on integrated head.
- [ ] CI fails on critical/high advisories and on unavailable/malformed audit results; EV-05 is closed with workflow evidence.
- [ ] #150/#151 or reviewed replacements landed with appropriate key-format/randomness regressions.
- [ ] Browser E2E and container build/start gate exercised on the exact deployment topology.
- [ ] Current advisory inventory recorded with dependency versions, runtime exposure and dispositions.

## External and operational gates

- [ ] Official Android/iOS and issuer/verifier profile matrix passed with exact versions/SHAs/settings and deviations.
- [ ] Applicable conformance/ICS/FCAF/protocol results recorded; exclusions are not counted as passes.
- [ ] Independent security/cryptographic review completed and findings dispositioned.
- [ ] Deployment-specific privacy/legal/retention, trust/key/session and incident/rollback/backup/support controls reviewed and exercised.
- [ ] Written conditional-pilot go/no-go linked from #142; no unresolved applicable P0/P1/high finding.

## Existing evidence and release scope

The #141 stack's 19–20 August branch runs remain historical branch evidence in GitHub; its green head checks
do not validate a new master integration. The July [ADOPT live record](qa/ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md)
establishes its named local issuance/disclosure/trust observations, not later session/eligibility controls.
The [14 October record](qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) records scoped build/helper results and reproduced open findings.
These records remain evidence for their stated scope. A future release rechecks affected integrations and release-critical dependencies; it does not erase unrelated component results. No static test total is a release criterion.
