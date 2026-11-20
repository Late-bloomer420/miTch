# QA Evidence Records — Index

> **New scoped record:** [PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md](PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) records open active HTTP, single-use, CI and evidence boundaries. Task status stays in the backlog/issues. The record supplements existing evidence; characterization acceptance does not prove a fix.

> **Rolle:** Dated, point-in-time **evidence records** (Beweis-Snapshots). Each file captures
> verification done *on its date* — they are **not** authoritative task-tracking and are not kept
> current. For "what is done / open" see [`../BACKLOG.md`](../BACKLOG.md); for the operational
> health snapshot see [`../../STATE.md`](../../STATE.md).
>
> **Reading rule:** treat every record as true *as of its date* only. Later evidence qualifies the same claim/path/profile where it differs; unrelated earlier results remain evidence for their recorded scope. Do not cite these as current state.

## Records

| File | Date | What it evidences |
|---|---|---|
| [`WALLET_RECOVERY_RC_2026-06-04.md`](WALLET_RECOVERY_RC_2026-06-04.md) | 2026-06-04 | Wallet recovery RC QA run (full-suite evidence baseline). |
| [`PILOT_FLOW_RERUN_2026-06-04.md`](PILOT_FLOW_RERUN_2026-06-04.md) | 2026-06-04 | Pilot demo flow re-run record. |
| [`MIT-10-demo-evidence.md`](MIT-10-demo-evidence.md) (+ `MIT-10-wallet.png`) | 2026-06-04 | MIT-10 local demo flow re-run, with wallet screenshot. |
| [`BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md`](BIG_AUDIT_CONSTANTS_CONTRACTS_2026-06-04.md) | 2026-06-04 | Big-audit slice: constants & contracts review. |
| [`BIG_AUDIT_SCENARIO_FIXTURES_2026-06-04.md`](BIG_AUDIT_SCENARIO_FIXTURES_2026-06-04.md) | 2026-06-04 | Big-audit slice: demo-scenario fixtures (S2-04). |
| [`BIG_AUDIT_STATUSLIST_FIXTURES_2026-06-04.md`](BIG_AUDIT_STATUSLIST_FIXTURES_2026-06-04.md) | 2026-06-04 | Big-audit slice: StatusList test fixtures (S2-05). |
| [`CAPSULE_SIG_ROOTCAUSE_2026-06-18.md`](CAPSULE_SIG_ROOTCAUSE_2026-06-18.md) | 2026-06-18 | Root-cause + resolution of the "capsule signature verification failures" (AskMI↔miTch rebrand AAD drift, not a crypto defect). |
| [`WEBAUTHN_FAIL_CLOSED_2026-07-12.md`](WEBAUTHN_FAIL_CLOSED_2026-07-12.md) | 2026-07-12 | WebAuthn fail-closed finding and fix: no software fallback while WebAuthn is available but no hardware identity key is registered. |
| [`SECURE_1_FINDINGS_REGISTER.md`](SECURE_1_FINDINGS_REGISTER.md) | 2026-07-13 | SECURE-1 sprint: full findings register (22 findings — 6 fix + F-14 real cred-sig verification + 7 documented-residual + 9 not-a-bug) with per-finding rationale and GAP-3 branching taxonomy. |
| [`SECURE_1_GAP_CLOSURE_2026-07-13.md`](SECURE_1_GAP_CLOSURE_2026-07-13.md) | 2026-07-13 | SECURE-1 gap-closure QA evidence: per-fix commits + tests, GAP-3 guard result + honesty boundary, GAP-2 reconciliation, verified final validation (46/46 turbo tasks, 0 errors/7 pre-existing warnings, guard passed). |
| [`ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md`](ADOPT_0AB_LIVE_VERIFICATION_2026-07-17.md) | 2026-07-17 | Live ADOPT-0a/0b real credential path verification: issuer-mock issues `vc+sd-jwt`, wallet presents stored credential with selective disclosure, verifier resolves issuer key via trust list/JWKS; records known gaps. |
| [`PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md`](PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md) | 2026-10-14 | Internal repository investigation at `cacbc95e` (open active HTTP, single-use, CI and evidence boundaries); not an external audit or conformance result. |
| [`DISCRETE_CORE_REVIEW_2026-10-23.md`](DISCRETE_CORE_REVIEW_2026-10-23.md) | 2026-10-23 | Review of `@askmi/discrete-core` (PR #189): findings F-1..F-5 with rechecks. Closes no gate. |
| [`CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md`](CONNECT_LIFECYCLE_CORRECTION_2026-10-24.md) | 2026-10-24 | PR #193 corrective commit: resolver-failure handling and guarded session-store state/TTL updates. No merge, approval or release gate claimed. |
| [`SECURITY_AUDIT_GATE_2026-10-24.md`](SECURITY_AUDIT_GATE_2026-10-24.md) | 2026-10-24 | Minimum critical audit gate (#185 slice): gate regression tests and a live audit result at that revision. |
| [`ACTIVE_AGE_PROFILE_2026-10-25.md`](ACTIVE_AGE_PROFILE_2026-10-25.md) | 2026-10-25 | #170 active numeric-age route in `verifier-demo/backend`: detached original request, per-attempt reservation, minimized result; single-process in-memory topology. Supplements the 2026-10-14 observations. |
| [`CONNECT_PROFILE_INTEGRATION_2026-10-25.md`](CONNECT_PROFILE_INTEGRATION_2026-10-25.md) | 2026-10-25 | Connect numeric-age integration at `2191ca38` (profile `age-liquor-store-v1`, in-memory store, single backend process). |
| [`PQC_SLH_DSA_TEST_TIMEOUT_2026-10-25.md`](PQC_SLH_DSA_TEST_TIMEOUT_2026-10-25.md) | 2026-10-25 | Test-timeout flake fix for the SLH-DSA-SHA2-128s block in `shared-crypto/test/pqc.test.ts`; no crypto change. |
| [`SECURITY_AUDIT_2_BODY_PARSER_2026-10-25.md`](SECURITY_AUDIT_2_BODY_PARSER_2026-10-25.md) | 2026-10-25 | SEC-AUDIT-2 batch: `body-parser` 1.x runtime pin (fixed in 1.20.9). |
| [`SECURITY_AUDIT_2_FAST_URI_2026-10-25.md`](SECURITY_AUDIT_2_FAST_URI_2026-10-25.md) | 2026-10-25 | SEC-AUDIT-2 batch: `fast-uri` pin to >= 3.1.7. |
| [`SECURITY_AUDIT_GATE_2026-10-25.md`](SECURITY_AUDIT_GATE_2026-10-25.md) | 2026-10-25 | The same gate after PR #206's dependency remediation; the 2026-10-24 record stays unchanged. |
| [`WEBAUTHN_ASSERTION_VERIFICATION_2026-10-25.md`](WEBAUTHN_ASSERTION_VERIFICATION_2026-10-25.md) | 2026-10-25 | Wallet-side verification of passkey-signed decision capsules (#218, closed by #222); follows the 2026-07-12 record. |
| [`PHASE0_SECURITY_CLEANUP_FORENSICS_2026-10-29.md`](PHASE0_SECURITY_CLEANUP_FORENSICS_2026-10-29.md) | 2026-10-29 | Forensic reconstruction of the 2026-03-12 `phase0-security` cleanup: what was lost, what survives. History verified 2026-11-13 at `d5ae4ea`. |
| [`PHASE0_SECURITY_METHOD_ASSESSMENT_2026-10-29.md`](PHASE0_SECURITY_METHOD_ASSESSMENT_2026-10-29.md) | 2026-10-29 | Method-by-method assessment of `phase0-security` and cleanup-drift record. No code change. |
| [`API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](API_PROTOCOL_REALITY_AUDIT_2026-11-03.md) | 2026-11-03 | First-principles comparison of 2026 upstream specs with repository code at `002ce5e`; findings `API-01`..`API-07`. |
| [`L2_ANCHOR_HONEST_STATUS_2026-11-18.md`](L2_ANCHOR_HONEST_STATUS_2026-11-18.md) | 2026-11-18 | Audit-log L2 anchor client reports mocked submissions as `mocked` and unchecked verifications as `unverifiable` (SECURE-1 F-05/F-06 mitigation, PR #297). Not a closure: no real anchoring exists; open work #294–#296. SECURE-1 records unchanged. |
| [`AGE_OVER_18_EXPLORATION_PROFILE_2026-11-18.md`](AGE_OVER_18_EXPLORATION_PROFILE_2026-11-18.md) | 2026-11-18 | Profile C `askmi-age-over-18-exploration-v0` on `POST /oid4vp-present`. Explicitly not an official EUDI/EU AV profile, not a ZK proof, not an interoperability result. |
| [`API_AUDIT_REVIEW_2026-11-18.md`](API_AUDIT_REVIEW_2026-11-18.md) | 2026-11-18 | Review of the 2026-11-03 API/protocol audit against `d7f0e77` (#299); static reading, not a security PASS. |
| [`ISSUER_KID_SELECTION_2026-11-18.md`](ISSUER_KID_SELECTION_2026-11-18.md) | 2026-11-18 | Issuer key selection by `kid` in `verifier-demo/backend` (`resolveTrustedIssuerKey`) and the `issuer-mock` header; remaining `kid` item of #240. |
| [`BUILD_TEST_PERFORMANCE_BASELINE_2026-11-19.md`](BUILD_TEST_PERFORMANCE_BASELINE_2026-11-19.md) | 2026-11-19 | Build/test runtime baseline at `70c7aef` (Windows, Node v24.16.0, pnpm 9.15.9). Observation, not a security or performance PASS; CI runtime not measured. |

_Sighting (H-10): index added 2026-06-24; all entries confirmed as dated evidence records, none acting as task-tracking._
