# AskMI security evidence — internal and scope-bound

**Current entry:** [REPO_EVIDENCE_STATUS_2026-10-14.md](REPO_EVIDENCE_STATUS_2026-10-14.md).
**Dated observations:** [PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md](../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md).
This research/evaluation repository uses synthetic test/demo fixtures; this document does not attest what any external deployment processes.

| Source | Role |
|---|---|
| [Current finding register](REPO_EVIDENCE_STATUS_2026-10-14.md) | Reproduced findings, implemented scope, claim limits and owners |
| [Residuals](RESIDUALS.md) | GAP-1/GAP-4 and SECURE-1 residuals remain explicit |
| [Remediation roadmap](SECURITY_AUDIT_ROADMAP_2026-10-01.md) | Existing SEC-AUDIT sequence with dated refresh |
| [Evidence source](../../src/packages/evidence/) | Manifest, runner and report; #173 limitations |
| [P0 component pack](../ops/EVIDENCE_PACK_P0.md) | Historical component evidence, not global pilot closure |
| [Threat model](../03-architecture/mvp/ADR-009_Threat_Model.md) | Internal risk analysis, pending independent review |
| [Requirement traceability](../compliance/EUDI_CIR_MATRIX.md) | Incomplete engineering mapping; no readiness percentage |
| [Security-target draft](../compliance/SECURITY_TARGET_CC_READY.md) | Assessment input, not accreditation or EAL/LoA result |
| [Responsible disclosure](../../SECURITY.md) | Reporting policy; owner-authorised public synthetic finding intake does not change external reporting rules |

## Reproduce named evidence, not an assumed success total

Use the pinned pnpm 9.15.9 for all subprocesses. CI uses Node 22; 14 October local evidence used Node 24.19.0.

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm lint
pnpm evidence
```

Record outcomes/versions/SHA/profile and gaps; the commands are not pre-certified to pass.
In the investigation host, tsx CLI IPC was unavailable; the same harness ran through
`pnpm --filter @askmi/evidence exec node --import tsx src/cli.ts`.

The dated existing manifest run had 10 PASS, 2 RESIDUAL, 0 FAIL. It does not cover #170/#171's active-path counterexamples.
GAP-1 physical/runtime-erasure and GAP-4 external-review evidence are not closed. No entire-suite or official matrix result is newly inferred.

## Known report-integrity defect — #173

The generator hashes JSON without final LF, then writes JSON plus LF. Hashing the exact July file bytes therefore does not match
the header; hashing after removing only final LF does. See the dated record for both hashes. This is not tampering evidence.
Do not silently normalize future artifacts and claim exact-byte verification; fix or explicitly version the representation and add write/read tests.

## Current high-priority boundary

#170 request/session/eligibility/scope; #171 real SD-JWT single-use; #172 actual audit/telemetry sinks;
#173 source-bound evidence; EV-05 CI advisory false-success under #141/SEC-AUDIT-1/2.
The existence of residual descriptions, specs or checklists is not implementation. An internal PASS is not external assurance.
