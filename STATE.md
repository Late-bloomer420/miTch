# STATE — AskMI current operating/evidence snapshot

**Checked:** 2026-10-14. **Executable baseline:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`.
**Category:** development/evaluation verifier-policy middleware; browser wallet is a reference harness.
No production readiness, certification, LoA High, legal compliance percentage, customers or official-wallet interop is established here.

## Single source of truth

1. [docs/DOCS_CANON.md](docs/DOCS_CANON.md): authority and navigation.
2. [Current findings/claim limits](docs/security/REPO_EVIDENCE_STATUS_2026-10-14.md): open findings and evidence scope.
3. [Dated verification](docs/qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md): exact observations, runtime, sources and probes.
4. [BACKLOG](docs/BACKLOG.md): task/implementation state; #170–#173.
5. [Release roadmap](docs/RELEASE_READINESS_ROADMAP.md), [GTM plan](docs/GTM_SPRINT_ROADMAP.md), #142/#143: evidence-gated sequencing and decisions.

## Implemented pieces versus active integration gaps

| Area | Evidence-backed boundary | Current gap |
|---|---|---|
| SD-JWT primitives | Issuer-signature, digest-verified disclosures and KB-JWT controls; #132/#135/#137 | `/oid4vp-present` request/session/eligibility/scope incomplete: #170 |
| Single-use | Legacy B+C pool/holder logic #86–#94 | Real stored-SD-JWT method can re-present singleUse=true: #171 |
| Policy | Scoped input/downgrade/geo/layer negatives; #125 fixed #122 scope | Not proof that every HTTP/presentation route invokes all gates |
| Audit | Tamper-evident helpers and #81 Tier-2 schema | Actual sink enforcement/durable failures/retention remain open: #172, F-19 |
| Evidence | Existing manifest reran 10 PASS / 2 RESIDUAL | Active route gaps excluded; source binding/file hash defect: #173 |
| Key and memory | Owned-buffer overwrite and wrapper API reuse controls | Runtime copies/timeout cancellation/TEE remain unproven: GAP-1 |
| Connect | #158/#159/#160 accept product/session/API designs | `src/packages/connect` absent; ADOPT-1.2-code not implemented |
| Trust/interoperability | JSON trust-list/demo and internal protocol/mdoc components | ETSI/current profiles, official devices and external assurance unproven |
| Deployment | Pages workflow copies self-contained synthetic site | No current hosted multi-service/security/provenance proof inferred |

## Validation actually recorded

On this executable SHA, the original 14 October local run recorded frozen pnpm 9.15.9 installation,
29/29 build tasks, guards, focused tests and 10 PASS / 2 RESIDUAL harness claims on Node 24.19.0.
Six additional synthetic characterization probes established open behavior, not fixes.
Before publication, the same source SHA was rechecked and schema/metadata/engine-security tests reran 63/63 across three files.
No new entire `pnpm test`, lint, browser click-through, official-wallet matrix or current advisory inventory is claimed.

Master's exact-SHA Build & Test check succeeded on 2026-10-03; CI green does not prove the advisory threshold:
the current audit workflow's broad exception catches its own critical exit and advisory steps continue on error.

## Open readiness and tracker state

- #170 P0 request-binding/eligibility; #171 single-use; #172 audit sinks; #173 revision-bound evidence.
- #141 remains open with baseline conflicts; its original three inline threads are resolved. Security code in that branch is not assumed landed.
- #150/#151 remain open. #152 is merged; preserve its shell-free runner.
- #157 audit-type correction is proposed in #168; source-watch stack through #169 is planning material, not active implementation.
- G0/G1 remain open. No public tally meets 20 interviews / 8 confirmations / 3 buyer signals; this is missing public evidence, not proof of zero private activity.
- G4 remains a conditional 2027-03-31 decision; production is undated. No date alone advances a gate.
- GAP-1/GAP-4 and F-05/F-06/F-15/F-19/F-20/F-22 remain explicitly open or residual.

## Historical record

[Previous STATE snapshot](docs/archive/STATE_PRE_EVIDENCE_2026-10-14.md) preserves earlier dates and claims for traceability.
Its old test totals, “98%/100%”, LoA High, complete-phase and green-by-construction assertions are not current evidence.
