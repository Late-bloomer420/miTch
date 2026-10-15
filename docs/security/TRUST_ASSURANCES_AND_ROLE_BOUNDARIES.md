# Observable trust: assurances, responsibilities and evidence

**Date:** 2026-10-14. **Status:** planning/assurance contract; runtime criteria below remain open.
**Source inspected:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`; documentation corrections in #174 do not implement controls.

This document records the PCC/panel and platform-governance learnings as concrete work for the existing profile. It supplements the [Claim Map](../05-business/marketing/06-claim-evidence-map.md), [ADOPT product decision](../tasks/ADOPT_1_PRODUCT_BOUNDARY_DECISION.md), [MCP architecture](../mcp-server-architecture.md) and [dated findings](REPO_EVIDENCE_STATUS_2026-10-14.md). It does not override component evidence, add a compliance score or replace #142/#143 gates.

## Goals retained; implementation gaps remain visible

**Product clarification — 2026-10-15:** correcting a readiness claim does not change the goal. Use **goal → current scoped evidence → remaining work and acceptance**. Retiring or narrowing a goal requires an explicit product decision, not a wording cleanup or an unmet test.

| Retained goal | Current evidence / limit | Work needed to demonstrate progress |
|---|---|---|
| Prevent fingerprinting and cross-service tracking | Pairwise identifiers and metadata controls have component evidence; one quantized field does not exclude issuer/credential, IP, timing or browser correlation | #175 assurance/threat-model mapping, existing metadata-budget controls and #173 reproducible evidence: identify observers and combined correlators; define measurable adversarial scenarios, test them and record residual risk. Unproven protection remains an open goal |
| Complete, user-inspectable log of every wallet transaction | Local audit/history components exist; a synthetic timeline does not establish coverage of every active route or durable storage | #172/#175: enumerate entry points and expected events; reconcile requested/approved/disclosed/withheld outcomes, denials, errors and retries; test missing writes, restart/recovery and supported storage durability. Distinguish attempted/completed/unknown cleanup; protect detailed local history from external disclosure |
| Control exactly what leaves the wallet at every transaction | Policy/selection components are present; #170 reproduces an active-route excess-claim gap | #170 binds the original approved request and enforces output scope with negative tests; #171 governs the applicable single-use lifecycle |
| Reveal student status without revealing the university | Omitting a university-name disclosure is insufficient when the preserved signed issuer identifier identifies it | #97 must evaluate the issuer/trust profile and remaining metadata; preserve this scenario goal while marking issuer privacy unproven |

These are acceptance directions for existing work, not newly delivered protections. The threat model makes evaluation explicit; it must not silently lower the product ambition. Separate goals from guarantees in public copy, roadmap entries, receipts and review decisions.

## Understandable assurances and their actual boundaries

The following are proposed user-facing assurances. They may be presented as enforced only after the stated path/profile checks pass. Until then show their scope and open status.

| ID | Proposed assurance | Existing evidence | Remaining proof / owner |
|---|---|---|---|
| TA-01 | This transaction releases only the fields approved for this recipient and profile | Policy/selection components; [session contract](../tasks/ADOPT_1_MINIMAL_SESSION_CONTRACT.md); requested/allowed/withheld views | Original request, output scope and substitution/replay negatives on the actual route: #170. The real demo currently shares numeric age, not solely a boolean |
| TA-02 | A valid signature is reported separately from eligibility and permission to proceed | Issuer-signature, disclosure-digest and KB-JWT work #132/#135/#137 | Signed age 12 may correctly pass crypto validation but cannot satisfy an 18+ application result; verify separate flags and consuming UI: #170/#175 |
| TA-03 | An agent cannot create my approval by saying that I approved | [Spec 49](../specs/49_Agentic_Threat_Model_and_Controls.md) describes independent controls; MCP offers policy evaluation | Current caller-supplied override is evaluation input, not authenticated action authority. Trace consumers and define a bound approval before any action connector: #177 |
| TA-04 | Cleanup history reports operations that actually completed | Owned-buffer lifecycle helpers and legacy single-use pool; [residuals](RESIDUALS.md) | Stored-SD-JWT reservation/consume and honest UI: #171. No all-RAM-copy or recipient-deletion proof; receipt integrity does not prove every copy was erased |
| TA-05 | I can inspect what was shared, who received it and which guarantees are still unverified | DataFlow/Consent Manager, audit-chain helpers and existing claim/test links | Connect actual outcomes to assurance IDs; distinguish observation, enforcement and third-party declaration: #175. Actual output inventory #172 and report provenance #173 |

Keep local user history, RP application results, operational telemetry, external audit exports and public assurance summaries separate. User-facing detail must not become a verifier policy oracle, raw credential export or public stable holder identifier.

A purpose string alone is not a legal basis, issuer trust or user approval. Authenticated consent is also not permission to bypass mandatory rules. Log an attempted operation separately from a successful one; show unknown outcomes as unknown.

## Role separation for the initial RP-deployed profile

The reference deployment combines mock issuer, wallet and verifier for evaluation. Shared ownership of a demo is not proof of independent governance in a real deployment. The accepted initial product is RP-deployed middleware, not a new credential issuer.

| Role | Responsibility to document | Initial boundary / unresolved work |
|---|---|---|
| Holder/user | Select permitted disclosure and control approval | Wallet UX exists; action-specific consent provenance and multi-turn scope are #177 |
| Authentic source / credential issuer | Assert attributes and sign the credential; define revocation and authority | `issuer-mock` is synthetic. Real issuer/trust/profile onboarding remains #97/#170; a valid device attestation is not an identity assertion |
| Wallet provider | Protect storage, present selected credentials and report lifecycle honestly | Reference wallet exists; #171 governs the stored single-use path; native key properties and recovery depend on the selected platform |
| Policy author / executor | Define allowable recipient/profile/claims and enforce an inspectable policy version | Policy Engine exists; approved Connect designs do not yet supply a completed active adapter. Changes to policy/trust roots must have reviewable provenance |
| Verifier/RP | Check issuer/holder evidence, apply business eligibility, decide authorization and govern retained results | Do not treat crypto `ok` or advisory MCP ALLOW as an authorization token. RP receipt of age is a data flow even if its UI shows only a boolean |
| Hardware/key/attestation provider | Protect key operations and attest relevant properties | Identify roots of trust, API/entitlement restrictions and certificate meanings; no vendor-independent hardware guarantee inferred |
| Reviewer/operator | Verify source/configuration and applicable integration/operational evidence | #173 provenance, EV-05 CI gate and GAP-4 independent review remain distinct. Public source alone does not attest deployed remote code |

For each role, #176 must record who can read values or metadata; approve, deny or revoke access; update policy, trust lists or software; and remove a competing integration. Where one organisation holds several roles, specify least privilege, data/audit separation, independent credential trust and reviewable changes.

VeriCred is a separate integration candidate in this conversation. This repository's evidence does not validate VeriCred's implementation or confer readiness across repositories. A real cross-repo integration requires its own source/profile/test evidence.

## Platform dependency and provider exit

Privacy, security and contestability are separate assessment dimensions. An opaque provider admission rule can create dependency even when transaction contents are private. Conversely, hardware-backed keys can improve protection without making the hardware vendor the credential's identity authority.

#176 owns a selected-profile dependency table: platform/version, required API/entitlement, permitted role/data scope, credential format, trust root, access conditions, observed test and unavailable/unknown features. #97 owns actual wallet/profile interoperability; do not open a duplicate generic adapter epic.

The provider/device exit scenario must state what can migrate, what requires credential reissuance or holder-key rebinding, how revocation and local history behave, and which operations fail closed. Switching provider does not require exporting non-exportable private keys. Do not promise universal portability before an actual scenario is tested.

## Evidence levels and maintenance

Use these distinct descriptions rather than a single trust/readiness percentage:

1. **Design:** intended behavior and owner; no implementation assertion.
2. **Component evidence:** code and named internal tests for a defined contract.
3. **Integrated-path evidence:** actual request/decision/output and relevant negative cases for the selected profile/configuration.
4. **Independent evidence:** named external review or conformance result, including exclusions and findings.
5. **Deployment evidence:** release/configuration and operational checks matching the system users actually reach.

One level does not replace the others. An attestation establishes specified measured properties and trust assumptions, not the absence of every bug. A receipt can authenticate a recorded event without proving that an RP never retained data. An external processor's terms are declarations unless a control is technically verified.

For each assurance use: ID, plain-language promise, owner, role/path/profile, evidence links/revision/date, status, dependencies, known limits and the next verification. #173 supplies report/build provenance; #175 supplies the user-facing mapping. Revalidate affected implementation/configuration/dependency/profile changes. Preserve prior dated outcomes. Docs-only wording changes do not trigger whole-repository re-audits.

## Milestones within the existing roadmap

These are outcome milestones inside #142's existing waves, not new calendar commitments, GitHub milestone objects or completed implementations. #143's buyer targets and stop rules remain unchanged.

| Milestone | Completion evidence | Existing/new owner | Sequence |
|---|---|---|---|
| TR-1: inspectable promises | Initial assurance IDs, exact scope and evidence links; a small synthetic comprehension exercise; public copy agrees with the evidence | #175, #173, Claim Map; #174 corrects current copy | Define now; completion awaits outcome/UX evidence |
| TR-2: one bounded real transaction | Stored server request; separate crypto/eligibility/authorization results; one-shot state; selected single-use lifecycle; integration negatives | #170/#171; #141 baseline hardening | First runtime implementation priority |
| TR-3: authenticated agent authority | Advice/action contract, trusted approval origin, bound scope/recipient/expiry and substitution/replay/injection negatives | #177, Spec 49; reuse #170 session control | Design now; action enforcement before any live action connector |
| TR-4: inspectable role/provider dependencies | Selected-profile role/access matrix and provider-exit scenario; tested adapters where applicable | #176/#97; accepted #158 role boundary | Design alongside the first slice; no broad platform build |
| TR-5: accountable operating evidence | Actual output inventory, applicable minimised exports/retention, revision-bound reports and explicit independent/deployment findings | #172/#173, GAP-4, existing release gates | Before the corresponding external-export/pilot assurances |

Independent review and market demand remain separate gates. Interviews can test whether provider choice, auditable scope or operational evidence solves a buyer's problem; technical milestone completion does not satisfy the existing 20/8/3 buyer tally.

## Next implementation slice

Publication prerequisite: #174's corrections must be accepted into the target baseline under its applicable checks/review and branch rules. Their presence in a stacked branch does not establish a master merge. The runtime sequence after that publication is:

1. Reconcile the relevant #141 security work against current master; preserve later issuer/digest/runner fixes. First code slice is #170's original-request binding and explicit result semantics, with focused HTTP/session regressions. Do not merge stale #141 wholesale.
2. Integrate #171 where the selected profile requires single-use; connect accurate outcomes to #175's user-facing assurances.
3. Inventory actual outputs for #172 and implement #173 provenance/serialization without duplicating existing schemas/tests. Keep #176/#177 design decisions linked; do not silently expand into a new wallet or agent execution product.

## Primary learning sources (checked 2026-10-14)

- [Apple: secure agentic app features](https://developer.apple.com/videos/play/wwdc2026/347/) describes prompt injection, threat modelling, confirmations and deterministic action controls. Application: #177; it is not a claim of immunity.
- [Apple: expanding PCC](https://security.apple.com/blog/expanding-pcc/) describes layered hardening, verifiable software and independent roots of trust for critical components. Application: report provenance and explicit assumptions; #173 does not implement hardware runtime attestation.
- [Apple: Verify with Wallet](https://developer.apple.com/wallet/get-started-with-verify-with-wallet/) exposes third-party verification through controlled access. Application: inspect actual role/API dependencies in #176 rather than assuming either universal access or blanket exclusion.

The supplied panel transcript is a learning input, not evidence that miTch implements Apple's guarantees. Applicable EU role/interoperability obligations need current primary-source and deployment-specific review; this document makes no legal-compliance finding.
