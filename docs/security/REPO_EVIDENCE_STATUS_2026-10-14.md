# AskMI repository evidence and open findings

**Checked:** 2026-10-14. **Executable baseline:** `cacbc95e5ef884e59c688aea41081f8fb7f12fa6`.
The baseline and relevant open PR heads were re-read before publication and were unchanged.
Documentation changes do not fix executable behavior or advance a readiness gate.

## Scope and statuses

This index links additional findings to their exact scope and existing owners. It is not a complete audit of every source file or a replacement for component evidence. [Dated verification](../qa/PCC_LEARNINGS_REPO_AUDIT_2026-10-14.md)
records exactly what was observed. [BACKLOG](../BACKLOG.md) owns task state;
[release roadmap](../RELEASE_READINESS_ROADMAP.md) owns sequencing; #142/#143 own live gate decisions.

| Status | Meaning |
|---|---|
| Implemented, scoped | Active code and specified repository tests establish the named behavior only |
| Reproduced defect | A local synthetic counterexample contradicts a specific path/profile contract |
| Integration gap | Existing components are not wired into the inspected application path; this does not negate component tests |
| Deliberate boundary / investigation | A threat-model limit or unresolved contract question; not automatically a software defect |
| Accepted design / not implemented | Contract/spec accepted; no completed active implementation evidenced |
| Partial / demo / stub | Components exist but the complete profile, path or external integration is missing |
| Externally unvalidated | No independent review, official interop/conformance or certification evidence recorded |
| Closed, scoped | Exact issue scope has fix commit plus relevant negative/integration evidence; unrelated guarantees remain open |

Neither a green helper test, a documentation PR, a passing HTTP status nor a hash-chain receipt proves an entire end-to-end guarantee.

## Open findings and existing owners

| ID | Priority | Evidence / exact boundary | Owner / close condition |
|---|---|---|---|
| EV-01 | P0 | `/oid4vp-present` accepts repeated valid tokens and caller-selected nonce/state; it reconstructs expectations from incoming data | #170: original server request, atomic one-shot state and active HTTP negatives |
| EV-02 | P0 for eligible application success | Signed `age:12` is cryptographically accepted; extra signed name is returned on the demo route. A valid credential may correctly describe an underage holder: this is not a broken signature validator or a general PolicyEngine defect | #170: enforce original profile/scope and distinguish crypto acceptance, age eligibility and application authorization |
| EV-03 | P1; P0 if required by profile | `singleUse:true` SD-JWT can be presented twice through `presentStoredSdJwtVc`; issuer-JWT identical, no consumedAt; UI marks SHREDDED without that lifecycle | #171: atomic reservation/consumption, holder lifecycle and honest UI; retain explicitly reusable profiles |
| EV-04 | P1 integration/inventory | Tier-2 helpers and their tests exist; no invocation found at inspected app/audit call sites. This does not establish an external data leak or negate the separate receipt-export path. A retention field alone is not a scheduler | #172: inventory actual outputs, then wire applicable export/telemetry controls; preserve local history |
| EV-05 | P0 for asserted security gate | Audit steps are advisory; unchanged ci-security Python snippet exits 0 for synthetic critical=1/high=5 | #141 / SEC-AUDIT-1/2: blocking threshold plus audit-error/malformed-data negatives; no current advisory count inferred |
| EV-06 | P1 | Evidence JSON hash excludes written final LF; source/profile binding absent; existing manifest excludes EV-01..03 | #173 / SEC-AUDIT-3: exact persisted-byte hash, revision/profile/config and active-path regressions |
| EV-07 | Deliberate boundary / investigation | Wrapper overwrite does not cancel asynchronous work or erase caller-owned copies. Browser physical RAM erasure is outside this wrapper's evidence | GAP-1: state ownership/lifetime boundaries; determine whether cancellation is required by the caller contract before treating it as a defect |
| EV-08 | Distinct trust/API contracts | Local predicate signatures prove a different property from issuer-authenticated ZK derivation. Structural verifier mode explicitly reports whether signatures were checked; it is not inherently defective | #170/#97: consuming adapters must require the checks appropriate to their selected application/profile |
| EV-09 | Residual | Pairwise-DID failure continues without it; payload/IP/timing/cookie/issuer correlation not excluded by DID uniqueness | F-20 / SEC-AUDIT-4 / #142 Wave 4: explicit profile downgrade behavior and correlation evidence |
| EV-10 | Missing external evidence | No published official Android/iOS interop, independent security review or conformance result establishing current profile | GAP-4 / #97 / #142 Waves 2–4; exact-version external artifacts required |

### Scoped protocol & integration findings — 2026-11-03 (executable baseline `002ce5e`)

Full dated audit and reproduction paths: [`docs/qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md`](../qa/API_PROTOCOL_REALITY_AUDIT_2026-11-03.md). Staged remediation plan: [`docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md`](../tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md). These findings qualify overlapping claims only and do not duplicate or close `#170`–`#173`.

| ID | Priority | Evidence / exact boundary | Owner / close condition |
|---|---|---|---|
| API-01 | P0 (live browser Connect E2E) | 4-way mismatch across `@askmi/connect`, `verifier-demo`, `wallet-pwa`, and `issuer-mock`: (1) `wallet-pwa` runs HTTPS while `verifier-demo` `walletBaseUrl` + `dev-demo.ps1` CORS use `http://localhost:5174`; (2) `handoff.ts` omits `demo=wallet` so `App.tsx` lands on `<LandingPage>`; (3) `connect/src/core/profile.ts` bypasses `claim-contract.ts` and requests `$.age`, which `DemoPolicy.ts` (`allowedClaims: []`) rejects with `CLAIM_NOT_ALLOWED` (masked in `App.test.tsx:972` by `bootstrapFetchMocks('ALLOW')`); (4) `issuer-mock` issues `iss: 'did:web:localhost%3A3005'` vs. verifier default `'https://issuer.askmi.demo'` | Stage 0 (`API-V2-S0` / extends `#170` live browser E2E scope): wire `claim-contract.ts`, align URL/HTTPS/CORS/`iss`, and add unmocked E2E regression |
| API-02 | P0 (wallet disclosure clipping) | `wallet-pwa/src/App.tsx:959-961` (`presentOID4VP`) ignores `result.decisionCapsule.authorized_requirements` and re-extracts all requested fields from `authRequest.presentation_definition` | Stage 0 (`API-V2-S0`): filter disclosed claims strictly by `decisionCapsule.authorized_requirements` + negative test |
| API-03 | P0 (RFC 9901 & KB-JWT verification) | `sd-jwt-vc.ts:145-157` does not enforce `typ` or `algorithms`; `sd-jwt-vc.ts:404-418` uses `continue` on unmatched/malformed disclosures instead of rejecting per RFC 9901 §7.1; `sd-jwt-vc.ts:465` emits `~~` on 0 disclosures; `oid4vp-verifier/src/response-verifier.ts:38-48,197` defaults `verifyCredentialSignatures` to falsy and skips KB-JWT check when trailing segment is empty (`<issuerJwt>~<disc>~`) | Stage 0 (`API-V2-S0`): strict RFC 9901 §7.1 validation, mandatory KB-JWT check when `cnf`/`expectedNonce` applies, and negative tests |
| API-04 | P1 (ISO/IEC 18013-5 §9.1.3.6 conformance) | `mdoc/src/device-auth.ts:39-101` passes `sessionTranscript` as `externalAad` and embeds inline payload instead of detached (`payload: null`) `COSE_Sign1` over `DeviceAuthenticationBytes = Tag24(CBOR(["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]))` | Stage 0 (`API-V2-S0` / `#97`): implement ISO 18013-5 §9.1.3.6 detached `DeviceAuthenticationBytes` + `OpenID4VPHandover` |
| API-05 | P1 (fail-closed trust/status/WebAuthn helpers) | `trust-list-resolver.ts:121,159-162` returns `verified: true` when `anchorPublicKey === null` and applies 4h expired-cache grace even for `riskTier === 'high'`; `revocation-statuslist/src/index.ts:185-212` does not verify status list signature; `webauthn-verifier/src/index.ts:129-168` does not verify server-side `response.signature` | Stage 0 (`API-V2-S0`): fail-closed cryptographic signature verification + high-risk expiry enforcement |
| API-06 | P2 (docs truth) | `docs/_core/03_ARCHITECTURE.md:10` cited `@sd-jwt/core`..`@sd-jwt/verify`, which are absent from the repository | Closed in docs on `chore/enable-entire` (`2026-11-03`) |
| API-07 | P1 (2026 EUDI protocol alignment) | Pre-final OID4VP (DIF PE v2, `client_id_scheme`, `redirect_uri`, static `walletBaseUrl`), draft-13 `/batch_credential`, custom LOTL JSON, and custom `askmi-poe` erasure/reporting differ from OpenID4VP 1.0 Final (DCQL, Client ID Prefixes, `response_uri`, `verifier_info` WRPRC), W3C DC API, OpenID4VCI 1.0 Final, ETSI TS 119 602 LoTE, and EUDI TS07/TS08 | Stages 1–3 (`API-V2-S1`..`S3` / `#97`) in `docs/tasks/API_V2_ARCHITECTURE_PLAN_2026-11-03.md` |

### Important implemented pieces to preserve

Issuer signatures, digest-verified disclosures and KB-JWT primitives exist; #132/#135/#137 fixed real problems.
Policy input, downgrade, geo-scope and the #125 layer checks have scoped repository tests.
Legacy B+C single-use pool/holder-binding work #86–#94 is implemented in its own path; it does not close EV-03.
The #81 audit schema and #134 harness are useful components, not global runtime guarantees.
The #152 shell-free evidence-runner hardening is landed and must survive baseline reconciliation.

### Tracker reconciliation

- #122: #125 fixes the named layer-map scope. Current code and two negative cases plus a fresh 63-test focused run support scoped closure, not general health-pilot readiness.
- #95: superseded by AskMI naming and #158 product decision, not a new product-delivery claim.
- #138, #158, #159, #160 and #152 are merged. #159/#160 accept designs; `src/packages/connect` does not exist at this baseline.
- #141 remains open/non-mergeable at head `6f9e00569c3cf0ea00daf11dad39e68a96d857ad`; its three original inline review threads are resolved. Old branch checks do not validate a rebased integration.
- #150/#151 remain open. Key separation and randomness patches are not assumed landed or hardware-verified.
- #157's issuance/presentation lifecycle thread remains unresolved; #168 proposes the wording correction. Proposed documentation is not implementation.
- #144/#145/#146/#156/#157/#168/#169 source-watch content is consolidated here as dated planning input; no executable code from those branches is imported.

## Gate decision

G0 and G1 remain open; their September/11 October windows elapsed. Public evidence has no completed tally meeting
20 interviews, 8 confirmations and 3 qualifying buyer/procurement/deadline signals. This does not prove zero private interviews.
No sprint or pilot gate advances automatically. Broad product expansion remains paused under the existing #143 stop rule;
remediation and evidence work for the existing profile can continue. Cloud/TEE/ZKP expansion remains deferred.

## Examples of scoped claim language

- Say “selective disclosure of numeric age on the tested demo path”, not “only a boolean/no PII reaches every verifier”.
- Say “locally signed predicate result” unless an issuer-authenticated cryptographic derivation is actually evidenced.
- Say “wrapper-owned buffer overwritten/API reuse blocked”, not “all RAM copies and verifier data erased”.
- Say “tamper-evident local audit/helper schema”, not universal WORM storage, guaranteed durable write or PII-free telemetry.
- Say “development/evaluation middleware and reference harness”, not production-ready, certified-ready, LoA High or percentage compliant.
- Link the claim to its dated source/profile/test record. Ordinary component descriptions need not repeat the whole metadata block; preserve navigation to the evidence.

## Update rule

Keep one finding ID with issue and evidence links. A fix closes only the tested path/profile, after negative and integration evidence.
Do not infer completion from accepted designs, closed/superseded PRs, elapsed dates, static totals or internal test counts.
Preserve dated QA and original source-watch material. Later findings qualify overlapping claims only; unrelated observations remain valid evidence for their recorded scope.
Documentation-only edits do not trigger a full repository re-audit. Revalidate affected paths/dependencies/configuration/profile changes; full release gates require broader checks.
